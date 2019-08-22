package devdeploy

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
)

// BuildDockerRequest defines the details needed to execute a docker build.
type BuildDockerRequest struct {
	Env         string `validate:"oneof=dev stage prod" example:"dev"`
	ProjectName string ` validate:"omitempty" example:"example-project"`
	ServiceName string `validate:"required" example:"web-api"`

	ReleaseImage string `validate:"required" example:""`

	BuildDir              string   `validate:"required" example:"."`
	DockerBuildContext    string   `validate:"required" example:"."`
	Dockerfile            string   `validate:"required" example:"./cmd/web-api/Dockerfile"`
	ReleaseDockerLoginCmd []string `validate:"required_without=IsLambda"`

	AwsCredentials AwsCredentials `validate:"required_with=IsLambda,dive,required"`

	NoCache        bool   `validate:"omitempty"`
	NoPush         bool   `validate:"omitempty"`
	IsLambda       bool   `validate:"omitempty"`
	LambdaS3Key    string `validate:"required_with=IsLambda"`
	LambdaS3Bucket string `validate:"required_with=IsLambda"`
	TargetLayer    string `validate:"omitempty" example:"lambda"`

	BuildArgs map[string]string `validate:"omitempty"`
}

// BuildDocker executes the docker build commands and either pushes the image to ECR or uploads a zip to S3 for
// AWS Lambda support.
// Note: This is pretty tailored for working with gitlab ATM.
func BuildDocker(log *log.Logger, req *BuildDockerRequest) error {

	log.Printf("Starting docker build %s\n", req.Dockerfile)

	if req.DockerBuildContext == "" {
		req.DockerBuildContext = "."
	}

	var dockerFile string
	dockerPath := filepath.Join(req.BuildDir, req.Dockerfile)
	if _, err := os.Stat(dockerPath); err == nil {
		dockerFile = req.Dockerfile
	} else {
		dockerPath = req.Dockerfile

		dockerFile, err = filepath.Rel(req.BuildDir, dockerPath)
		if err != nil {
			return errors.Wrapf(err, "Failed parse relative path for %s from %s", dockerPath, req.BuildDir)
		}
	}

	// Name of the first build stage declared in the docckerFile.
	var buildStageName string

	// When the dockerFile is multistage, caching can be applied. Scan the dockerFile for the first stage.
	// FROM golang:1.12.6-alpine3.9 AS build_base
	var buildBaseImageTag string
	{
		file, err := os.Open(dockerPath)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		// List of lines in the dockerfile for the first stage. This will be used to tag the image to help ensure
		// any changes to the lines associated with the first stage force cache to be reset.
		var stageLines []string

		// Loop through all the lines in the Dockerfile searching for the lines associated with the first build stage.
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			lineLower := strings.ToLower(line)

			if strings.HasPrefix(lineLower, "from ") {
				if buildStageName != "" {
					// Only need to scan all the lines for the first build stage. Break when reach next FROM.
					break
				} else if !strings.Contains(lineLower, " as ") {
					// Caching is only supported if the first FROM has a name.
					log.Printf("\t\t\tSkipping stage cache, build stage not detected.\n")
					break
				}

				buildStageName = strings.TrimSpace(strings.Split(lineLower, " as ")[1])
				stageLines = append(stageLines, line)
			} else if buildStageName != "" {
				stageLines = append(stageLines, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return errors.WithStack(err)
		}

		// If we have detected a build stage, then generate the appropriate tag.
		if buildStageName != "" {
			log.Printf("\t\tFound build stage %s for caching.\n", buildStageName)

			// Generate a checksum for the lines associated with the build stage.
			buildBaseHashPts := []string{
				fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(stageLines, "\n")))),
			}

			switch buildStageName {
			case "build_base_golang":
				goModHash, err := findGoModHashForBuild(req.BuildDir)
				if err != nil {
					return err
				}

				buildBaseHashPts = append(buildBaseHashPts, goModHash)
			}

			// Combine all the checksums to be used to tag the target build stage.
			buildBaseHash := fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(buildBaseHashPts, "|"))))

			// New stage image tag.
			buildBaseImageTag = buildStageName + "-" + buildBaseHash[0:8]
		}
	}

	var cmds [][]string

	// Enabling caching of the first build stage defined in the dockerFile.
	var buildBaseImage string
	if !req.NoCache && buildBaseImageTag != "" {
		var pushTargetImg bool
		if ciReg := os.Getenv("CI_REGISTRY"); ciReg != "" {
			cmds = append(cmds, []string{
				"docker", "login",
				"-u", os.Getenv("CI_REGISTRY_USER"),
				"-p", os.Getenv("CI_REGISTRY_PASSWORD"),
				ciReg})

			buildBaseImage = os.Getenv("CI_REGISTRY_IMAGE") + ":" + buildBaseImageTag
			pushTargetImg = true
		} else {
			buildBaseImage = req.ProjectName + ":" + req.Env + "-" + req.ServiceName + "-" + buildBaseImageTag
		}

		cmds = append(cmds, []string{"docker", "pull", buildBaseImage})

		cmds = append(cmds, []string{
			"docker", "build",
			"--file=" + dockerFile,
			"--cache-from", buildBaseImage,
			"-t", buildBaseImage,
			"--target", buildStageName,
			req.DockerBuildContext,
		})

		if pushTargetImg {
			cmds = append(cmds, []string{"docker", "push", buildBaseImage})
		}
	}

	// The initial build command slice.
	buildCmd := []string{
		"docker", "build",
		"--file=" + dockerFile,
		"--build-arg", "service=" + req.ServiceName,
		"--build-arg", "env=" + req.Env,
	}

	for k, v := range req.BuildArgs {
		buildCmd = append(buildCmd, "--build-arg", k+"="+v)
	}

	if req.TargetLayer != "" {
		buildCmd = append(buildCmd, "--target", req.TargetLayer)
	}

	buildCmd = append(buildCmd, "-t", req.ReleaseImage)

	// Append additional build flags.
	if req.NoCache {
		buildCmd = append(buildCmd, "--no-cache")
	} else if buildBaseImage != "" {
		buildCmd = append(buildCmd, "--cache-from", buildBaseImage)
	}

	// Finally append the build context as the current directory since os.Exec will use the project root as
	// the working directory.
	buildCmd = append(buildCmd, req.DockerBuildContext)

	cmds = append(cmds, buildCmd)

	s3Files := make(map[string]*s3manager.UploadInput)
	if req.NoPush == false {
		if req.IsLambda {
			tmpDir := os.TempDir()
			lambdaZip := filepath.Join(tmpDir, filepath.Base(req.LambdaS3Key))

			containerName := uuid.NewRandom().String()

			cmds = append(cmds, []string{"docker", "create", "-ti", "--name", containerName, req.ReleaseImage, "bash"})
			cmds = append(cmds, []string{"docker", "cp", containerName + ":/var/task", tmpDir})
			cmds = append(cmds, []string{"docker", "rm", containerName})
			cmds = append(cmds, []string{"cd", tmpDir + "/task"})
			cmds = append(cmds, []string{"zip", "-r", lambdaZip, "."})

			s3Files[lambdaZip] = &s3manager.UploadInput{
				Bucket: &req.LambdaS3Bucket,
				Key:    &req.LambdaS3Key,
			}

		} else {
			cmds = append(cmds, req.ReleaseDockerLoginCmd)
			cmds = append(cmds, []string{"docker", "push", req.ReleaseImage})
		}
	}

	wkdir := req.BuildDir
	for _, cmd := range cmds {
		var logCmd string
		if len(cmd) >= 2 && cmd[1] == "login" {
			logCmd = strings.Join(cmd[0:2], " ")
		} else {
			logCmd = strings.Join(cmd, " ")
		}

		log.Printf("\t\t%s\n", logCmd)

		if strings.ToLower(cmd[0]) == "cd" {
			log.Printf("\t\t\tChanging directory\n")
			wkdir = cmd[1]
			continue
		}

		err := execCmds(log, wkdir, cmd)
		if err != nil {
			if len(cmd) > 2 && cmd[1] == "pull" {
				log.Printf("\t\t\tSkipping pull - %s\n", err.Error())
			} else {
				return errors.Wrapf(err, "Failed to exec %s", strings.Join(cmd, " "))
			}
		}
	}

	if s3Files != nil && len(s3Files) > 0 {
		// Create an uploader with the session and default options
		uploader := s3manager.NewUploader(req.AwsCredentials.Session())

		// Perform an upload.
		for lf, upParams := range s3Files {
			f, err := os.Open(lf)
			if err != nil {
				return errors.Wrapf(err, "Failed open file to %s", lf)
			}
			upParams.Body = f

			_, err = uploader.Upload(upParams)
			if err != nil {
				return errors.Wrapf(err, "Failed upload file to s3://%s/%s", *upParams.Bucket, *upParams.Key)
			}

			log.Printf("\t\tUploaded %s to s3://%s/%s\n", lf, *upParams.Bucket, *upParams.Key)
		}
	}

	log.Printf("\t%s\tbuild complete.\n", Success)

	return nil
}

// execCmds executes a set of commands using the current env variables.
func execCmds(log *log.Logger, workDir string, cmds ...[]string) error {
	for _, cmdVals := range cmds {
		cmd := exec.Command(cmdVals[0], cmdVals[1:]...)
		cmd.Dir = workDir
		cmd.Env = os.Environ()

		cmd.Stderr = log.Writer()
		cmd.Stdout = log.Writer()

		err := cmd.Run()

		if err != nil {
			return errors.WithMessagef(err, "failed to execute %s", strings.Join(cmdVals, " "))
		}
	}

	return nil
}

// findGoModHashForBuild generates an md5 hash for the project based on the go.sum or go.mod file.
func findGoModHashForBuild(buildDir string) (string, error) {

	// Loop through all the parent directories of the build directory looking for go.sum or go.mod
	var hashFile string
	testDir := buildDir
	for i := 0; i < 10; i++ {
		goSumPath := filepath.Join(testDir, "go.sum")
		if ok, _ := exists(goSumPath); ok {
			hashFile = goSumPath
			break
		}

		goModPath := filepath.Join(testDir, "go.mod")
		if ok, _ := exists(goModPath); ok {
			hashFile = goModPath
			break
		}

		testDir = filepath.Join(testDir, "../")
		if ok, _ := exists(goModPath); !ok {
			break
		}
	}

	if hashFile == "" {
		return "", errors.New("Unable to find go.mod or go.sum file")
	}

	// Compute the checksum for the go.mod file.
	dat, err := ioutil.ReadFile(hashFile)
	if err != nil {
		return "", errors.WithStack(err)
	}
	hash := fmt.Sprintf("%x", md5.Sum(dat))

	return hash, nil
}
