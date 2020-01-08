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
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
)

// BuildDockerRequest defines the details needed to execute a docker build.
type BuildDockerRequest struct {
	Env         string `validate:"oneof=dev stage prod" example:"dev"`
	ProjectName string ` validate:"omitempty" example:"example-project"`
	Name        string `validate:"required" example:"web-api"`

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

	BaseImageTags map[string]string `validate:"omitempty"`
	BuildArgs     map[string]string `validate:"omitempty"`
}

// BuildDocker executes the docker build commands and either pushes the image to ECR or uploads a zip to S3 for
// AWS Lambda support.
// Note: This is pretty tailored for working with gitlab ATM.
func BuildDocker(log *log.Logger, req *BuildDockerRequest) error {

	log.Printf("Starting docker build %s\n", req.Dockerfile)

	if req.DockerBuildContext == "" {
		req.DockerBuildContext = "."
	}

	wkdir := req.BuildDir

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

	type builtStage struct {
		Image    string
		Name     string
		Args     map[string]string
		Lines    []string
		CacheTag string
	}

	var stages []*builtStage

	// When the dockerFile is multistage, caching can be applied. Scan the dockerFile for the first stage.
	// FROM golang:1.13.6-alpine3.9 AS build_base
	{
		log.Printf("\tParsing build stages from %s\n", dockerPath)

		file, err := os.Open(dockerPath)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		reFrom := regexp.MustCompile(`^(?i)from `)
		reAs := regexp.MustCompile(`(?i) as `)
		reArg := regexp.MustCompile(`^(?i)arg `)

		var curStage *builtStage

		// Loop through all the lines in the Dockerfile searching for the lines associated with the first build stage.
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			line = reFrom.ReplaceAllString(line, "FROM ")

			if reFrom.MatchString(line) {
				line = reFrom.ReplaceAllString(line, "FROM ")
				line = reAs.ReplaceAllString(line, " AS ")

				if curStage != nil {
					stages = append(stages, curStage)
				}

				curStage = &builtStage{
					Args: make(map[string]string),
					Lines: []string{
						line,
					},
				}

				fromline := strings.TrimSpace(strings.Replace(line, "FROM ", "", 1))

				if strings.Contains(fromline, " AS ") {
					pts := strings.Split(fromline, " AS ")
					curStage.Image = strings.TrimSpace(pts[0])

					// Strip any trailing comments.
					curStage.Name = strings.TrimSpace(strings.Split(pts[1], " ")[0])

					log.Printf("\t\tLayer Image: '%s' AS '%s'\n", curStage.Image, curStage.Name)
				} else {
					// Strip any trailing comments.
					curStage.Image = strings.TrimSpace(strings.Split(fromline, " ")[0])

					log.Printf("\t\tLayer Image: '%s'\n", curStage.Image)
				}

			} else if curStage != nil {
				curStage.Lines = append(curStage.Lines, line)

				if reArg.MatchString(line) {
					vals := strings.Split(line, "=")

					argKey := strings.TrimSpace(strings.Split(vals[0], " ")[1])

					// Build args are option to set a default value.
					var argVal string
					if len(vals) > 1 {
						argVal = strings.TrimSpace(vals[1])
					}

					curStage.Args[argKey] = argVal

					log.Printf("\t\t\tArg %s: '%s'\n", argKey, argVal)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			return errors.WithStack(err)
		}

		if curStage != nil {
			stages = append(stages, curStage)
		}

		for idx, stage := range stages {
			stageName := strings.ToLower(stage.Name)

			// If we have detected a build stage, then generate the appropriate tag.
			if idx == 0 && strings.HasPrefix(stageName, "build_base_") {
				log.Printf("\t\tFound build stage %s for caching.\n", stage.Name)

				var layerHash string
				switch stageName {
				case "build_base_golang":

					// Ensure the first stage actually includes `RUN go mod download`
					var hasGoModDownload bool
					for _, l := range stage.Lines {
						if strings.Contains(l, "go mod download") {
							hasGoModDownload = true
							break
						}
					}

					if hasGoModDownload {
						layerHash, err = findGoModHashForBuild(req.BuildDir)
						if err != nil {
							return err
						}
					}
				}

				if layerHash != "" {
					// Generate a checksum for the lines associated with the build stage.
					buildBaseHashPts := []string{
						fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(stage.Lines, "\n")))),
						layerHash,
					}

					// Combine all the checksums to be used to tag the target build stage.
					buildBaseHash := fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(buildBaseHashPts, "|"))))

					// New stage image tag.
					stage.CacheTag = stage.Name + "-" + buildBaseHash[0:8]
					log.Printf("\t\t\tTag %s\n", stage.CacheTag)
				}
			}
		}
	}

	// Check to see if we can pass the env var GOPROXY from the os as a build arg.
	{
		log.Printf("\tChecking stages for GOPROXY arg\n")

		var dockerFileHasGoProxyArg bool
		for _, stage := range stages {
			for k, v := range stage.Args {
				if k == "GOPROXY" {
					dockerFileHasGoProxyArg = true

					if stage.Name != "" {
						log.Printf("\t\tFound arg %s in stage %s with default value '%s'\n", k, stage.Name, v)
					} else {
						log.Printf("\t\tFound arg %s with default value '%s'\n", k, v)
					}
					break
				}
			}
			if dockerFileHasGoProxyArg {
				break
			}
		}

		// If the Dockerfile contains an optional build arg of GOPROXY then try to copy value from env.
		if dockerFileHasGoProxyArg {
			// Check to see if the value is set as an env var.
			if ev := os.Getenv("GOPROXY"); ev != "" {
				log.Printf("\t\tOS environment variable GOPROXY set to '%s'\n", ev)

				// Only add the build arg if one wasn't specifically defined.
				if bv, ok := req.BuildArgs["GOPROXY"]; ok {
					log.Printf("\t\t\tBuild arg already set to '%s'\n", bv)
				} else {
					req.BuildArgs["GOPROXY"] = ev
					log.Printf("\t\t\tAdding build arg\n")
				}
			} else {
				log.Printf("\t\tOS environment variable GOPROXY not set\n")
			}
		}
	}

	var ciLoginCmd []string
	var ciRegImg string
	ciReg := os.Getenv("CI_REGISTRY")
	if ciReg != "" {
		ciLoginCmd = []string{
			"docker", "login",
			"-u", os.Getenv("CI_REGISTRY_USER"),
			"-p", os.Getenv("CI_REGISTRY_PASSWORD"),
			ciReg}
		ciRegImg = os.Getenv("CI_REGISTRY_IMAGE")
	}

	var cmds [][]string

	// Check to see if any of the containers reference other defined Dockerfiles for the project. The must be referenced
	// from the root build directory.
	if req.BaseImageTags != nil && len(req.BaseImageTags) > 0 {
		if ciReg != "" && len(ciLoginCmd) > 0 {
			cmds = append(cmds, ciLoginCmd)
		}

		for bt, bi := range req.BaseImageTags {
			var (
				buildBaseImage string
			)
			if ciReg != "" {
				buildBaseImage = ciRegImg + ":" + bi
				cmds = append(cmds, []string{"docker", "pull", buildBaseImage})
			} else {
				buildBaseImage = req.ProjectName + ":" + bi
			}

			// Retag the image locally so the build can keep the same reference in the dockerFile.
			cmds = append(cmds, []string{"docker", "tag", buildBaseImage, bt})
		}
	}

	// Enabling caching of the first build stage defined in the dockerFile.
	var cacheFrom []string
	if !req.NoCache {
		for _, stage := range stages {
			if stage.CacheTag == "" {
				continue
			}

			var (
				pushTargetImg  bool
				buildBaseImage string
			)
			if ciReg != "" {
				cmds = append(cmds, []string{
					"docker", "login",
					"-u", os.Getenv("CI_REGISTRY_USER"),
					"-p", os.Getenv("CI_REGISTRY_PASSWORD"),
					ciReg})

				buildBaseImage = ciRegImg + ":" + stage.CacheTag
				pushTargetImg = true
			} else {
				buildBaseImage = req.ProjectName + ":" + req.Env + "-" + req.Name + "-" + stage.CacheTag
			}

			cmds = append(cmds, []string{"docker", "pull", buildBaseImage})

			baseBuildCmd := []string{
				"docker", "build",
				"--file=" + dockerFile,
				"--cache-from", buildBaseImage,
				"-t", buildBaseImage,
				"--target", stage.Name,
			}
			for k, v := range req.BuildArgs {
				baseBuildCmd = append(baseBuildCmd, "--build-arg", k+"="+v)
			}
			baseBuildCmd = append(baseBuildCmd, req.DockerBuildContext)

			cmds = append(cmds, baseBuildCmd)

			if pushTargetImg {
				cmds = append(cmds, []string{"docker", "push", buildBaseImage})
			}

			cacheFrom = append(cacheFrom, buildBaseImage)
		}
	}

	// The initial build command slice.
	buildCmd := []string{
		"docker", "build",
		"--file=" + dockerFile,
		"--build-arg", "name=" + req.Name,
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
	} else {
		for _, ct := range cacheFrom {
			buildCmd = append(buildCmd, "--cache-from", ct)
		}
	}

	// Finally append the build context as the current directory since os.Exec will use the project root as
	// the working directory.
	buildCmd = append(buildCmd, req.DockerBuildContext)

	cmds = append(cmds, buildCmd)

	s3Files := make(map[string]*s3manager.UploadInput)
	if req.NoPush == false {
		if req.IsLambda {
			containerName := uuid.NewRandom().String()

			tmpDir := filepath.Join(os.TempDir(), containerName)

			if err := os.MkdirAll(tmpDir, os.ModePerm); err != nil {
				return errors.WithStack(err)
			}

			lambdaZip := filepath.Join(tmpDir, containerName+"-"+filepath.Base(req.LambdaS3Key))
			defer os.Remove(lambdaZip)

			cmds = append(cmds, []string{"docker", "create", "-ti", "--name", containerName, req.ReleaseImage, "bash"})
			cmds = append(cmds, []string{"docker", "cp", containerName + ":/var/task", tmpDir})
			cmds = append(cmds, []string{"docker", "rm", containerName})
			cmds = append(cmds, []string{"cd", tmpDir + "/task"})
			cmds = append(cmds, []string{"zip", "-r", lambdaZip, "."})
			cmds = append(cmds, []string{"rm", "-rf", tmpDir + "/task"})

			s3Files[lambdaZip] = &s3manager.UploadInput{
				Bucket: &req.LambdaS3Bucket,
				Key:    &req.LambdaS3Key,
			}

		} else {
			if len(req.ReleaseDockerLoginCmd) > 0 {
				cmds = append(cmds, req.ReleaseDockerLoginCmd)
			}
			cmds = append(cmds, []string{"docker", "push", req.ReleaseImage})
		}
	}

	for _, cmd := range cmds {
		var logCmd string
		if len(cmd) >= 2 && cmd[1] == "login" {
			logCmd = strings.Join(cmd[0:2], " ")
		} else {
			logCmd = strings.Join(cmd, " ")
		}

		log.Printf("\t\t%s\n", logCmd)

		if len(cmd) > 0 && strings.ToLower(cmd[0]) == "cd" {
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
			return errors.Wrapf(err, "failed to execute %s", strings.Join(cmdVals, " "))
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
