package devdeploy

import (
	"encoding/base64"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/pkg/errors"
	"log"
	"os"
	"strings"

	"gopkg.in/go-playground/validator.v9"
)

// BuildImageForTargetEnv builds an image using the defined Dockerfile and pushes the image to a local repo.
func BuildImageForTargetEnv(log *log.Logger, cfg *Config, targetImage *ProjectImage, noCache, noPush bool) error {

	log.Printf("Build image %s for environment %s\n", targetImage.Name, cfg.Env)

	if targetImage.DockerBuildDir == "" {
		targetImage.DockerBuildDir = cfg.ProjectRoot
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetImage)
	if errs != nil {
		return errs
	}

	var releaseDockerLoginCmd []string
	var releaseImage string
	if targetImage.UseECR {
		infra, err := NewInfrastructure(cfg)
		if err != nil {
			return err
		}

		repo, err := infra.GetAwsEcrRepository(cfg.AwsEcrRepository.RepositoryName)
		if err != nil {
			return err
		}

		releaseImage = repo.RepositoryUri + ":" + targetImage.ReleaseTag

		log.Println("\tRetrieve ECR authorization token used for docker login.")

		svc := ecr.New(infra.AwsSession())

		// Get the credentials necessary for logging into the AWS Elastic Container Registry
		// made available with the AWS access key and AWS secret access keys.
		res, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
		if err != nil {
			return errors.Wrap(err, "failed to get ecr authorization token")
		}

		authToken, err := base64.StdEncoding.DecodeString(*res.AuthorizationData[0].AuthorizationToken)
		if err != nil {
			return errors.Wrap(err, "failed to base64 decode ecr authorization token")
		}
		pts := strings.Split(string(authToken), ":")
		user := pts[0]
		pass := pts[1]

		releaseDockerLoginCmd = []string{
			"docker",
			"login",
			"-u", user,
			"-p", pass,
			*res.AuthorizationData[0].ProxyEndpoint,
		}

		log.Printf("\t%s\tdocker cmd login set.", Success)
	} else if ciReg := os.Getenv("CI_REGISTRY"); ciReg != "" {
		releaseDockerLoginCmd = []string{
			"docker", "login",
			"-u", os.Getenv("CI_REGISTRY_USER"),
			"-p", os.Getenv("CI_REGISTRY_PASSWORD"),
			ciReg}

		releaseImage = os.Getenv("CI_REGISTRY_IMAGE") + ":" + targetImage.ReleaseTag
	} else {
		releaseImage = cfg.ProjectName + ":" + targetImage.ReleaseTag
		noPush = true
	}

	req := &BuildDockerRequest{
		Env:         cfg.Env,
		ProjectName: cfg.ProjectName,
		Name:        targetImage.Name,

		ReleaseImage: releaseImage,

		BuildDir:           targetImage.DockerBuildDir,
		Dockerfile:         targetImage.Dockerfile,
		DockerBuildContext: targetImage.DockerBuildContext,
		BaseImageTags:      targetImage.BaseImageTags,
		TargetLayer:        targetImage.DockerBuildTargetLayer,

		ReleaseDockerLoginCmd: releaseDockerLoginCmd,

		NoCache: noCache,
		NoPush:  noPush,

		BuildArgs: targetImage.DockerBuildArgs,
	}

	return BuildDocker(log, req)
}
