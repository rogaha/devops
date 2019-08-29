package devdeploy

import (
	"encoding/base64"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

// BuildServiceForTargetEnv builds a service using the defined Dockerfile and pushes the release image to AWS ECR.
func BuildServiceForTargetEnv(log *log.Logger, cfg *Config, targetService *ProjectService, noCache, noPush bool) error {

	log.Printf("Build service %s for environment %s\n", targetService.Name, cfg.Env)

	if targetService.DockerBuildDir == "" {
		targetService.DockerBuildDir = cfg.ProjectRoot
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetService)
	if errs != nil {
		return errs
	}

	infra, err := NewInfrastructure(cfg)
	if err != nil {
		return err
	}

	repo, err := infra.GetAwsEcrRepository(cfg.AwsEcrRepository.RepositoryName)
	if err != nil {
		return err
	}

	releaseImage := repo.RepositoryUri + ":" + targetService.ReleaseTag
	log.Printf("\tRelease image: %s", releaseImage)

	var ecrDockerLoginCmd []string
	{
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

		ecrDockerLoginCmd = []string{
			"docker",
			"login",
			"-u", user,
			"-p", pass,
			*res.AuthorizationData[0].ProxyEndpoint,
		}

		log.Printf("\t%s\tdocker cmd login set.", Success)
	}

	req := &BuildDockerRequest{
		Env:         cfg.Env,
		ProjectName: cfg.ProjectName,
		Name:        targetService.Name,

		ReleaseImage: releaseImage,

		BuildDir:           targetService.DockerBuildDir,
		Dockerfile:         targetService.Dockerfile,
		DockerBuildContext: targetService.DockerBuildContext,
		BaseImageTags:      targetService.BaseImageTags,
		TargetLayer:        targetService.DockerBuildTargetLayer,

		ReleaseDockerLoginCmd: ecrDockerLoginCmd,

		AwsCredentials: cfg.AwsCredentials,

		NoCache: noCache,
		NoPush:  noPush,

		BuildArgs: targetService.DockerBuildArgs,
	}

	return BuildDocker(log, req)
}
