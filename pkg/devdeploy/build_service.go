package devdeploy

import (
	"encoding/base64"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

// BuildService defines the details needed to build a service using docker.
type BuildService struct {
	//BuildEnv *BuildEnv `validate:"required,dive,required"`

	// Required flags.
	ServiceName string `validate:"required" example:"web-api"`

	Dockerfile string `validate:"required" example:"./cmd/web-api/Dockerfile"`

	ReleaseTag string `validate:"required"`

	// Optional flags.
	CommitRef string `validate:"omitempty" example:"master@1ecfd275"`
	BuildDir  string `validate:"omitempty" example:"."`
	NoCache   bool   `validate:"omitempty" example:"false"`
	NoPush    bool   `validate:"omitempty" example:"false"`
}

// BuildServiceForTargetEnv builds a service using the defined Dockerfile and pushes the release image to AWS ECR.
func BuildServiceForTargetEnv(log *log.Logger, targetEnv *BuildEnv, targetService *BuildService) error {

	log.Printf("Build service %s for environment %s\n", targetService.ServiceName, targetEnv.Env)

	// Get the default commit ref used by main.go:build constant.
	if targetService.CommitRef == "" {
		if ev := os.Getenv("CI_COMMIT_TAG"); ev != "" {
			targetService.CommitRef = "tag-" + ev
		} else if ev := os.Getenv("CI_COMMIT_REF_NAME"); ev != "" {
			targetService.CommitRef = "branch-" + ev
		}

		if ev := os.Getenv("CI_COMMIT_SHORT_SHA"); ev != "" {
			targetService.CommitRef = targetService.CommitRef + "@" + ev
		}

		if targetService.CommitRef == "" {
			targetService.CommitRef = targetService.ReleaseTag
		}
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetService)
	if errs != nil {
		return errs
	}

	releaseImage := *targetEnv.AwsEcrRepository.result.RepositoryUri + ":" + targetService.ReleaseTag
	log.Printf("\tRelease image: %s", releaseImage)

	var ecrDockerLoginCmd []string
	{
		log.Println("\tRetrieve ECR authorization token used for docker login.")

		svc := ecr.New(targetEnv.AwsSession())

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
		Env:         targetEnv.Env,
		ProjectName: targetEnv.ProjectName,
		ServiceName: targetService.ServiceName,

		ReleaseImage: releaseImage,

		BuildDir:              targetEnv.ProjectRoot,
		Dockerfile:            targetService.Dockerfile,
		ReleaseDockerLoginCmd: ecrDockerLoginCmd,

		AwsCredentials: targetEnv.AwsCredentials,

		CommitRef: targetService.CommitRef,
		NoCache:   targetService.NoCache,
		NoPush:    targetService.NoPush,
	}

	return BuildDocker(log, req)
}
