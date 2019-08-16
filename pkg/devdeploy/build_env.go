package devdeploy

import (
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

// BuildEnv defines the details to setup the target environment for the project to build services and functions.
type BuildEnv struct {
	Env string `validate:"oneof=dev stage prod"`

	// ProjectRoot should be the root directory for the project.
	ProjectRoot string `validate:"required"`

	// ProjectName will be used for prefixing AWS resources.
	ProjectName string `validate:"required"`

	// AwsCredentials defines the credentials used for deployment.
	AwsCredentials AwsCredentials `validate:"required,dive,required"`

	// AwsEcrRepository defines the name of the ECR repository and details needed to create if does not exist.
	AwsEcrRepository *AwsEcrRepository
}

// ProjectNameCamel takes a project name and returns the camel cased version.
func (buildEnv *BuildEnv) ProjectNameCamel() string {
	s := strings.Replace(buildEnv.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
}

// AwsSession returns the AWS session based on the defined credentials.
func (buildEnv *BuildEnv) AwsSession() *session.Session {
	return buildEnv.AwsCredentials.Session()
}

// SetupBuildEnv ensures all the resources for the project are setup before building a service or function. This will
// ensure the following AWS are available for build:
// 1. AWS ECR repository
func SetupBuildEnv(log *log.Logger, buildEnv *BuildEnv) error {

	log.Printf("Setup build environment %s\n", buildEnv.Env)

	log.Println("\tValidate request.")
	errs := validator.New().Struct(buildEnv)
	if errs != nil {
		return errs
	}

	// Step 1: Find or create the AWS ECR repository.
	{
		log.Println("\tECR - Get or create repository")

		svc := ecr.New(buildEnv.AwsSession())

		repositoryName := buildEnv.AwsEcrRepository.RepositoryName

		var respository *ecr.Repository
		descRes, err := svc.DescribeRepositories(&ecr.DescribeRepositoriesInput{
			RepositoryNames: []*string{aws.String(repositoryName)},
		})
		if err != nil {
			// The repository should have been created by build or manually created and should exist at this point.
			return errors.Wrapf(err, "Failed to describe repository '%s'.", repositoryName)
		} else if len(descRes.Repositories) > 0 {
			respository = descRes.Repositories[0]
		}

		if respository == nil {
			input, err := buildEnv.AwsEcrRepository.Input()
			if err != nil {
				return err
			}

			// If no repository was found, create one.
			createRes, err := svc.CreateRepository(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create repository '%s'", repositoryName)
			}
			respository = createRes.Repository
			log.Printf("\t\tCreated: %s", *respository.RepositoryArn)
		} else {
			log.Printf("\t\tFound: %s", *respository.RepositoryArn)

			log.Println("\t\tChecking old ECR images.")
			maxImages := buildEnv.AwsEcrRepository.MaxImages
			if maxImages == 0 || maxImages > AwsRegistryMaximumImages {
				maxImages = AwsRegistryMaximumImages
			}
			delIds, err := EcrPurgeImages(buildEnv.AwsCredentials, repositoryName, maxImages)
			if err != nil {
				return err
			}

			// Since ECR has max number of repository images, need to delete old ones so can stay under limit.
			// If there are image IDs to delete, delete them.
			if len(delIds) > 0 {
				log.Printf("\t\tDeleted %d images that exceeded limit of %d", len(delIds), maxImages)
				for _, imgId := range delIds {
					log.Printf("\t\t\t%s", *imgId.ImageTag)
				}
			}
		}
		buildEnv.AwsEcrRepository.result = respository

		log.Printf("\t%s\tECR Respository available\n", Success)
	}

	return nil
}
