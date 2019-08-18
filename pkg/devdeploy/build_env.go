package devdeploy

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

// SetupBuildEnv ensures all the resources for the project are setup before building a service or function. This will
// ensure the following AWS are available for build:
// 1. AWS ECR repository
func SetupBuildEnv(log *log.Logger, cfg *Config) error {

	log.Printf("Setup build environment %s\n", cfg.Env)

	log.Println("\tValidate request.")
	errs := validator.New().Struct(cfg)
	if errs != nil {
		return errs
	}

	// Step 1: Find or create the AWS ECR repository.
	{
		log.Println("\tECR - Get or create repository")

		respository, err := setupAwsEcrRepository(log, cfg, cfg.AwsEcrRepository)
		if err != nil {
			return err
		}
		cfg.AwsEcrRepository.result = respository

		log.Printf("\t%s\tECR Respository available\n", Success)
	}

	return nil
}

// setupAwsEcrRepository ensures the AWS ECR repository exists else creates it.
func setupAwsEcrRepository(log *log.Logger, cfg *Config, repo *AwsEcrRepository) (*ecr.Repository, error) {
	svc := ecr.New(cfg.AwsSession())

	repositoryName := repo.RepositoryName

	var respository *ecr.Repository
	descRes, err := svc.DescribeRepositories(&ecr.DescribeRepositoriesInput{
		RepositoryNames: []*string{aws.String(repositoryName)},
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != ecr.ErrCodeRepositoryNotFoundException {
			return nil, errors.Wrapf(err, "Failed to describe repository '%s'.", repositoryName)
		}
	} else if len(descRes.Repositories) > 0 {
		respository = descRes.Repositories[0]
	}

	if respository == nil {
		input, err :=repo.Input()
		if err != nil {
			return nil, err
		}

		// If no repository was found, create one.
		createRes, err := svc.CreateRepository(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create repository '%s'", repositoryName)
		}
		respository = createRes.Repository
		log.Printf("\t\tCreated: %s", *respository.RepositoryArn)
	} else {
		log.Printf("\t\tFound: %s", *respository.RepositoryArn)

		log.Println("\t\tChecking old ECR images.")
		maxImages := repo.MaxImages
		if maxImages == 0 || maxImages > AwsRegistryMaximumImages {
			maxImages = AwsRegistryMaximumImages
		}
		delIds, err := EcrPurgeImages(cfg.AwsCredentials, repositoryName, maxImages)
		if err != nil {
			return nil, err
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

	return respository, nil
}
