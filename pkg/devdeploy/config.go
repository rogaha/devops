package devdeploy

import (
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
)

// Config defines the details needed to build the target deployment environment for AWS.
type Config struct {
	Env string `validate:"oneof=dev stage prod"`

	// ProjectRoot should be the root directory for the project.
	ProjectRoot string `validate:"required"`

	// ProjectName will be used for prefixing AWS resources.
	ProjectName string `validate:"required"`

	// AwsCredentials defines the credentials used for deployment.
	AwsCredentials AwsCredentials `validate:"required,dive,required"`

	// AwsEcrRepository defines the name of the ECR repository and details needed to create if does not exist.
	AwsEcrRepository *AwsEcrRepository

	// AwsIamPolicy defines the name of the iam policy that will be attached to ecs tasks and functions.
	AwsIamPolicy *AwsIamPolicy `validate:"required"`

	// AwsS3BucketPrivate sets the S3 bucket used internally for services.
	AwsS3BucketPrivate *AwsS3Bucket

	// AwsS3BucketPublic sets the S3 bucket used to host static files for all services.
	AwsS3BucketPublic *AwsS3Bucket

	// AwsS3BucketPublicKeyPrefix defines the base S3 key prefix used to upload static files.
	AwsS3BucketPublicKeyPrefix string `validate:"omitempty"`

	// AwsEc2Vpc defines the name of the VPC and details needed to create if does not exist.
	AwsEc2Vpc *AwsEc2Vpc

	// AwsEc2SecurityGroup defines the name of the EC2 security group and details needed to create if does not exist.
	AwsEc2SecurityGroup *AwsEc2SecurityGroup

	// GitlabRunnerEc2SecurityGroupName defines the name of the security group that was used to deploy the GitLab
	// Runners on AWS. This will allow the deploy script to ensure the GitLab Runners have access to community to through
	// the deployment EC2 Security Group.
	GitlabRunnerEc2SecurityGroupName string `validate:"required"`

	// AwsElasticCacheCluster defines the name of the cache cluster and the details needed to create if does not exist.
	AwsElasticCacheCluster *AwsElasticCacheCluster

	// AwsRdsDBCluster defines the name of the rds cluster and the details needed to create if does not exist.
	// This is only needed for Aurora storage engine.
	AwsRdsDBCluster *AwsRdsDBCluster

	// AwsRdsDBInstance defines the name of the rds database instance and the detailed needed to create doesn't exist.
	AwsRdsDBInstance *AwsRdsDBInstance

	// DBConnInfo defines the database connection details.
	// This is optional and will get populated when RDS Cluster/Instance is created.
	DBConnInfo *DBConnInfo
}

// ProjectNameCamel takes a project name and returns the camel cased version.
func (buildEnv *Config) ProjectNameCamel() string {
	s := strings.Replace(buildEnv.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
}

// AwsSession returns the AWS session based on the defined credentials.
func (buildEnv *Config) AwsSession() *session.Session {
	return buildEnv.AwsCredentials.Session()
}

// SecretID returns the secret name with a standard prefix.
func (deployEnv *Config) SecretID(secretName string) string {
	return filepath.Join(deployEnv.ProjectName, deployEnv.Env, secretName)
}

// Ec2TagResource is a helper function to tag EC2 resources.
func (cfg *Config) Ec2TagResource(resource, name string, tags ...Tag) error {
	svc := ec2.New(cfg.AwsSession())

	existingKeys := make(map[string]bool)
	ec2Tags := []*ec2.Tag{}
	for _, t := range tags {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(t.Key), Value: aws.String(t.Value)})
		existingKeys[t.Key] = true
	}

	if !existingKeys[AwsTagNameProject] {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameProject), Value: aws.String(cfg.ProjectName)})
	}

	if !existingKeys[AwsTagNameEnv] {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameEnv), Value: aws.String(cfg.Env)})
	}

	if !existingKeys[AwsTagNameName] && name != "" {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameName), Value: aws.String(name)})
	}

	_, err := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: aws.StringSlice([]string{resource}),
		Tags:      ec2Tags,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create tags for %s", resource)
	}

	return nil
}
