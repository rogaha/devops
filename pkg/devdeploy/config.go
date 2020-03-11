package devdeploy

import (
	"strings"

	"github.com/iancoleman/strcase"
)

// Config defines the details needed to build the target deployment environment for AWS.
type Config struct {
	Env string `validate:"oneof=dev stage prod"`

	// AwsSecretPrefix will be used for prefixing AWS resources. If empty, default to Project Name.
	AwsSecretPrefix string

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

	// AwsSQSQueues is a list of SQS queues configured for the project.
	AwsSQSQueues []*AwsSQSQueue

	// List of configured services.
	ProjectServices []*ProjectService

	// List of configured functions.
	ProjectFunctions []*ProjectFunction

	// AwsRoute53MapZone allows the user to map a hostname to a specific zone id.
	AfterLoad func(infra *Infrastructure) error `json:"-"`
}

// SecretID returns the secret name with a standard prefix.
func (cfg *Config) SecretID(secretName string) string {
	return AwsSecretID(cfg.ProjectName, cfg.Env, secretName)
}

// ProjectNameCamel takes a project name and returns the camel cased version.
func (cfg *Config) ProjectNameCamel() string {
	s := strings.Replace(cfg.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
}

// GetDBConnInfo returns DBConnInfo for any dynamically created database else defined to the defined value.
func (cfg *Config) GetDBConnInfo(infra *Infrastructure) (*DBConnInfo, error) {
	var (
		dbConnInfo *DBConnInfo
		err        error
	)
	if cfg.AwsRdsDBCluster != nil {
		dbConnInfo, err = infra.GetDBConnInfo(cfg.AwsRdsDBCluster.DBClusterIdentifier)
		if err != nil {
			return nil, err
		}
	} else if cfg.AwsRdsDBInstance != nil {
		dbConnInfo, err = infra.GetDBConnInfo(cfg.AwsRdsDBInstance.DBInstanceIdentifier)
		if err != nil {
			return nil, err
		}
	} else {
		dbConnInfo = cfg.DBConnInfo
	}

	return dbConnInfo, nil
}
