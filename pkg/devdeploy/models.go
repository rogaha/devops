package devdeploy

import (
	"github.com/aws/aws-sdk-go/service/s3"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/iancoleman/strcase"
)


type ModuleDetails struct {
	ProjectRoot string `validate:"required"`
	ProjectName string `validate:"required"`
	GoModFile   string `validate:"required"`
	GoModName   string `validate:"required"`
}


// DeploymentEnv .......
type DeploymentEnv struct {
	Env         string `validate:"oneof=dev stage prod"`

	// ProjectRoot should be the root directory for the project.
	ProjectRoot string `validate:"required"`

	// ProjectName will be used for prefixing AWS resources.
	ProjectName string `validate:"required"`

	// EcrRepository defines the name of the ECR repository and details need to create if does not exist.
	EcrRepository  AwsEcrRepository

	// Ec2SecurityGroup defines the name of the EC2 security group and details need to create if does not exist.
	Ec2SecurityGroup      AwsEc2SecurityGroup

	//
	GitlabRunnerEc2SecurityGroupName string `validate:"required"`

	S3BucketTempPrefix      string `validate:"required_with=S3BucketPrivateName S3BucketPublicName"`
	S3BucketPrivateName     string `validate:"omitempty"`
	S3Buckets               []S3Bucket

}


type Tag struct {
	// One part of a key-value pair that make up a tag. A key is a general label
	// that acts like a category for more specific tag values.
	Key string `type:"string"`

	// The optional part of a key-value pair that make up a tag. A value acts as
	// a descriptor within a tag category (key).
	Value string `type:"string"`
	// contains filtered or unexported fields
}


// Describes an AWS ECR repository.
type AwsEcrRepository struct {
	// The name to use for the repository. The repository name may be specified
	// on its own (such as nginx-web-app) or it can be prepended with a namespace
	// to group the repository into a category (such as project-a/nginx-web-app).
	//
	// RepositoryName is a required field
	RepositoryName string `locationName:"repositoryName" min:"2" type:"string" required:"true"`

	// The tag mutability setting for the repository. If this parameter is omitted,
	// the default setting of MUTABLE will be used which will allow image tags to
	// be overwritten. If IMMUTABLE is specified, all image tags within the repository
	// will be immutable which will prevent them from being overwritten.
	ImageTagMutability *string `locationName:"imageTagMutability" type:"string" enum:"ImageTagMutability"`

	// The metadata that you apply to the repository to help you categorize and
	// organize them. Each tag consists of a key and an optional value, both of
	// which you define. Tag keys can have a maximum character length of 128 characters,
	// and tag values can have a maximum length of 256 characters.
	Tags []Tag `locationName:"tags" type:"list"`


}


// Describes an AWS ECS security group.
type AwsEc2SecurityGroup struct {
	// The name of the security group.
	// Constraints: Up to 255 characters in length. Cannot start with sg-.
	// Constraints for EC2-Classic: ASCII characters
	// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
	// GroupName is a required field
	GroupName string `type:"string" required:"true"`

	// A description for the security group. This is informational only.
	// Constraints: Up to 255 characters in length
	// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
	// Description is a required field
	Description string `locationName:"GroupDescription" type:"string" required:"true"`

	// [EC2-VPC] The ID of the VPC.
	VpcId string `type:"string"`
}









/*

type DeploymentEnv struct {
	Env         string `validate:"oneof=dev stage prod"`
	ProjectRoot string `validate:"required"`
	ProjectName string `validate:"required"`

	AwsCreds    AwsCredentials `validate:"required,dive,required"`

	VpcPrivate        *Ec2Vpc `validate:"required,dive,required"`
	Ec2SecurityGroup     *Ec2SecurityGroup `validate:"required,dive,required"`
	SDNamepsace *SDNamepsace `validate:"omitempty,dive,required"`

	GitlabRunnerEc2SecurityGroupName string `validate:"required"`
	EcrRepositoryName string `validate:"required"`

	EcsCluster     *ecs.CreateClusterInput

	EcsExecutionRoleName       string `validate:"required"`
	EcsExecutionRole           *iam.CreateRoleInput
	EcsExecutionRolePolicyArns []string `validate:"required"`

	EcsTaskRoleName string `validate:"required"`
	EcsTaskRole     *iam.CreateRoleInput

	EcsTaskPolicyName     string `validate:"required"`
	EcsTaskPolicy         *iam.CreatePolicyInput
	EcsTaskPolicyDocument IamPolicyDocument


	CloudWatchLogGroupName string `validate:"required"`
	CloudWatchLogGroup     *cloudwatchlogs.CreateLogGroupInput

	S3BucketTempPrefix      string `validate:"required_with=S3BucketPrivateName S3BucketPublicName"`
	S3BucketPrivateName     string `validate:"omitempty"`
	S3BucketPublicName      string `validate:"omitempty"`
	S3BucketPublicKeyPrefix string `validate:"omitempty"`
	S3Buckets               []S3Bucket

	CloudfrontPublic *cloudfront.DistributionConfig

	SDService   *servicediscovery.CreateServiceInput

	CacheCluster          *elasticache.CreateCacheClusterInput
	CacheClusterParameter []*elasticache.ParameterNameValue

	Database *RdsDatabase `validate:"required,dive,required"`
}


type Ec2Vpc struct {
	Name    string `validate:"required"`
	VpcPublic        *ec2.CreateVpcInput
	Subnets []*ec2.CreateSubnetInput
}

type Ec2SecurityGroup struct {
	Name string `validate:"required"`
	Ec2SecurityGroup     *ec2.CreateSecurityGroupInput
}

type SDNamepsace struct {
	Name string `validate:"required"`
	SDNamepsace *servicediscovery.CreatePrivateDnsNamespaceInput
}

// S3Bucket defines the details need to create a bucket that includes additional configuration.
type S3Bucket struct {
	Name              string `validate:"omitempty"`
	Input             *s3.CreateBucketInput
	LifecycleRules    []*s3.LifecycleRule
	CORSRules         []*s3.CORSRule
	PublicAccessBlock *s3.PublicAccessBlockConfiguration
	Policy            string
}

type RdsDatabase struct {
	DBCluster  *rds.CreateDBClusterInput
	DBInstance *rds.CreateDBInstanceInput

}










// ServiceRequest defines the details needed to execute a service deployment.
type ServiceRequest struct {
	ServiceName string `validate:"required"`
	ServiceDir  string `validate:"required"`
	Env         string `validate:"oneof=dev stage prod"`
	ProjectRoot string `validate:"required"`
	ProjectName string `validate:"required"`
	GoModFile   string `validate:"required"`
	GoModName   string `validate:"required"`

	GitlabRunnerEc2SecurityGroupName string `validate:"required"`
	EcrRepositoryName string `validate:"required"`

	AwsCreds    AwsCredentials `validate:"required,dive,required"`
	_awsSession *session.Session

	ReleaseImage string

	DockerFile  string `validate:"required"`
}

// AwsCredentials defines AWS credentials used for deployment. Unable to use roles when deploying
// using gitlab CI/CD pipeline.
type AwsCredentials struct {
	AccessKeyID     string `validate:"required_without=UseRole"`
	SecretAccessKey string `validate:"required_without=UseRole"`
	Region          string `validate:"required_without=UseRole"`
	UseRole         bool
}


// DeployECSRequest defines the details needed to deploy a service to AWS ECS Fargate.
type DeployECSRequest struct {
	*ServiceRequest

	EnableHTTPS        bool     `validate:"omitempty"`
	ServiceHostPrimary string   `validate:"omitempty,required_with=EnableHTTPS,fqdn"`
	ServiceHostNames   []string `validate:"omitempty,dive,fqdn"`


	EcsClusterName string `validate:"required"`
	EcsCluster     *ecs.CreateClusterInput

	EcsServiceName                          string `validate:"required"`
	EcsServiceDesiredCount                  int64  `validate:"required"`
	EcsServiceMinimumHealthyPercent         *int64 `validate:"omitempty"`
	EcsServiceMaximumPercent                *int64 `validate:"omitempty"`
	EscServiceHealthCheckGracePeriodSeconds *int64 `validate:"omitempty"`



	StaticFilesS3Enable        bool   `validate:"omitempty"`
	StaticFilesS3Prefix        string `validate:"omitempty"`
	StaticFilesImgResizeEnable bool   `validate:"omitempty"`

	EnableEcsElb           bool   `validate:"omitempty"`
	ElbLoadBalancerName    string `validate:"omitempty"`
	ElbDeregistrationDelay *int   `validate:"omitempty"`
	ElbLoadBalancer        *elbv2.CreateLoadBalancerInput

	ElbTargetGroupName string `validate:"omitempty"`
	ElbTargetGroup     *elbv2.CreateTargetGroupInput



	EnableLambdaVPC bool `validate:"omitempty"`
	IsLambda        bool `validate:"omitempty"`
	RecreateService bool `validate:"omitempty"`


}

// IamPolicyDocument defines an AWS IAM policy used for defining access for IAM roles, users, and groups.
type IamPolicyDocument struct {
	Version   string              `json:"Version"`
	Statement []IamStatementEntry `json:"Statement"`
}

// IamStatementEntry defines a single statement for an IAM policy.
type IamStatementEntry struct {
	Sid      string      `json:"Sid"`
	Effect   string      `json:"Effect"`
	Action   []string    `json:"Action"`
	Resource interface{} `json:"Resource"`
}


// projectNameCamel takes a project name and returns the camel cased version.
func (r *DeploymentEnv) ProjectNameCamel() string {
	s := strings.Replace(r.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
}
*/