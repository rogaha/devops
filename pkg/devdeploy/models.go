package devdeploy

import (
	"encoding/base64"
	"encoding/json"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/aws/aws-sdk-go/service/sqs"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

// Success and failure markers.
const (
	Success = "\u2713"
	Failed  = "\u2717"
)

// ModuleDetails defines information about the project determined from the go.mod file.
type ModuleDetails struct {
	ProjectRoot string `validate:"required"`
	ProjectName string `validate:"required"`
	GoModFile   string `validate:"required"`
	GoModName   string `validate:"required"`
}

// DB mimics the general info needed for services used to define placeholders.
type DBConnInfo struct {
	Host       string
	User       string
	Pass       string
	Database   string
	Driver     string
	DisableTLS bool
}

// URL returns the URL to connect to a database.
func (db DBConnInfo) URL() string {

	// Query parameters.
	var q url.Values = make(map[string][]string)

	// Handle SSL Mode
	if db.DisableTLS {
		q.Set("sslmode", "disable")
	} else {
		q.Set("sslmode", "require")
	}

	// Construct url.
	dbUrl := url.URL{
		Scheme:   db.Driver,
		User:     url.UserPassword(db.User, db.Pass),
		Host:     db.Host,
		Path:     db.Database,
		RawQuery: q.Encode(),
	}

	return dbUrl.String()
}

// ProjectImage configures an image for build.
type ProjectImage struct {
	// Required flags.
	Name           string `validate:"required" example:"web-api"`
	Dockerfile     string `validate:"required" example:"./cmd/web-api/Dockerfile"`
	DockerBuildDir string `validate:"required"`
	ReleaseTag     string `validate:"required"`
	CodeDir        string `validate:"required"`

	// Optional flags.
	DockerBuildContext     string            `validate:"omitempty" example:"."`
	DockerBuildTargetLayer string            `validate:"omitempty" example:"lambda"`
	DockerBuildArgs        map[string]string `validate:"omitempty"`
	BaseImageTags          map[string]string `validate:"omitempty"`
	UseECR                 bool              `validate:"omitempty"`
}

// ProjectFunction configures a function for build and deploy.
type ProjectFunction struct {
	// Required flags.
	Name           string `validate:"required" example:"web-api"`
	Dockerfile     string `validate:"required" example:"./cmd/web-api/Dockerfile"`
	DockerBuildDir string `validate:"required"`
	ReleaseTag     string `validate:"required"`
	CodeDir        string `validate:"required"`
	CodeS3Key      string `validate:"required"`
	CodeS3Bucket   string `validate:"required"`

	// AwsLambdaFunction defines the details for a lambda function.
	AwsLambdaFunction *AwsLambdaFunction `validate:"required"`

	// AwsIamRole defines the details for assigning the lambda function to use a custom role.
	AwsIamRole *AwsIamRole `validate:"required"`

	// Optional flags.
	DockerBuildContext     string            `validate:"omitempty" example:"."`
	DockerBuildTargetLayer string            `validate:"omitempty" example:"lambda"`
	DockerBuildArgs        map[string]string `validate:"omitempty"`
	BaseImageTags          map[string]string `validate:"omitempty"`
	EnableVPC              bool              `validate:"omitempty"`

	// AwsIamPolicy defines the details for created a custom policy for the lambda function. The default service policy
	// will be attached to the role if no IAM policy is defined.
	AwsIamPolicy *AwsIamPolicy `validate:"omitempty"`

	// Passed to AwsEcsTaskDefinition.PreRegister
	CustomVariables map[string]interface{}

	// List of Cloudwatch event targets.
	AwsCloudwatchEventRules []*AwsCloudwatchEventRule `validate:"omitempty"`
}

// ProjectService configures a service for build and deploy.
type ProjectService struct {
	// Required flags.
	Name           string `validate:"required" example:"web-api"`
	Dockerfile     string `validate:"required" example:"./cmd/web-api/Dockerfile"`
	DockerBuildDir string `validate:"required"`
	ReleaseTag     string `validate:"required"`
	CodeDir        string `validate:"required"`

	// AwsEcsCluster defines the name of the ecs cluster and the details needed to create doesn't exist.
	AwsEcsCluster *AwsEcsCluster `validate:"required"`

	// AwsEcsService defines the name of the ecs service and the details needed to create doesn't exist.
	AwsEcsService *AwsEcsService `validate:"required"`

	// AwsEcsTaskDefinition defines the task definition.
	AwsEcsTaskDefinition *AwsEcsTaskDefinition `validate:"required"`

	// AwsEcsExecutionRole defines the name of the iam execution role for ecs task and the detailed needed to create doesn't exist.
	// This role executes ECS actions such as pulling the image and storing the application logs in cloudwatch.
	AwsEcsExecutionRole *AwsIamRole `validate:"required"`

	// AwsEcsExecutionRole defines the name of the iam task role for ecs task and the detailed needed to create doesn't exist.
	// This role is used by the task itself for calling other AWS services.
	AwsEcsTaskRole *AwsIamRole `validate:"required"`

	// AwsCloudWatchLogGroup defines the name of the cloudwatch log group that will be used to store logs for the ECS
	// task.
	AwsCloudWatchLogGroup *AwsCloudWatchLogGroup `validate:"required"`

	// AwsElbLoadBalancer defines if the service should use an elastic load balancer.
	AwsElbLoadBalancer *AwsElbLoadBalancer `validate:"omitempty"`

	// AwsAppAutoscalingPolicy defines if the service should use an autoscaling policy applied.
	AwsAppAutoscalingPolicy *AwsAppAutoscalingPolicy `validate:"omitempty"`

	// AwsSdPrivateDnsNamespace defines the name of the service discovery group and the details needed to create if
	// it does not exist.
	AwsSdPrivateDnsNamespace *AwsSdPrivateDnsNamespace `validate:"omitempty"`

	// Optional flags.
	EnableHTTPS            bool              `validate:"omitempty"`
	ServiceHostPrimary     string            `validate:"omitempty,required_with=EnableHTTPS"`
	ServiceHostNames       []string          `validate:"omitempty"`
	StaticFilesDir         string            `validate:"omitempty" example:"./cmd/web-api"`
	StaticFilesS3Prefix    string            `validate:"omitempty"`
	DockerBuildContext     string            `validate:"omitempty" example:"."`
	DockerBuildTargetLayer string            `validate:"omitempty" example:"lambda"`
	DockerBuildArgs        map[string]string `validate:"omitempty"`
	BaseImageTags          map[string]string `validate:"omitempty"`
	ReleaseImage           string            `validate:"omitempty"`
	BuildOnly              bool              `validate:"omitempty"`

	// Passed to AwsEcsTaskDefinition.PreRegister
	CustomVariables map[string]interface{}
}

// Tag describes a key/value pair that will help identify a resource.
type Tag struct {
	// One part of a key-value pair that make up a tag. A key is a general label
	// that acts like a category for more specific tag values.
	Key string

	// The optional part of a key-value pair that make up a tag. A value acts as
	// a descriptor within a tag category (key).
	Value string
}

// Metadata describes a key/value pair that will help identify an S3 object.
type Metadata struct {
	// One part of a key-value pair that make up a tag. A key is a general label
	// that acts like a category for more specific tag values.
	Key string

	// The optional part of a key-value pair that make up a tag. A value acts as
	// a descriptor within a tag category (key).
	Value string
}

// AwsCredentials defines AWS credentials used for deployment. Unable to use roles when deploying
// using gitlab CI/CD pipeline.
type AwsCredentials struct {
	AccessKeyID     string `validate:"required_without=UseRole"`
	SecretAccessKey string `validate:"required_without=UseRole"`
	Region          string `validate:"required_without=UseRole"`
	UseRole         bool
}

// AwsEcrRepository describes an AWS ECR repository.
type AwsEcrRepository struct {
	// The name to use for the repository. The repository name may be specified
	// on its own (such as nginx-web-app) or it can be prepended with a namespace
	// to group the repository into a category (such as project-a/nginx-web-app).
	//
	// RepositoryName is a required field
	RepositoryName string `required:"true"`

	// The tag mutability setting for the repository. If this parameter is omitted,
	// the default setting of MUTABLE will be used which will allow image tags to
	// be overwritten. If IMMUTABLE is specified, all image tags within the repository
	// will be immutable which will prevent them from being overwritten.
	ImageTagMutability *string

	// The metadata that you apply to the repository to help you categorize and
	// organize them. Each tag consists of a key and an optional value, both of
	// which you define. Tag keys can have a maximum character length of 128 characters,
	// and tag values can have a maximum length of 256 characters.
	Tags []Tag

	// The maximum number of images to maintain for the repository.
	MaxImages int

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecr.CreateRepositoryInput) error `json:"-"`
}

// AwsEcrRepositoryResult defines information about a repository derived from *ecr.Repository.
type AwsEcrRepositoryResult struct {
	// The name of the repository.
	RepositoryName string

	// The Amazon Resource Name (ARN) that identifies the repository.
	RepositoryArn string

	// The URI for the repository. You can use this URI for Docker push or pull operations.
	RepositoryUri string

	// The date and time when the repository was created.
	CreatedAt time.Time

	// The md5 hash of the input used to create the Repository.
	InputHash string
}

// Input returns the AWS input for ecr.CreateRepository.
func (m *AwsEcrRepository) Input() (*ecr.CreateRepositoryInput, error) {

	input := &ecr.CreateRepositoryInput{
		RepositoryName:     aws.String(m.RepositoryName),
		ImageTagMutability: m.ImageTagMutability,
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &ecr.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsEc2Vpc describes an AWS EC2 VPC.
type AwsEc2Vpc struct {
	// The ID of the VPC. This is optional when IsDefault is set to true which will find the default VPC.
	VpcId string

	// Indicates whether the VPC is the default VPC.
	IsDefault bool

	// The IPv4 network range for the VPC, in CIDR notation. For example, 10.0.0.0/16.
	// CidrBlock is a required field for creating a custom VPC when IsDefault is false and VpcId is empty.
	CidrBlock string

	// Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for
	// the VPC. You cannot specify the range of IP addresses, or the size of the CIDR block.
	// This is only optional for creating a custom VPC when IsDefault is false and VpcId is empty.
	AmazonProvidedIpv6CidrBlock *bool

	// The set of subnets used for creating a custom VPC.
	Subnets []AwsEc2Subnet

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateVpcInput) error `json:"-"`
}

// AwsEc2VpcResult defines information about a VPC derived from *ec2.Vpc.
type AwsEc2VpcResult struct {
	// The ID of the VPC. This is optional when IsDefault is set to true which will find the default VPC.
	VpcId string

	// Indicates whether the VPC is the default VPC.
	IsDefault bool

	// List of subnet IDs associated with the VPC.
	SubnetIds []string

	// The md5 hash of the input used to create the Vpc.
	InputHash string
}

// Input returns the AWS input for ec2.CreateVpc.
func (m *AwsEc2Vpc) Input() (*ec2.CreateVpcInput, error) {
	input := &ec2.CreateVpcInput{
		// The IPv4 network range for the VPC, in CIDR notation. For example, 10.0.0.0/16.
		// CidrBlock is a required field for creating a custom VPC when IsDefault is false and VpcId is empty.
		CidrBlock: aws.String(m.CidrBlock),

		// Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for
		// the VPC. You cannot specify the range of IP addresses, or the size of the CIDR block.
		// This is only optional for creating a custom VPC when IsDefault is false and VpcId is empty.
		AmazonProvidedIpv6CidrBlock: m.AmazonProvidedIpv6CidrBlock,
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsEc2Subnet describes the detailed needed for creating a subnet for a VPC when not using the default region VPC.
type AwsEc2Subnet struct {
	// The IPv4 network range for the subnet, in CIDR notation. For example, 10.0.0.0/24.
	// CidrBlock is a required field
	CidrBlock string `required:"true"`

	// The Availability Zone for the subnet.
	// Default: AWS selects one for you. If you create more than one subnet in your
	// VPC, we may not necessarily select a different zone for each subnet.
	AvailabilityZone *string

	// The AZ ID of the subnet.
	AvailabilityZoneId *string

	// The IPv6 network range for the subnet, in CIDR notation. The subnet size
	// must use a /64 prefix length.
	Ipv6CidrBlock *string

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateSubnetInput) error `json:"-"`
}

// Input returns the AWS input for ec2.CreateSubnet.
func (m *AwsEc2Subnet) Input(vpcId string) (*ec2.CreateSubnetInput, error) {
	input := &ec2.CreateSubnetInput{
		CidrBlock:          aws.String(m.CidrBlock),
		AvailabilityZone:   m.AvailabilityZone,
		AvailabilityZoneId: m.AvailabilityZoneId,
		Ipv6CidrBlock:      m.Ipv6CidrBlock,
		VpcId:              aws.String(vpcId),
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsEc2SecurityGroup describes an AWS ECS security group. This will use the VPC ID defined for the deployment when
// creating a new security group.
type AwsEc2SecurityGroup struct {
	// The name of the security group.
	// Constraints: Up to 255 characters in length. Cannot start with sg-.
	// Constraints for EC2-Classic: ASCII characters
	// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
	// GroupName is a required field
	GroupName string `required:"true"`

	// A description for the security group. This is informational only.
	// Constraints: Up to 255 characters in length
	// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
	// Description is a required field
	Description string `required:"true"`

	// list of ingress rules for the security group.
	IngressRules []*ec2.AuthorizeSecurityGroupIngressInput

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateSecurityGroupInput) error `json:"-"`
}

// AwsEc2SecurityGroupResult defines information about a security group derived from *ec2.SecurityGroup.
type AwsEc2SecurityGroupResult struct {
	// The ID of the security group.
	GroupId string

	// The name of the security group.
	GroupName string

	// [VPC only] The ID of the VPC for the security group.
	VpcId *string

	// The md5 hash of the input used to create the SecurityGroup.
	InputHash string
}

// Input returns the AWS input for ec2.CreateSecurityGroup.
func (m *AwsEc2SecurityGroup) Input(vpcId string) (*ec2.CreateSecurityGroupInput, error) {
	input := &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(m.GroupName),
		Description: aws.String(m.Description),
		VpcId:       aws.String(vpcId),
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsS3Bucket defines the details needed to create a bucket that includes additional configuration.
type AwsS3Bucket struct {
	// BucketName is a required field
	BucketName string

	// TempPrefix used by services for short term storage. If not empty, a lifecycle policy must be applied for the prefix.
	TempPrefix string

	// IsPublic defined if the S3 Bucket should allow public access. If false, then PublicAccessBlock is required.
	IsPublic bool

	// Specifies the region where the bucket will be created. If you don't specify
	// a region, the bucket is created in US East (N. Virginia) Region (us-east-1).
	LocationConstraint *string

	// A set of lifecycle rules for individual objects in an Amazon S3 bucket.
	LifecycleRules []*s3.LifecycleRule

	// A set of allowed origins and methods.
	CORSRules []*s3.CORSRule

	// The PublicAccessBlock configuration currently in effect for this Amazon S3 bucket.
	PublicAccessBlock *s3.PublicAccessBlockConfiguration

	// The bucket policy as a JSON document.
	Policy string

	// SSE enables AES256 Server-side encryption to use for the default encryption.
	SSE bool

	// Optional to provide additional details to the create input.
	PreCreate func(input *s3.CreateBucketInput) error `json:"-"`

	CloudFront *AwsS3BucketCloudFront
}

// AwsS3BucketResult defines information about a S3 bucket.
type AwsS3BucketResult struct {
	// BucketName is a required field
	BucketName string

	// TempPrefix used by services for short term storage. If not empty, a lifecycle policy must be applied for the prefix.
	TempPrefix string

	// IsPublic defined if the S3 Bucket should allow public access. If false, then PublicAccessBlock is required.
	IsPublic bool

	// Specifies the region where the bucket will be created. If you don't specify
	// a region, the bucket is created in US East (N. Virginia) Region (us-east-1).
	Region string

	// The md5 hash of the input used to create the S3Bucket.
	InputHash string

	// Optional Cloudfront Distribution.
	CloudFront *AwsCloudFrontDistributionResult
}

// Input returns the AWS input for s3.CreateBucket.
func (m *AwsS3Bucket) Input() (*s3.CreateBucketInput, error) {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(m.BucketName),
	}

	if m.LocationConstraint != nil && *m.LocationConstraint != "" && *m.LocationConstraint != "us-east-1" {
		input.CreateBucketConfiguration = &s3.CreateBucketConfiguration{
			LocationConstraint: m.LocationConstraint,
		}
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsS3BucketCloudFront defines the details needed to create a cloudfront distribution for an S3 bucket.
type AwsS3BucketCloudFront struct {
	// S3 key prefix to request your content from a directory in your Amazon S3 bucket.
	// When a user enters example.com/index.html in a browser, CloudFront sends a request to Amazon S3 for
	// 	myawsbucket/production/index.html.
	OriginPath string

	// A complex type that controls whether CloudFront caches the response to requests
	// using the specified HTTP methods. There are two choices:
	//    * CloudFront caches responses to GET and HEAD requests.
	//    * CloudFront caches responses to GET, HEAD, and OPTIONS requests.
	//
	// If you pick the second choice for your Amazon S3 Origin, you may need to
	// forward Access-Control-Request-Method, Access-Control-Request-Headers, and
	// Origin headers for the responses to be cached correctly.
	CachedMethods []string

	// The distribution's configuration information.
	DistributionConfig *cloudfront.DistributionConfig

	// Optional to provide additional details to the create input.
	PreCreate func(input *cloudfront.CreateDistributionInput) error `json:"-"`
}

// AwsCloudFrontDistributionResult defines information about a listener derived from *cloudfront.Distribution.
type AwsCloudFrontDistributionResult struct {
	// The identifier for the distribution. For example: EDFDVBD632BHDS5.
	Id string `required:"true"`

	// The domain name corresponding to the distribution, for example, d111111abcdef8.cloudfront.net.
	DomainName string `required:"true"`

	// The ARN (Amazon Resource Name) for the distribution.
	ARN string `required:"true"`

	// The current configuration information for the distribution. Send a GET request
	// to the /CloudFront API version/distribution ID/config resource.
	DistributionConfig cloudfront.DistributionConfig `required:"true"`

	// The md5 hash of the input used to create the Distribution.
	InputHash string
}

// Input returns the AWS input for cloudfront.CreateDistribution.
func (m *AwsS3BucketCloudFront) Input() (*cloudfront.CreateDistributionInput, error) {
	input := &cloudfront.CreateDistributionInput{
		DistributionConfig: m.DistributionConfig,
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsElasticCacheCluster defines the details needed to create an elastic cache cluster.
type AwsElasticCacheCluster struct {
	// The node group (shard) identifier. This parameter is stored as a lowercase
	// string.
	//
	// Constraints:
	//    * A name must contain from 1 to 20 alphanumeric characters or hyphens.
	//    * The first character must be a letter.
	//    * A name cannot end with a hyphen or contain two consecutive hyphens.
	// CacheClusterId is a required field
	CacheClusterId string `required:"true"`

	// The compute and memory capacity of the nodes in the node group (shard).
	//
	// The following node types are supported by ElastiCache. Generally speaking,
	// the current generation types provide more memory and computational power
	// at lower cost when compared to their equivalent previous generation counterparts.
	//
	//    * General purpose: Current generation: M5 node types: cache.m5.large,
	//    cache.m5.xlarge, cache.m5.2xlarge, cache.m5.4xlarge, cache.m5.12xlarge,
	//    cache.m5.24xlarge M4 node types: cache.m4.large, cache.m4.xlarge, cache.m4.2xlarge,
	//    cache.m4.4xlarge, cache.m4.10xlarge T2 node types: cache.t2.micro, cache.t2.small,
	//    cache.t2.medium Previous generation: (not recommended) T1 node types:
	//    cache.t1.micro M1 node types: cache.m1.small, cache.m1.medium, cache.m1.large,
	//    cache.m1.xlarge M3 node types: cache.m3.medium, cache.m3.large, cache.m3.xlarge,
	//    cache.m3.2xlarge
	//
	//    * Compute optimized: Previous generation: (not recommended) C1 node types:
	//    cache.c1.xlarge
	//
	//    * Memory optimized: Current generation: R5 node types: cache.r5.large,
	//    cache.r5.xlarge, cache.r5.2xlarge, cache.r5.4xlarge, cache.r5.12xlarge,
	//    cache.r5.24xlarge R4 node types: cache.r4.large, cache.r4.xlarge, cache.r4.2xlarge,
	//    cache.r4.4xlarge, cache.r4.8xlarge, cache.r4.16xlarge Previous generation:
	//    (not recommended) M2 node types: cache.m2.xlarge, cache.m2.2xlarge, cache.m2.4xlarge
	//    R3 node types: cache.r3.large, cache.r3.xlarge, cache.r3.2xlarge, cache.r3.4xlarge,
	//    cache.r3.8xlarge
	//
	// Additional node type info
	//    * All current generation instance types are created in Amazon VPC by default.
	//    * Redis append-only files (AOF) are not supported for T1 or T2 instances.
	//    * Redis Multi-AZ with automatic failover is not supported on T1 instances.
	//    * Redis configuration variables appendonly and appendfsync are not supported
	//    on Redis version 2.8.22 and later.
	CacheNodeType string

	// The initial number of cache nodes that the cluster has.
	//
	// For clusters running Redis, this value must be 1. For clusters running Memcached,
	// this value must be between 1 and 20.
	NumCacheNodes int64

	// The name of the parameter group to associate with this cluster. If this argument
	// is omitted, the default parameter group for the specified engine is used.
	// You cannot use any parameter group which has cluster-enabled='yes' when creating
	// a cluster.
	CacheParameterGroupName string

	// The name of the subnet group to be used for the cluster.
	CacheSubnetGroupName string

	// The name of the cache engine to be used for this cluster.
	//
	// Valid values for this parameter are: memcached | redis
	Engine string

	// The version number of the cache engine to be used for this cluster. To view
	// the supported cache engine versions, use the DescribeCacheEngineVersions
	// operation.
	EngineVersion string

	// The port number on which each of the cache nodes accepts connections.
	Port int64

	// This parameter is currently disabled.
	AutoMinorVersionUpgrade *bool

	// The number of days for which ElastiCache retains automatic snapshots before
	// deleting them. For example, if you set SnapshotRetentionLimit to 5, a snapshot
	// taken today is retained for 5 days before being deleted.
	//
	// This parameter is only valid if the Engine parameter is redis.
	//
	// Default: 0 (i.e., automatic backups are disabled for this cache cluster).
	SnapshotRetentionLimit *int64

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag

	// An array of parameter names and values for the parameter update. You must
	// supply at least one parameter name and value; subsequent arguments are optional.
	// A maximum of 20 parameters may be modified per request.
	ParameterNameValues []AwsElasticCacheParameter

	// Optional to provide additional details to the create input.
	PreCreate func(input *elasticache.CreateCacheClusterInput) error `json:"-"`
}

// AwsElasticCacheClusterResult defines information about a cache cluster derived from *elasticache.CacheCluster.
type AwsElasticCacheClusterResult struct {

	// The user-supplied identifier of the cluster. This identifier is a unique
	// key that identifies a cluster.
	CacheClusterId string

	// Represents a Memcached cluster endpoint which, if Automatic Discovery is
	// enabled on the cluster, can be used by an application to connect to any node
	// in the cluster. The configuration endpoint will always have .cfg in it.
	//
	// Example: mem-3.9dvc4r.cfg.usw2.cache.amazonaws.com:11211
	ConfigurationEndpoint *AwsElasticCacheClusterEndpoint

	// A list of cache nodes that are members of the cluster.
	CacheNodes []*AwsElasticCacheNode

	// The md5 hash of the input used to create the CacheCluster.
	InputHash string
}

// AwsElasticCacheClusterEndpoint represents the information required for client programs to connect to a cache node.
type AwsElasticCacheClusterEndpoint struct {
	// The DNS hostname of the cache node.
	Address string

	// The port number that the cache engine is listening on.
	Port int64
}

// AwsElasticCacheClusterResult Represents the information required for client programs to connect to a cache node.
type AwsElasticCacheNode struct {
	// The cache node identifier. A node ID is a numeric identifier (0001, 0002,
	// etc.). The combination of cluster ID and node ID uniquely identifies every
	// cache node used in a customer's AWS account.
	CacheNodeId string

	// The Availability Zone where this node was created and now resides.
	CustomerAvailabilityZone string

	// The date and time when the cache node was created.
	CreatedAt time.Time

	// The hostname for connecting to this cache node.
	Endpoint AwsElasticCacheClusterEndpoint

	// The ID of the primary node to which this read replica node is synchronized.
	// If this field is empty, this node is not associated with a primary cluster.
	SourceCacheNodeId *string
}

// Input returns the AWS input for elasticache.CreateCacheCluster.
func (m *AwsElasticCacheCluster) Input(securityGroup *AwsEc2SecurityGroupResult) (*elasticache.CreateCacheClusterInput, error) {

	input := &elasticache.CreateCacheClusterInput{
		CacheClusterId:          aws.String(m.CacheClusterId),
		CacheNodeType:           aws.String(m.CacheNodeType),
		NumCacheNodes:           aws.Int64(m.NumCacheNodes),
		CacheParameterGroupName: aws.String(m.CacheParameterGroupName),
		CacheSubnetGroupName:    aws.String(m.CacheSubnetGroupName),
		Engine:                  aws.String(m.Engine),
		EngineVersion:           aws.String(m.EngineVersion),
		Port:                    aws.Int64(m.Port),
		AutoMinorVersionUpgrade: m.AutoMinorVersionUpgrade,
		SnapshotRetentionLimit:  m.SnapshotRetentionLimit,
	}

	if securityGroup != nil {
		input.SecurityGroupIds = aws.StringSlice([]string{securityGroup.GroupId})
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &elasticache.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsElasticCacheParameter describes a name-value pair that is used to update the value of a parameter.
type AwsElasticCacheParameter struct {
	// The name of the parameter.
	ParameterName string

	// The value of the parameter.
	ParameterValue string
}

// CacheParameterGroupInput returns the AWS input for elasticache.ModifyCacheParameterGroup.
func (m *AwsElasticCacheCluster) CacheParameterGroupInput(CacheParameterGroupName string) (*elasticache.ModifyCacheParameterGroupInput, error) {

	input := &elasticache.ModifyCacheParameterGroupInput{
		CacheParameterGroupName: aws.String(CacheParameterGroupName),
		ParameterNameValues:     []*elasticache.ParameterNameValue{},
	}

	for _, p := range m.ParameterNameValues {
		input.ParameterNameValues = append(input.ParameterNameValues, &elasticache.ParameterNameValue{
			ParameterName:  aws.String(p.ParameterName),
			ParameterValue: aws.String(p.ParameterValue),
		})
	}

	return input, nil
}

// AwsRdsDBCluster defines the details needed to create a rds database cluster used for the aurora storage engine.
type AwsRdsDBCluster struct {
	// The DB cluster identifier. This parameter is stored as a lowercase string.
	//
	// Constraints:
	//    * Must contain from 1 to 63 letters, numbers, or hyphens.
	//    * First character must be a letter.
	//    * Can't end with a hyphen or contain two consecutive hyphens.
	//
	// Example: my-cluster1
	//
	// DBClusterIdentifier is a required field
	DBClusterIdentifier string `required:"true"`

	// The name for your database of up to 64 alpha-numeric characters.
	DatabaseName string

	// The name of the database engine to be used for this DB cluster.
	//
	// Valid Values: aurora (for MySQL 5.6-compatible Aurora), aurora-mysql (for
	// MySQL 5.7-compatible Aurora), and aurora-postgresql
	//
	// Engine is a required field
	Engine string `required:"true"`

	// The DB engine mode of the DB cluster, either provisioned, serverless, parallelquery,
	// or global.
	EngineMode string

	// The port number on which the instances in the DB cluster accept connections.
	//
	// Default: 3306 if engine is set as aurora or 5432 if set to aurora-postgresql.
	Port int64

	// The name of the master user for the DB cluster.
	//
	// Constraints:
	//    * Must be 1 to 16 letters or numbers.
	//    * First character must be a letter.
	//    * Can't be a reserved word for the chosen database engine.
	MasterUsername string

	// The password for the master database user. This password can contain any
	// printable ASCII character except "/", """, or "@".
	//
	// Constraints: Must contain from 8 to 41 characters.
	MasterUserPassword string

	// The number of days for which automated backups are retained.
	//
	// Default: 1
	//
	// Constraints:
	//
	//    * Must be a value from 1 to 35
	BackupRetentionPeriod *int64

	// A value that indicates that the DB cluster should be associated with the
	// specified CharacterSet.
	CharacterSetName *string

	// A value that indicates whether to copy all tags from the DB cluster to snapshots
	// of the DB cluster. The default is not to copy them.
	CopyTagsToSnapshot *bool

	// Tags to assign to the DB cluster.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *rds.CreateDBClusterInput) error `json:"-"`

	// Optional to provide method to be excecuted after database has been created.
	AfterCreate func(res *rds.DBCluster, info *DBConnInfo, db *sqlx.DB) error `json:"-"`
}

// AwsRdsDBClusterResult defines information about a database cluster derived from *rds.DBCluster.
type AwsRdsDBClusterResult struct {
	// The Amazon Resource Name (ARN) for the DB cluster.
	DBClusterArn string

	// Contains a user-supplied DB cluster identifier. This identifier is the unique
	// key that identifies a DB cluster.
	DBClusterIdentifier string

	// Contains the name of the initial database of this DB cluster that was provided
	// at create time, if one was specified when the DB cluster was created. This
	// same name is returned for the life of the DB cluster.
	DatabaseName string

	// Specifies the connection endpoint for the primary instance of the DB cluster.
	Endpoint string

	// Specifies the port that the database engine is listening on.
	Port int64

	// Provides the name of the database engine to be used for this DB cluster.
	Engine string

	// The DB engine mode of the DB cluster, either provisioned, serverless, or
	// parallelquery.
	EngineMode string

	// Indicates the database engine version.
	EngineVersion string

	// Contains the master username for the DB instance.
	MasterUsername string

	// Specifies the time when the DB cluster was created, in Universal Coordinated
	// Time (UTC).
	CreatedAt time.Time

	// DBConnInfo defines the database connection details.
	// This is optional and will get populated when RDS Cluster is created.
	DBConnInfo *DBConnInfo

	// The md5 hash of the input used to create the DBCluster.
	InputHash string
}

// Input returns the AWS input for rds.CreateDBCluster.
func (m *AwsRdsDBCluster) Input(securityGroup *AwsEc2SecurityGroupResult) (*rds.CreateDBClusterInput, error) {

	input := &rds.CreateDBClusterInput{
		DBClusterIdentifier:   aws.String(m.DBClusterIdentifier),
		DatabaseName:          aws.String(m.DatabaseName),
		Engine:                aws.String(m.Engine),
		EngineMode:            aws.String(m.EngineMode),
		Port:                  aws.Int64(m.Port),
		MasterUsername:        aws.String(m.MasterUsername),
		MasterUserPassword:    aws.String(m.MasterUserPassword),
		BackupRetentionPeriod: m.BackupRetentionPeriod,
		CharacterSetName:      m.CharacterSetName,
		CopyTagsToSnapshot:    m.CopyTagsToSnapshot,
	}

	if securityGroup != nil {
		input.VpcSecurityGroupIds = aws.StringSlice([]string{securityGroup.GroupId})
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &rds.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsRdsDBInstance defines the details needed to create a rds database instance.
type AwsRdsDBInstance struct {
	// The DB instance identifier. This parameter is stored as a lowercase string.
	//
	// Constraints:
	//    * Must contain from 1 to 63 letters, numbers, or hyphens.
	//    * First character must be a letter.
	//    * Can't end with a hyphen or contain two consecutive hyphens.
	//
	// Example: mydbinstance
	//
	// DBInstanceIdentifier is a required field
	DBInstanceIdentifier string `required:"true"`

	// The meaning of this parameter differs according to the database engine you
	// use.
	//
	// MySQL / PostgreSQL
	// 	The name of the database to create when the DB instance is created.
	// 	Constraints:
	//    * Must contain 1 to 64 letters or numbers.
	//    * Must begin with a letter or an underscore. Subsequent characters can
	//    be letters, underscores, or digits (0-9).
	//    * Can't be a word reserved by the specified database engine
	//
	// Amazon Aurora
	// 	The name of the database to create when the primary instance of the DB cluster
	// 	is created.
	// 	Constraints:
	//    * Must contain 1 to 64 letters or numbers.
	//    * Can't be a word reserved by the specified database engine
	//
	// DBName is a required field
	DBName string

	// The name of the database engine to be used for this instance.
	//
	// Not every database engine is available for every AWS Region.
	//
	// Valid Values:
	//    * aurora (for MySQL 5.6-compatible Aurora)
	//    * aurora-mysql (for MySQL 5.7-compatible Aurora)
	//    * aurora-postgresql
	//    * mysql
	//    * postgres
	//
	// Engine is a required field
	Engine string `required:"true"`

	// The version number of the database engine to use.
	//
	// For a list of valid engine versions, use the DescribeDBEngineVersions action.
	EngineVersion *string

	// The name for the master user.
	//
	// Amazon Aurora
	// 	Not applicable. The name for the master user is managed by the DB cluster.
	//
	// MySQL
	// 	Constraints:
	//    * Required for MySQL.
	//    * Must be 1 to 16 letters or numbers.
	//    * First character must be a letter.
	//    * Can't be a reserved word for the chosen database engine.
	//
	// PostgreSQL
	// 	Constraints:
	//    * Required for PostgreSQL.
	//    * Must be 1 to 63 letters or numbers.
	//    * First character must be a letter.
	//    * Can't be a reserved word for the chosen database engine.
	// MasterUsername is a required field for MySQL or PostgreSQL.
	MasterUsername string

	// The password for the master database user. This password can contain any
	// printable ASCII character except "/", """, or "@".
	//
	// Constraints: Must contain from 8 to 41 characters.
	MasterUserPassword string

	// The port number on which the database accepts connections.
	// Valid Values: 1150-65535
	//
	// MySQL
	// 	Default: 3306
	//
	// PostgreSQL
	// 	Default: 5432
	//
	// Amazon Aurora
	// 	Default: 3306
	//
	Port int64

	// The compute and memory capacity of the DB instance, for example, db.m4.large.
	// Not all DB instance classes are available in all AWS Regions, or for all
	// database engines. For the full list of DB instance classes, and availability
	// for your engine, see DB Instance Class (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.html)
	// in the Amazon RDS User Guide.
	//
	// DBInstanceClass is a required field
	DBInstanceClass string `required:"true"`

	// The amount of storage (in gibibytes) to allocate for the DB instance.
	//
	// MySQL/PostgreSQL
	// 	Constraints to the amount of storage for each storage type are the following:
	//    * General Purpose (SSD) storage (gp2): Must be an integer from 20 to 65536.
	//    * Provisioned IOPS storage (io1): Must be an integer from 100 to 65536.
	//
	// Amazon Aurora
	// 	Not applicable. Aurora cluster volumes automatically grow as the amount of
	// 	data in your database increases, though you are only charged for the space
	// 	that you use in an Aurora cluster volume.
	// AllocatedStorage is a required field for MySQL or PostgreSQL.
	AllocatedStorage int64

	// A value that indicates whether the DB instance is publicly accessible. When
	// the DB instance is publicly accessible, it is an Internet-facing instance
	// with a publicly resolvable DNS name, which resolves to a public IP address.
	// When the DB instance is not publicly accessible, it is an internal instance
	// with a DNS name that resolves to a private IP address.
	PubliclyAccessible bool

	// A value that indicates whether minor engine upgrades are applied automatically
	// to the DB instance during the maintenance window. By default, minor engine
	// upgrades are applied automatically.
	AutoMinorVersionUpgrade bool

	// The number of days for which automated backups are retained. Setting this
	// parameter to a positive number enables backups. Setting this parameter to
	// 0 disables automated backups.
	//
	// Amazon Aurora
	// 	Not applicable. The retention period for automated backups is managed by
	// 	the DB cluster.
	//
	// Default: 1
	// Constraints:
	//    * Must be a value from 0 to 35
	//    * Can't be set to 0 if the DB instance is a source to Read Replicas
	BackupRetentionPeriod *int64

	// For supported engines, indicates that the DB instance should be associated
	// with the specified CharacterSet.
	//
	// Amazon Aurora
	// 	Not applicable. The character set is managed by the DB cluster. For more
	// 	information, see CreateDBCluster.
	CharacterSetName *string

	// A value that indicates whether to copy tags from the DB instance to snapshots
	// of the DB instance. By default, tags are not copied.
	//
	// Amazon Aurora
	// 	Not applicable. Copying tags to snapshots is managed by the DB cluster. Setting
	// 	this value for an Aurora DB instance has no effect on the DB cluster setting.
	CopyTagsToSnapshot *bool

	// The identifier of the DB cluster that the instance will belong to.
	DBClusterIdentifier *string

	// Tags to assign to the DB instance.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *rds.CreateDBInstanceInput) error `json:"-"`

	// Optional to provide method to be excecuted after database has been created.
	AfterCreate func(res *rds.DBInstance, info *DBConnInfo, db *sqlx.DB) error `json:"-"`
}

// AwsRdsDBInstanceResult defines information about a database instance derived from *rds.DBInstance.
type AwsRdsDBInstanceResult struct {
	// If the DB instance is a member of a DB cluster, contains the name of the
	// DB cluster that the DB instance is a member of.
	DBClusterIdentifier *string

	// The Amazon Resource Name (ARN) for the DB instance.
	DBInstanceArn string

	// Contains the name of the compute and memory capacity class of the DB instance.
	DBInstanceClass string

	// Contains a user-supplied database identifier. This identifier is the unique
	// key that identifies a DB instance.
	DBInstanceIdentifier string

	// Contains the name of the initial database of this DB cluster that was provided
	// at create time, if one was specified when the DB cluster was created. This
	// same name is returned for the life of the DB cluster.
	DatabaseName string

	// Specifies the connection endpoint for the primary instance of the DB cluster.
	Endpoint string

	// Specifies the port that the database engine is listening on.
	Port int64

	// Provides the name of the database engine to be used for this DB instance.
	Engine string

	// Indicates the database engine version.
	EngineVersion string

	// Contains the master username for the DB instance.
	MasterUsername string

	// Provides the date and time the DB instance was created.
	CreatedAt time.Time

	// DBConnInfo defines the database connection details.
	// This is optional and will get populated when RDS Instance is created.
	DBConnInfo *DBConnInfo

	// The md5 hash of the input used to create the DBInstance.
	InputHash string
}

// Input returns the AWS input for rds.CreateDBInstance.
func (m *AwsRdsDBInstance) Input(securityGroup *AwsEc2SecurityGroupResult) (*rds.CreateDBInstanceInput, error) {

	input := &rds.CreateDBInstanceInput{
		DBInstanceIdentifier:    aws.String(m.DBInstanceIdentifier),
		DBName:                  aws.String(m.DBName),
		Engine:                  aws.String(m.Engine),
		EngineVersion:           m.EngineVersion,
		MasterUsername:          aws.String(m.MasterUsername),
		MasterUserPassword:      aws.String(m.MasterUserPassword),
		Port:                    aws.Int64(m.Port),
		DBInstanceClass:         aws.String(m.DBInstanceClass),
		AllocatedStorage:        aws.Int64(m.AllocatedStorage),
		PubliclyAccessible:      aws.Bool(m.PubliclyAccessible),
		AutoMinorVersionUpgrade: aws.Bool(m.AutoMinorVersionUpgrade),
		BackupRetentionPeriod:   m.BackupRetentionPeriod,
		CharacterSetName:        m.CharacterSetName,
		CopyTagsToSnapshot:      m.CopyTagsToSnapshot,
		DBClusterIdentifier:     m.DBClusterIdentifier,
	}

	if securityGroup != nil {
		input.VpcSecurityGroupIds = aws.StringSlice([]string{securityGroup.GroupId})
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &rds.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsEcsCluster defines the details needed to create an ecs cluster.
type AwsEcsCluster struct {
	// The name of your cluster. If you do not specify a name for your cluster,
	// you create a cluster named default. Up to 255 letters (uppercase and lowercase),
	// numbers, and hyphens are allowed.
	ClusterName string

	// The metadata that you apply to the cluster to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. Tag keys can have a maximum character length of 128 characters, and
	// tag values can have a maximum length of 256 characters.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecs.CreateClusterInput) error `json:"-"`
}

// AwsEcsClusterResult defines information about a cluster derived from *ecs.Cluster.
type AwsEcsClusterResult struct {
	// The Amazon Resource Name (ARN) that identifies the cluster. The ARN contains
	// the arn:aws:ecs namespace, followed by the Region of the cluster, the AWS
	// account ID of the cluster owner, the cluster namespace, and then the cluster
	// name. For example, arn:aws:ecs:region:012345678910:cluster/test.
	ClusterArn string

	// A user-generated string that you use to identify your cluster.
	ClusterName string

	// List of services defined for the cluster.
	Services map[string]*AwsEcsServiceResult

	// The md5 hash of the input used to create the Cluster.
	InputHash string
}

// Input returns the AWS input for ecs.CreateCluster.
func (m *AwsEcsCluster) Input() (*ecs.CreateClusterInput, error) {

	input := &ecs.CreateClusterInput{
		ClusterName: aws.String(m.ClusterName),
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &ecs.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// GetService returns *AwsEcsServiceResult by service name.
func (m *AwsEcsClusterResult) GetService(serviceName string) (*AwsEcsServiceResult, error) {
	result, ok := m.Services[serviceName]
	if !ok {
		return nil, errors.Errorf("No service configured for '%s'", serviceName)
	}
	return result, nil
}

// AwsEcsService defines the details needed to create an ecs service.
type AwsEcsService struct {

	// The name of your service. Up to 255 letters (uppercase and lowercase), numbers,
	// and hyphens are allowed. Service names must be unique within a cluster, but
	// you can have similarly named services in multiple clusters within a Region
	// or across multiple Regions.
	//
	// ServiceName is a required field
	ServiceName string `required:"true"`

	// The number of instantiations of the specified task definition to place and
	// keep running on your cluster.
	DesiredCount int64

	// If a service is using the rolling update (ECS) deployment type, the maximum
	// percent parameter represents an upper limit on the number of tasks in a service
	// that are allowed in the RUNNING or PENDING state during a deployment, as
	// a percentage of the desired number of tasks (rounded down to the nearest
	// integer), and while any container instances are in the DRAINING state if
	// the service contains tasks using the EC2 launch type. This parameter enables
	// you to define the deployment batch size. For example, if your service has
	// a desired number of four tasks and a maximum percent value of 200%, the scheduler
	// may start four new tasks before stopping the four older tasks (provided that
	// the cluster resources required to do this are available). The default value
	// for maximum percent is 200%.
	//
	// If a service is using the blue/green (CODE_DEPLOY) or EXTERNAL deployment
	// types and tasks that use the EC2 launch type, the maximum percent value is
	// set to the default value and is used to define the upper limit on the number
	// of the tasks in the service that remain in the RUNNING state while the container
	// instances are in the DRAINING state. If the tasks in the service use the
	// Fargate launch type, the maximum percent value is not used, although it is
	// returned when describing your service.
	DeploymentMaximumPercent int64

	// If a service is using the rolling update (ECS) deployment type, the minimum
	// healthy percent represents a lower limit on the number of tasks in a service
	// that must remain in the RUNNING state during a deployment, as a percentage
	// of the desired number of tasks (rounded up to the nearest integer), and while
	// any container instances are in the DRAINING state if the service contains
	// tasks using the EC2 launch type. This parameter enables you to deploy without
	// using additional cluster capacity. For example, if your service has a desired
	// number of four tasks and a minimum healthy percent of 50%, the scheduler
	// may stop two existing tasks to free up cluster capacity before starting two
	// new tasks. Tasks for services that do not use a load balancer are considered
	// healthy if they are in the RUNNING state; tasks for services that do use
	// a load balancer are considered healthy if they are in the RUNNING state and
	// they are reported as healthy by the load balancer. The default value for
	// minimum healthy percent is 100%.
	//
	// If a service is using the blue/green (CODE_DEPLOY) or EXTERNAL deployment
	// types and tasks that use the EC2 launch type, the minimum healthy percent
	// value is set to the default value and is used to define the lower limit on
	// the number of the tasks in the service that remain in the RUNNING state while
	// the container instances are in the DRAINING state. If the tasks in the service
	// use the Fargate launch type, the minimum healthy percent value is not used,
	// although it is returned when describing your service.
	DeploymentMinimumHealthyPercent int64

	// The period of time, in seconds, that the Amazon ECS service scheduler should
	// ignore unhealthy Elastic Load Balancing target health checks after a task
	// has first started. This is only valid if your service is configured to use
	// a load balancer. If your service's tasks take a while to start and respond
	// to Elastic Load Balancing health checks, you can specify a health check grace
	// period of up to 2,147,483,647 seconds. During that time, the ECS service
	// scheduler ignores health check status. This grace period can prevent the
	// ECS service scheduler from marking tasks as unhealthy and stopping them before
	// they have time to come up.
	HealthCheckGracePeriodSeconds int64

	// The launch type on which to run your service. For more information, see Amazon
	// ECS Launch Types (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/launch_types.html)
	// in the Amazon Elastic Container Service Developer Guide.
	LaunchType string

	// Specifies whether to enable Amazon ECS managed tags for the tasks within
	// the service. For more information, see Tagging Your Amazon ECS Resources
	// (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html)
	// in the Amazon Elastic Container Service Developer Guide.
	EnableECSManagedTags bool

	// The metadata that you apply to the service to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. When a service is deleted, the tags are deleted as well. Tag keys
	// can have a maximum character length of 128 characters, and tag values can
	// have a maximum length of 256 characters.
	Tags []Tag

	// Force the current service is one exists to be deleted and a fresh service to be created.
	ForceRecreate bool `validate:"omitempty"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecs.CreateServiceInput) error `json:"-"`

	// Optional to provide additional details to the update input.
	PreUpdate func(input *ecs.UpdateServiceInput) error `json:"-"`
}

// AwsEcsServiceResult defines information about a service derived from *ecs.Service.
type AwsEcsServiceResult struct {

	// The ARN that identifies the service. The ARN contains the arn:aws:ecs namespace,
	// followed by the Region of the service, the AWS account ID of the service
	// owner, the service namespace, and then the service name. For example, arn:aws:ecs:region:012345678910:service/my-service.
	ServiceArn string

	// The name of your service. Up to 255 letters (uppercase and lowercase), numbers,
	// and hyphens are allowed. Service names must be unique within a cluster, but
	// you can have similarly named services in multiple clusters within a Region
	// or across multiple Regions.
	ServiceName string

	// The Amazon Resource Name (ARN) of the cluster that hosts the service.
	ClusterArn string

	// The desired number of instantiations of the task definition to keep running
	// on the service. This value is specified when the service is created with
	// CreateService, and it can be modified with UpdateService.
	DesiredCount int64

	// The launch type on which your service is running. If no value is specified,
	// it will default to EC2. Valid values include EC2 and FARGATE. For more information,
	// see Amazon ECS Launch Types (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/launch_types.html)
	// in the Amazon Elastic Container Service Developer Guide.
	LaunchType string

	// The task definition to use for tasks in the service.
	TaskDefinition *AwsEcsTaskDefinitionResult

	// The md5 hash of the input used to create the Service.
	InputHash string
}

// AwsEcsTaskDefinition defines the details needed to register an ecs task definition.
type AwsEcsTaskDefinition struct {
	// The task definition input defined.
	RegisterInput *ecs.RegisterTaskDefinitionInput `validate:"required"`

	// Optional to provide additional details to the register input.
	PreRegister func(input *ecs.RegisterTaskDefinitionInput, vars AwsEcsServiceDeployVariables) error `json:"-"`
}

// AwsEcsServiceDeployDetails defines the details that can be used as env of placeholders that can be used in task
// definition and replaced on deployment.
type AwsEcsServiceDeployVariables struct {
	ProjectName                  string
	ServiceName                  string
	ServiceBaseUrl               string
	PrimaryHostname              string
	AlternativeHostnames         []string
	ReleaseImage                 string
	AwsRegion                    string
	AwsLogGroupName              string
	AwsS3BucketNamePrivate       string
	AwsS3BucketNamePublic        string
	AwsExecutionRoleArn          string
	AwsTaskRoleArn               string
	Env                          string
	HTTPHost                     string
	HTTPSHost                    string
	HTTPSEnabled                 bool
	StaticFilesS3Enabled         bool
	StaticFilesS3Prefix          string
	StaticFilesCloudfrontEnabled bool
	CacheHost                    string
	DbHost                       string
	DbUser                       string
	DbPass                       string
	DbName                       string
	DbDriver                     string
	DbDisableTLS                 bool
	Route53Zones                 map[string][]string
	AwsEc2Vpc                    *AwsEc2VpcResult
	AwsEc2SecurityGroup          *AwsEc2SecurityGroupResult
	AwsSdService                 *AwsSdServiceResult
	AwsElbLoadBalancer           *AwsElbLoadBalancerResult
	AwsEcsCluster                *AwsEcsClusterResult
	ProjectService               *ProjectService
}

// EncodeRoute53Zones returns the base64 json encoded string of Route53Zones that can be used as an envirnment variable.
// This is to be used by the service for maintaining A records when new tasks are spun up or down.
func (vars AwsEcsServiceDeployVariables) EncodeRoute53Zones() string {
	if len(vars.Route53Zones) == 0 {
		return ""
	}

	dat, err := json.Marshal(vars.Route53Zones)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(dat)
}

// AwsEcsTaskDefinitionResult wraps *ecs.TaskDefinition.
type AwsEcsTaskDefinitionResult struct {
	*ecs.TaskDefinition

	// The md5 hash of the input used to create the Task Definition.
	InputHash string
}

// Input returns the AWS input for ecs.RegisterTaskDefinition.
func (m *AwsEcsTaskDefinition) Input(vars AwsEcsServiceDeployVariables) (*ecs.RegisterTaskDefinitionInput, error) {

	input := m.RegisterInput

	if m.PreRegister != nil {
		if err := m.PreRegister(input, vars); err != nil {
			return input, err
		}
	}

	return input, nil
}

// CreateInput returns the AWS input for ecs.CreateService.
func (m *AwsEcsService) CreateInput(cluster *AwsEcsClusterResult, taskDefinition *AwsEcsTaskDefinitionResult, vpc *AwsEc2VpcResult, securityGroup *AwsEc2SecurityGroupResult, ecsELBs []*ecs.LoadBalancer, sdService *AwsSdServiceResult) (*ecs.CreateServiceInput, error) {

	var (
		assignPublicIp                *string
		healthCheckGracePeriodSeconds *int64
	)
	if len(ecsELBs) > 0 {
		// TODO: It would be nice to set this to DISABLED and not assign public IPs if we are using an ELB, but
		// 		ECS can't pull the image from ECR when its set to disabled.
		assignPublicIp = aws.String("ENABLED")

		healthCheckGracePeriodSeconds = aws.Int64(m.HealthCheckGracePeriodSeconds)
	} else {
		assignPublicIp = aws.String("ENABLED")
	}

	input := &ecs.CreateServiceInput{
		ServiceName:  aws.String(m.ServiceName),
		DesiredCount: aws.Int64(m.DesiredCount),
		DeploymentConfiguration: &ecs.DeploymentConfiguration{
			// Refer to documentation for flags.ecsServiceMaximumPercent
			MaximumPercent: aws.Int64(m.DeploymentMaximumPercent),
			// Refer to documentation for flags.ecsServiceMinimumHealthyPercent
			MinimumHealthyPercent: aws.Int64(m.DeploymentMinimumHealthyPercent),
		},
		HealthCheckGracePeriodSeconds: healthCheckGracePeriodSeconds,
		LaunchType:                    aws.String(m.LaunchType),
		LoadBalancers:                 ecsELBs,
		NetworkConfiguration: &ecs.NetworkConfiguration{
			AwsvpcConfiguration: &ecs.AwsVpcConfiguration{
				AssignPublicIp: assignPublicIp,
			},
		},
		EnableECSManagedTags: aws.Bool(m.EnableECSManagedTags),
	}

	if cluster != nil {
		input.Cluster = aws.String(cluster.ClusterName)
	}

	if taskDefinition != nil {
		input.TaskDefinition = taskDefinition.TaskDefinitionArn
	}

	if securityGroup != nil {
		input.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups = aws.StringSlice([]string{
			securityGroup.GroupId,
		})
	}

	if vpc != nil {
		input.NetworkConfiguration.AwsvpcConfiguration.Subnets = aws.StringSlice(vpc.SubnetIds)
	}

	if input.DesiredCount == nil || *input.DesiredCount == 0 {
		input.DesiredCount = aws.Int64(1)
	}

	// Add the Service Discovery registry to the ECS service.
	if sdService != nil {
		if input.ServiceRegistries == nil {
			input.ServiceRegistries = []*ecs.ServiceRegistry{}
		}
		input.ServiceRegistries = append(input.ServiceRegistries, &ecs.ServiceRegistry{
			RegistryArn: aws.String(sdService.Arn),
		})
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &ecs.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// UpdateInput returns the AWS input for ecs.UpdateService.
func (m *AwsEcsService) UpdateInput(cluster *AwsEcsClusterResult, taskDefinition *AwsEcsTaskDefinitionResult, desiredCount int64) (*ecs.UpdateServiceInput, error) {

	input := &ecs.UpdateServiceInput{
		Service:      aws.String(m.ServiceName),
		DesiredCount: aws.Int64(desiredCount),
	}

	if cluster != nil {
		input.Cluster = aws.String(cluster.ClusterName)
	}

	if taskDefinition != nil {
		input.TaskDefinition = taskDefinition.TaskDefinitionArn
	}

	// If the desired count is zero because it was spun down for termination of staging env, update to launch
	// with at least once task running for the service.
	if input.DesiredCount == nil || *input.DesiredCount == 0 {
		if m.DesiredCount == 0 {
			m.DesiredCount = 1
		}
		input.DesiredCount = aws.Int64(m.DesiredCount)
	}

	if m.PreUpdate != nil {
		if err := m.PreUpdate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsIamRole defines the details needed to create an iam role.
type AwsIamRole struct {
	// The name of the role to create.
	//
	// IAM user, group, role, and policy names must be unique within the account.
	// Names are not distinguished by case. For example, you cannot create resources
	// named both "MyResource" and "myresource".
	//
	// RoleName is a required field
	RoleName string `required:"true"`

	// A description of the role.
	Description string

	// The trust relationship policy document that grants an entity permission to assume the role.
	//
	// AssumeRolePolicyDocument is a required field
	AssumeRolePolicyDocument string `required:"true"`

	// Set of the specified managed policy to attach to the IAM role.
	AttachRolePolicyArns []string

	// A list of tags that you want to attach to the newly created role. Each tag
	// consists of a key name and an associated value. For more information about
	// tagging, see Tagging IAM Identities (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html)
	// in the IAM User Guide.
	//
	// If any one of the tags is invalid or if you exceed the allowed number of
	// tags per role, then the entire request fails and the role is not created.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *iam.CreateRoleInput) error `json:"-"`
}

// AwsIamRoleResult defines information about a role derived from *iam.Role.
type AwsIamRoleResult struct {
	// The stable and unique string identifying the role.
	RoleId string

	// The friendly name that identifies the role.
	RoleName string

	// The Amazon Resource Name (ARN) specifying the role.
	Arn string

	// The date and time when the role was created.
	CreatedAt time.Time

	// The md5 hash of the input used to create the Role.
	InputHash string
}

// Input returns the AWS input for iam.CreateRole.
func (m *AwsIamRole) Input() (*iam.CreateRoleInput, error) {

	input := &iam.CreateRoleInput{
		RoleName:                 aws.String(m.RoleName),
		Description:              aws.String(m.Description),
		AssumeRolePolicyDocument: aws.String(m.AssumeRolePolicyDocument),
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &iam.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsIamPolicy defines the details needed to create an iam policy.
type AwsIamPolicy struct {
	// The friendly name of the policy.
	//
	// IAM user, group, role, and policy names must be unique within the account.
	// Names are not distinguished by case. For example, you cannot create resources
	// named both "MyResource" and "myresource".
	//
	// PolicyName is a required field
	PolicyName string `required:"true"`

	// A friendly description of the policy.
	//
	// Typically used to store information about the permissions defined in the
	// policy. For example, "Grants access to production DynamoDB tables."
	//
	// The policy description is immutable. After a value is assigned, it cannot
	// be changed.
	Description string

	// The policy document that you want to use as the content for the new
	// policy.
	//
	// PolicyDocument is a required field
	PolicyDocument AwsIamPolicyDocument

	// Optional to provide additional details to the create input.
	PreCreate func(input *iam.CreatePolicyInput) error `json:"-"`
}

// AwsIamPolicyResult defines information about a policy derived from *iam.Policy.
type AwsIamPolicyResult struct {
	// The stable and unique string identifying the policy.
	PolicyId string

	// The friendly name (not ARN) identifying the policy.
	PolicyName string

	// The Amazon Resource Name (ARN). ARNs are unique identifiers for AWS resources.
	Arn string

	// The date and time when the policy was created.
	CreatedAt time.Time

	// The md5 hash of the input used to create the Policy.
	InputHash string
}

// Input returns the AWS input for iam.CreatePolicy.
func (m *AwsIamPolicy) Input() (*iam.CreatePolicyInput, error) {

	input := &iam.CreatePolicyInput{
		PolicyName:  aws.String(m.PolicyName),
		Description: aws.String(m.Description),
	}

	dat, err := json.Marshal(m.PolicyDocument)
	if err != nil {
		return input, errors.Wrap(err, "Failed to json encode policy document")
	}
	input.PolicyDocument = aws.String(string(dat))

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsIamPolicyDocument defines an AWS IAM policy used for defining access for IAM roles, users, and groups.
type AwsIamPolicyDocument struct {
	Version   string                 `json:"Version"`
	Statement []AwsIamStatementEntry `json:"Statement"`
}

// AwsIamStatementEntry defines a single statement for an IAM policy.
type AwsIamStatementEntry struct {
	Sid      string      `json:"Sid"`
	Effect   string      `json:"Effect"`
	Action   []string    `json:"Action"`
	Resource interface{} `json:"Resource"`
}

// AwsCloudWatchLogGroup defines the details needed to create a Cloudwatch log group.
type AwsCloudWatchLogGroup struct {
	// The name of the log group.
	//
	// LogGroupName is a required field
	LogGroupName string `required:"true"`

	// The key-value pairs to use for the tags.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *cloudwatchlogs.CreateLogGroupInput) error `json:"-"`
}

// AwsCloudWatchLogGroupResult defines information about the Cloudwatch Log Group.
type AwsCloudWatchLogGroupResult struct {
	// The name of the log group.
	LogGroupName string

	// The md5 hash of the input used to create the Log Group.
	InputHash string
}

// Input returns the AWS input for cloudwatchlogs.CreateLogGroup.
func (m *AwsCloudWatchLogGroup) Input() (*cloudwatchlogs.CreateLogGroupInput, error) {

	input := &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(m.LogGroupName),
	}

	input.Tags = make(map[string]*string)
	for _, t := range m.Tags {
		input.Tags[t.Key] = aws.String(t.Value)
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsAcmCertificateResult defines information about a certificate derived from *acm.CertificateSummary.
type AwsAcmCertificateResult struct {
	// Amazon Resource Name (ARN) of the certificate. This is of the form:
	CertificateArn string

	// Fully qualified domain name (FQDN), such as www.example.com or example.com,
	// for the certificate.
	DomainName string

	// The status of the certificate.
	Status string

	// The md5 hash of the input used to create the Certificate.
	InputHash string
}

// AwsElbLoadBalancer defines the details needed to create an elbv2 load balancer.
type AwsElbLoadBalancer struct {
	// The name of the load balancer.
	//
	// This name must be unique per region per account, can have a maximum of 32
	// characters, must contain only alphanumeric characters or hyphens, must not
	// begin or end with a hyphen, and must not begin with "internal-".
	Name string

	// [Application Load Balancers] The type of IP addresses used by the subnets
	// for your load balancer. The possible values are ipv4 (for IPv4 addresses)
	// and dualstack (for IPv4 and IPv6 addresses). Internal load balancers must
	// use ipv4.
	IpAddressType string

	// The nodes of an Internet-facing load balancer have public IP addresses. The
	// DNS name of an Internet-facing load balancer is publicly resolvable to the
	// public IP addresses of the nodes. Therefore, Internet-facing load balancers
	// can route requests from clients over the internet.
	//
	// The nodes of an internal load balancer have only private IP addresses. The
	// DNS name of an internal load balancer is publicly resolvable to the private
	// IP addresses of the nodes. Therefore, internal load balancers can only route
	// requests from clients with access to the VPC for the load balancer.
	//
	// The default is an Internet-facing load balancer.
	Scheme string

	// The type of load balancer. The default is application.
	Type string

	// The number of seconds to wait before removing task from target group.
	EcsTaskDeregistrationDelay int

	// The key-value pairs to use for the tags.
	Tags []Tag

	// The set of target groups for an application load balancer.
	TargetGroups []*AwsElbTargetGroup

	// Optional to provide list of listeners to be attached to the load balancer.
	Listeners []*AwsElbListener

	// Optional to provide additional details to the create input.
	PreCreate func(input *elbv2.CreateLoadBalancerInput) error `json:"-"`
}

// AwsElbLoadBalancerResult defines information about a load balancer derived from *elbv2.LoadBalancer.
type AwsElbLoadBalancerResult struct {
	// The Amazon Resource Name (ARN) of the load balancer.
	LoadBalancerArn string

	// The name of the load balancer.
	LoadBalancerName string

	// The ID of the Amazon Route 53 hosted zone associated with the load balancer.
	CanonicalHostedZoneId string

	// The public DNS name of the load balancer.
	DNSName string

	// The type of IP addresses used by the subnets for your load balancer. The
	// possible values are ipv4 (for IPv4 addresses) and dualstack (for IPv4 and
	// IPv6 addresses).
	IpAddressType string

	// The nodes of an Internet-facing load balancer have public IP addresses. The
	// DNS name of an Internet-facing load balancer is publicly resolvable to the
	// public IP addresses of the nodes. Therefore, Internet-facing load balancers
	// can route requests from clients over the internet.
	//
	// The nodes of an internal load balancer have only private IP addresses. The
	// DNS name of an internal load balancer is publicly resolvable to the private
	// IP addresses of the nodes. Therefore, internal load balancers can only route
	// requests from clients with access to the VPC for the load balancer.
	Scheme string

	// The listeners attached to the load balancer.
	Listeners []*AwsElbListenerResult

	// The target groups associated to the attached listeners for the load balancer.
	TargetGroups []*AwsElbTargetGroupResult

	// The md5 hash of the input used to create the LoadBalancer.
	InputHash string
}

// Input returns the AWS input for elbv2.CreateLoadBalance.
func (m *AwsElbLoadBalancer) Input(vpc *AwsEc2VpcResult, securityGroup *AwsEc2SecurityGroupResult) (*elbv2.CreateLoadBalancerInput, error) {

	input := &elbv2.CreateLoadBalancerInput{
		Name:          aws.String(m.Name),
		IpAddressType: aws.String(m.IpAddressType),
		Scheme:        aws.String(m.Scheme),
		Type:          aws.String(m.Type),
	}

	if securityGroup != nil {
		input.SecurityGroups = aws.StringSlice([]string{
			securityGroup.GroupId,
		})
	}
	if vpc != nil {
		input.Subnets = aws.StringSlice(vpc.SubnetIds)
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &elbv2.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsElbListener defines the details needed to create an elbv2 listener.
type AwsElbListener struct {

	// [HTTPS and TLS listeners] The default certificate for the listener. You must
	// provide exactly one certificate. Set CertificateArn to the certificate ARN
	// but do not set IsDefault.
	Certificates []*AwsElbCertificate

	// The actions for the default rule. The rule must include one forward action
	// or one or more fixed-response actions.
	//
	// If the action type is forward, you specify a target group. The protocol of
	// the target group must be HTTP or HTTPS for an Application Load Balancer.
	// The protocol of the target group must be TCP, TLS, UDP, or TCP_UDP for a
	// Network Load Balancer.
	//
	// [HTTPS listeners] If the action type is authenticate-oidc, you authenticate
	// users through an identity provider that is OpenID Connect (OIDC) compliant.
	//
	// [HTTPS listeners] If the action type is authenticate-cognito, you authenticate
	// users through the user pools supported by Amazon Cognito.
	//
	// [Application Load Balancer] If the action type is redirect, you redirect
	// specified client requests from one URL to another.
	//
	// [Application Load Balancer] If the action type is fixed-response, you drop
	// specified client requests and return a custom HTTP response.
	//
	// DefaultActions is a required field
	DefaultActions []*AwsElbAction

	// The Amazon Resource Name (ARN) of the load balancer.
	//
	// LoadBalancerArn is a required field
	LoadBalancerArn string `required:"true"`

	// The port on which the load balancer is listening.
	Port int64 `required:"true"`

	// The protocol for connections from clients to the load balancer. For Application
	// Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load
	// Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP.
	Protocol string `required:"true"`

	// Optional to provide additional details to the create input.
	PreCreate func(elb *AwsElbLoadBalancerResult, input *elbv2.CreateListenerInput) error `json:"-"`
}

// AwsElbListenerResult defines information about a listener derived from *elbv2.Listener.
type AwsElbListenerResult struct {

	// [HTTPS or TLS listener] The default certificate for the listener.
	Certificates []*AwsElbCertificate

	// The default actions for the listener.
	DefaultActions []*AwsElbAction

	// The Amazon Resource Name (ARN) of the listener.
	ListenerArn string

	// The Amazon Resource Name (ARN) of the load balancer.
	LoadBalancerArn string

	// The port on which the load balancer is listening.
	Port int64

	// The protocol for connections from clients to the load balancer.
	Protocol string

	// The md5 hash of the input used to create the Listener.
	InputHash string
}

// AwsElbCertificate defines information about a certificate derived from *elbv2.Certificate.
type AwsElbCertificate struct {
	// The Amazon Resource Name (ARN) of the certificate.
	CertificateArn string

	// Indicates whether the certificate is the default certificate. Do not set
	// this value when specifying a certificate as an input. This value is not included
	// in the output when describing a listener, but is included when describing
	// listener certificates.
	IsDefault bool
}

// AwsElbAction defines information about an action derived from *elbv2.Action.
type AwsElbAction struct {
	// The type of action. Each rule must include exactly one of the following types
	// of actions: forward, fixed-response, or redirect.
	//
	// Type is a required field
	Type string

	// The Amazon Resource Name (ARN) of the target group. Specify only when Type
	// is forward.
	TargetGroupArn string

	// [Application Load Balancer] Information for creating a redirect action. Specify
	// only when Type is redirect.
	RedirectConfig *AwsElbRedirectActionConfig

	// The order for the action. This value is required for rules with multiple
	// actions. The action with the lowest value for order is performed first. The
	// final action to be performed must be a forward or a fixed-response action.
	Order *int64
}

// AwsElbRedirectActionConfig defines information about an action derived from *elbv2.RedirectActionConfig.
type AwsElbRedirectActionConfig struct {
	// The hostname. This component is not percent-encoded. The hostname can contain
	// #{host}.
	Host string

	// The absolute path, starting with the leading "/". This component is not percent-encoded.
	// The path can contain #{host}, #{path}, and #{port}.
	Path string

	// The port. You can specify a value from 1 to 65535 or #{port}.
	Port string

	// The protocol. You can specify HTTP, HTTPS, or #{protocol}. You can redirect
	// HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS
	// to HTTP.
	Protocol string

	// The query parameters, URL-encoded when necessary, but not percent-encoded.
	// Do not include the leading "?", as it is automatically added. You can specify
	// any of the reserved keywords.
	Query string

	// The HTTP redirect code. The redirect is either permanent (HTTP 301) or temporary
	// (HTTP 302).
	//
	// StatusCode is a required field
	StatusCode string
}

// Input returns the AWS input for elbv2.CreatListener.
func (m *AwsElbListener) Input(elb *AwsElbLoadBalancerResult) (*elbv2.CreateListenerInput, error) {

	input := &elbv2.CreateListenerInput{
		LoadBalancerArn: aws.String(m.LoadBalancerArn),
		Port:            aws.Int64(m.Port),
		Protocol:        aws.String(m.Protocol),
	}

	if m.LoadBalancerArn != "" {
		input.LoadBalancerArn = aws.String(m.LoadBalancerArn)
	} else if elb != nil {
		input.LoadBalancerArn = aws.String(elb.LoadBalancerArn)
	}

	if len(m.Certificates) > 0 {
		for _, c := range m.Certificates {
			input.Certificates = append(input.Certificates, &elbv2.Certificate{
				CertificateArn: aws.String(c.CertificateArn),
			})
		}
	}

	if len(m.DefaultActions) > 0 {
		for _, a := range m.DefaultActions {

			ia := &elbv2.Action{
				TargetGroupArn: aws.String(a.TargetGroupArn),
				Type:           aws.String(a.Type),
			}

			if a.RedirectConfig != nil {
				ia.RedirectConfig = &elbv2.RedirectActionConfig{
					Host:       aws.String(a.RedirectConfig.Host),
					Path:       aws.String(a.RedirectConfig.Path),
					Port:       aws.String(a.RedirectConfig.Port),
					Protocol:   aws.String(a.RedirectConfig.Protocol),
					Query:      aws.String(a.RedirectConfig.Query),
					StatusCode: aws.String(a.RedirectConfig.StatusCode),
				}
			}

			input.DefaultActions = append(input.DefaultActions, ia)
		}
	}

	if m.PreCreate != nil {
		if elb == nil {
			elb = &AwsElbLoadBalancerResult{}
		}

		if err := m.PreCreate(elb, input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsElbTargetGroup defines the details needed to create an elbv2 target group.
type AwsElbTargetGroup struct {
	// The name of the target group.
	//
	// This name must be unique per region per account, can have a maximum of 32
	// characters, must contain only alphanumeric characters or hyphens, and must
	// not begin or end with a hyphen.
	//
	// Name is a required field
	Name string

	// The port on which the targets receive traffic. This port is used unless you
	// specify a port override when registering the target. If the target is a Lambda
	// function, this parameter does not apply.
	Port int64

	// The protocol to use for routing traffic to the targets. For Application Load
	// Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers,
	// the supported protocols are TCP, TLS, UDP, or TCP_UDP. A TCP_UDP listener
	// must be associated with a TCP_UDP target group. If the target is a Lambda
	// function, this parameter does not apply.
	Protocol string

	// The type of target that you must specify when registering targets with this
	// target group. You can't specify targets for a target group using more than
	// one target type.
	//
	//    * instance - Targets are specified by instance ID. This is the default
	//    value. If the target group protocol is UDP or TCP_UDP, the target type
	//    must be instance.
	//
	//    * ip - Targets are specified by IP address. You can specify IP addresses
	//    from the subnets of the virtual private cloud (VPC) for the target group,
	//    the RFC 1918 range (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16), and
	//    the RFC 6598 range (100.64.0.0/10). You can't specify publicly routable
	//    IP addresses.
	//
	//    * lambda - The target groups contains a single Lambda function.
	TargetType string

	// Indicates whether health checks are enabled. If the target type is lambda,
	// health checks are disabled by default but can be enabled. If the target type
	// is instance or ip, health checks are always enabled and cannot be disabled.
	HealthCheckEnabled bool

	// The approximate amount of time, in seconds, between health checks of an individual
	// target. For HTTP and HTTPS health checks, the range is 5–300 seconds. For
	// TCP health checks, the supported values are 10 and 30 seconds. If the target
	// type is instance or ip, the default is 30 seconds. If the target type is
	// lambda, the default is 35 seconds.
	HealthCheckIntervalSeconds int64

	// [HTTP/HTTPS health checks] The ping path that is the destination on the targets
	// for health checks. The default is /.
	HealthCheckPath string

	// The protocol the load balancer uses when performing health checks on targets.
	// For Application Load Balancers, the default is HTTP. For Network Load Balancers,
	// the default is TCP. The TCP protocol is supported for health checks only
	// if the protocol of the target group is TCP, TLS, UDP, or TCP_UDP. The TLS,
	// UDP, and TCP_UDP protocols are not supported for health checks.
	HealthCheckProtocol string

	// The amount of time, in seconds, during which no response from a target means
	// a failed health check. For target groups with a protocol of HTTP or HTTPS,
	// the default is 5 seconds. For target groups with a protocol of TCP or TLS,
	// this value must be 6 seconds for HTTP health checks and 10 seconds for TCP
	// and HTTPS health checks. If the target type is lambda, the default is 30
	// seconds.
	HealthCheckTimeoutSeconds int64

	// The number of consecutive health checks successes required before considering
	// an unhealthy target healthy. For target groups with a protocol of HTTP or
	// HTTPS, the default is 5. For target groups with a protocol of TCP or TLS,
	// the default is 3. If the target type is lambda, the default is 5.
	HealthyThresholdCount int64

	// The number of consecutive health check failures required before considering
	// a target unhealthy. For target groups with a protocol of HTTP or HTTPS, the
	// default is 2. For target groups with a protocol of TCP or TLS, this value
	// must be the same as the healthy threshold count. If the target type is lambda,
	// the default is 2.
	UnhealthyThresholdCount int64

	// [HTTP/HTTPS health checks] The HTTP codes to use when checking for a successful
	// response from a target.
	//
	// For Application Load Balancers, you can specify values between 200 and 499,
	// and the default value is 200. You can specify multiple values (for example,
	// "200,202") or a range of values (for example, "200-299").
	//
	// HttpCode is a required field
	Matcher string

	// Optional to provide additional details to the create input.
	PreCreate func(input *elbv2.CreateTargetGroupInput) error `json:"-"`
}

// AwsElbTargetGroupResult defines information about a target group derived from *elbv2.TargetGroup.
type AwsElbTargetGroupResult struct {

	// Indicates whether health checks are enabled.
	HealthCheckEnabled bool

	// The approximate amount of time, in seconds, between health checks of an individual target.
	HealthCheckIntervalSeconds int64

	// The destination for the health check request.
	HealthCheckPath string

	// The port to use to connect with the target.
	HealthCheckPort string

	// The protocol to use to connect with the target.
	HealthCheckProtocol string

	// The amount of time, in seconds, during which no response means a failed health check.
	HealthCheckTimeoutSeconds int64

	// The number of consecutive health checks successes required before considering an unhealthy target healthy.
	HealthyThresholdCount int64

	// The Amazon Resource Names (ARN) of the load balancers that route traffic to this target group.
	LoadBalancerArns []string

	// The HTTP codes to use when checking for a successful response from a target.
	Matcher string

	// The port on which the targets are listening.
	Port int64

	// The protocol to use for routing traffic to the targets.
	Protocol string

	// The Amazon Resource Name (ARN) of the target group.
	TargetGroupArn string

	// The name of the target group.
	TargetGroupName string

	// The type of target that you must specify when registering targets with this
	// target group. The possible values are instance (targets are specified by
	// instance ID) or ip (targets are specified by IP address).
	TargetType string

	// The number of consecutive health check failures required before considering
	// the target unhealthy.
	UnhealthyThresholdCount int64

	// The ID of the VPC for the targets.
	VpcId string

	// The md5 hash of the input used to create the TargetGroup.
	InputHash string
}

// Input returns the AWS input for elbv2.CreateTargetGroup.
func (m *AwsElbTargetGroup) Input(vpc *AwsEc2VpcResult) (*elbv2.CreateTargetGroupInput, error) {

	input := &elbv2.CreateTargetGroupInput{
		Name:                       aws.String(m.Name),
		Port:                       aws.Int64(m.Port),
		Protocol:                   aws.String(m.Protocol),
		TargetType:                 aws.String(m.TargetType),
		HealthCheckEnabled:         aws.Bool(m.HealthCheckEnabled),
		HealthCheckIntervalSeconds: aws.Int64(m.HealthCheckIntervalSeconds),
		HealthCheckPath:            aws.String(m.HealthCheckPath),
		HealthCheckProtocol:        aws.String(m.HealthCheckProtocol),
		HealthCheckTimeoutSeconds:  aws.Int64(m.HealthCheckTimeoutSeconds),
		HealthyThresholdCount:      aws.Int64(m.HealthyThresholdCount),
		UnhealthyThresholdCount:    aws.Int64(m.UnhealthyThresholdCount),
	}

	if vpc != nil {
		input.VpcId = aws.String(vpc.VpcId)
	}

	if m.Matcher != "" {
		input.Matcher = &elbv2.Matcher{
			HttpCode: aws.String(m.Matcher),
		}
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsAppAutoscalingPolicy defines the details needed to create an application autoscaling policy.
type AwsAppAutoscalingPolicy struct {
	// The name of the scaling policy.
	PolicyName string

	// The policy type. The following policy types are supported:
	// * TargetTrackingScaling
	// * StepScaling—Not
	//
	// For more information, see Step Scaling Policies for Application Auto Scaling
	// (https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-step-scaling-policies.html)
	// and Target Tracking Scaling Policies for Application Auto Scaling (https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html)
	// in the Application Auto Scaling User Guide.
	PolicyType string

	// A step scaling policy. This parameter is required if you are creating a policy and the policy type is StepScaling.
	StepScalingPolicyConfiguration *applicationautoscaling.StepScalingPolicyConfiguration `type:"structure"`

	// A target tracking scaling policy. Includes support for predefined or customized metrics. This parameter is
	// required if you are creating a policy and the policy type is TargetTrackingScaling.
	TargetTrackingScalingPolicyConfiguration *applicationautoscaling.TargetTrackingScalingPolicyConfiguration `type:"structure"`

	// The minimum value to scale to in response to a scale-in event. MinCapacity
	// is required to register a scalable target.
	MinCapacity int64

	// The maximum value to scale to in response to a scale-out event. MaxCapacity
	// is required to register a scalable target.
	MaxCapacity int64

	// Optional to provide additional details to the create input.
	PrePut func(input *applicationautoscaling.PutScalingPolicyInput) error `json:"-"`

	// Optional to provide additional details to the create input.
	PreRegisterTarget func(input *applicationautoscaling.RegisterScalableTargetInput) error `json:"-"`
}

// AwsAppAutoscalingPolicyResult defines information about an application autoscaling policy.
type AwsAppAutoscalingPolicyResult struct {
	// The name of the policy.
	PolicyName string

	// The policy type.
	PolicyType string

	// The Amazon Resource Name (ARN) of the policy.
	PolicyARN string

	// The md5 hash of the input used to create the Policy.
	InputHash string
}

// Input returns the AWS input for applicationautoscaling.PutScalingPolicy.
func (m *AwsAppAutoscalingPolicy) PutInput() (*applicationautoscaling.PutScalingPolicyInput, error) {

	input := &applicationautoscaling.PutScalingPolicyInput{
		PolicyName:                               aws.String(m.PolicyName),
		PolicyType:                               aws.String(m.PolicyType),
		StepScalingPolicyConfiguration:           m.StepScalingPolicyConfiguration,
		TargetTrackingScalingPolicyConfiguration: m.TargetTrackingScalingPolicyConfiguration,
	}

	if m.PrePut != nil {
		if err := m.PrePut(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// Input returns the AWS input for applicationautoscaling.PutScalingPolicy.
func (m *AwsAppAutoscalingPolicy) RegisterTargetInput() (*applicationautoscaling.RegisterScalableTargetInput, error) {

	input := &applicationautoscaling.RegisterScalableTargetInput{
		MinCapacity: aws.Int64(m.MinCapacity),
		MaxCapacity: aws.Int64(m.MaxCapacity),
	}

	if m.PreRegisterTarget != nil {
		if err := m.PreRegisterTarget(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsRoute53ZoneResult defines information about a hosted zone derived from *route53.HostedZone.
type AwsRoute53ZoneResult struct {
	// The ID that Amazon Route 53 assigned to the hosted zone when you created it.
	ZoneId string

	// The name of the domain. For public hosted zones, this is the name that you
	// have registered with your DNS registrar.
	Name string

	// List of subdomains for the zone.
	Entries []string

	// List of associated domains.
	AssocDomains []string
}

// AwsSdPrivateDnsNamespace defines the details needed to create a service discovery private namespace.
type AwsSdPrivateDnsNamespace struct {
	// The name that you want to assign to this namespace. When you create a private
	// DNS namespace, AWS Cloud Map automatically creates an Amazon Route 53 private
	// hosted zone that has the same name as the namespace.
	//
	// Name is a required field
	Name string

	// A description for the namespace.
	Description string

	// Optional to provide additional details to the create input.
	PreCreate func(input *servicediscovery.CreatePrivateDnsNamespaceInput) error `json:"-"`

	// The set of services for the dns namespace.
	Service *AwsSdService
}

// AwsSdPrivateDnsNamespaceResult  defines information about a namespace derived from *servicediscovery.NamespaceSummary.
type AwsSdPrivateDnsNamespaceResult struct {
	// The ID of a namespace.
	Id string

	// The name of the namespace, such as example.com.
	Name string

	// The Amazon Resource Name (ARN) that AWS Cloud Map assigns to the namespace
	// when you create it.
	Arn string

	// The type of the namespace. Valid values are DNS_PUBLIC and DNS_PRIVATE.
	Type string

	// List of services associated with the namespace.
	Services map[string]*AwsSdServiceResult

	// The md5 hash of the input used to create the TargetGroup.
	InputHash string
}

// Input returns the AWS input for servicediscovery.CreatePrivateDnsNamespace.
func (m *AwsSdPrivateDnsNamespace) Input(vpc *AwsEc2VpcResult) (*servicediscovery.CreatePrivateDnsNamespaceInput, error) {

	input := &servicediscovery.CreatePrivateDnsNamespaceInput{
		Name:             aws.String(m.Name),
		Description:      aws.String(m.Description),
		CreatorRequestId: aws.String("devops-deploy"),
	}

	if vpc != nil {
		input.Vpc = aws.String(vpc.VpcId)
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsSdService defines the details needed to create a service for a namespace.
type AwsSdService struct {
	// The name that you want to assign to the service.
	//
	// Name is a required field
	Name string `required:"true"`

	// A description for the service.
	Description string

	// The amount of time, in seconds, that you want DNS resolvers to cache the
	// settings for this record.
	//
	// Alias records don't include a TTL because Route 53 uses the TTL for the AWS
	// resource that an alias record routes traffic to. If you include the AWS_ALIAS_DNS_NAME
	// attribute when you submit a RegisterInstance request, the TTL value is ignored.
	// Always specify a TTL for the service; you can use a service to register instances
	// that create either alias or non-alias records.
	//
	DnsRecordTTL int64 `required:"true"`

	// The number of 30-second intervals that you want Cloud Map to wait after receiving
	// an UpdateInstanceCustomHealthStatus request before it changes the health
	// status of a service instance. For example, suppose you specify a value of
	// 2 for FailureTheshold, and then your application sends an UpdateInstanceCustomHealthStatus
	// request. Cloud Map waits for approximately 60 seconds (2 x 30) before changing
	// the status of the service instance based on that request.
	//
	// Sending a second or subsequent UpdateInstanceCustomHealthStatus request with
	// the same value before FailureThreshold x 30 seconds has passed doesn't accelerate
	// the change. Cloud Map still waits FailureThreshold x 30 seconds after the
	// first request to make the change.
	HealthCheckFailureThreshold int64

	// Optional to provide additional details to the create input.
	PreCreate func(input *servicediscovery.CreateServiceInput) error `json:"-"`
}

// AwsSdServiceResult defines information about a service derived from *servicediscovery.Service.
type AwsSdServiceResult struct {
	// The ID that AWS Cloud Map assigned to the service when you created it.
	Id string

	// The name of the service.
	Name string

	// The Amazon Resource Name (ARN) that AWS Cloud Map assigns to the service
	// when you create it.
	Arn string

	// The ID of the namespace that was used to create the service.
	NamespaceId string

	// The md5 hash of the input used to create the TargetGroup.
	InputHash string
}

// Input returns the AWS input for servicediscovery.CreateService.
func (m *AwsSdService) Input(namespace *AwsSdPrivateDnsNamespaceResult) (*servicediscovery.CreateServiceInput, error) {

	input := &servicediscovery.CreateServiceInput{
		Name:        aws.String(m.Name),
		Description: aws.String(m.Description),
		DnsConfig: &servicediscovery.DnsConfig{
			DnsRecords: []*servicediscovery.DnsRecord{
				{
					TTL:  aws.Int64(m.DnsRecordTTL),
					Type: aws.String("A"),
				},
			},
		},
		HealthCheckCustomConfig: &servicediscovery.HealthCheckCustomConfig{
			FailureThreshold: aws.Int64(m.HealthCheckFailureThreshold),
		},
		CreatorRequestId: aws.String("devops-deploy"),
	}

	if namespace != nil {
		input.NamespaceId = aws.String(namespace.Id)
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsLambdaFunction defines the details needed to create an lambda function.
type AwsLambdaFunction struct {

	// The name of the Lambda function.
	//
	// The length constraint applies only to the full ARN. If you specify only the
	// function name, it is limited to 64 characters in length.
	FunctionName string `required:"true"`

	// A description of the function.
	Description string

	// The name of the method within your code that Lambda calls to execute your
	// function. The format includes the file name. It can also include namespaces
	// and other qualifiers, depending on the runtime. For more information, see
	// Programming Model (https://docs.aws.amazon.com/lambda/latest/dg/programming-model-v2.html).
	Handler string `required:"true"`

	// The amount of memory that your function has access to. Increasing the function's
	// memory also increases its CPU allocation. The default value is 128 MB. The
	// value must be a multiple of 64 MB.
	MemorySize int64

	// The Amazon Resource Name (ARN) of the function's execution role.
	Role string `required:"true"`

	// The identifier of the function's runtime (https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html).
	Runtime string `required:"true"`

	// The amount of time that Lambda allows a function to run before stopping it.
	// The default is 3 seconds. The maximum allowed value is 900 seconds.
	Timeout *int64

	// Environment variables that are accessible from function code during execution.
	Environment map[string]string `sensitive:"true"`

	// The metadata that you apply to the service to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. When a service is deleted, the tags are deleted as well. Tag keys
	// can have a maximum character length of 128 characters, and tag values can
	// have a maximum length of 256 characters.
	Tags []Tag

	// Optional to provide additional details to the create input.
	PreCreate func(input *lambda.CreateFunctionInput) error `json:"-"`

	// Optional to provide additional details to the update code input.
	PreUpdateCode func(input *lambda.UpdateFunctionCodeInput) error `json:"-"`

	// Optional to provide additional details to the update configuration input.
	PreUpdateConfiguration func(input *lambda.UpdateFunctionConfigurationInput, existing *lambda.FunctionConfiguration) error `json:"-"`

	// Optional to update the Environment before create function or updateConfiguration is executed.
	UpdateEnvironment func(vars map[string]string) error `json:"-"`

	// Optional to defined a Cloudwatch Event rule that will trigger this lambda.
	AwsCloudwatchEventRule *AwsCloudwatchEventRule
}

// CreateInput returns the AWS input for lambda.CreateFunction.
func (m *AwsLambdaFunction) CreateInput(codeS3Bucket, codeS3Key string, vpc *AwsEc2VpcResult, securityGroup *AwsEc2SecurityGroupResult) (*lambda.CreateFunctionInput, error) {

	input := &lambda.CreateFunctionInput{
		FunctionName: aws.String(m.FunctionName),
		Description:  aws.String(m.Description),
		Handler:      aws.String(m.Handler),
		MemorySize:   aws.Int64(m.MemorySize),
		Role:         aws.String(m.Role),
		Runtime:      aws.String(m.Runtime),
		Timeout:      m.Timeout,
		Code: &lambda.FunctionCode{
			S3Bucket: aws.String(codeS3Bucket),
			S3Key:    aws.String(codeS3Key),
		},
	}

	if m.UpdateEnvironment != nil {
		if m.Environment == nil {
			m.Environment = make(map[string]string)
		}
		if err := m.UpdateEnvironment(m.Environment); err != nil {
			return nil, err
		}
	}

	if len(m.Environment) > 0 {
		input.Environment = &lambda.Environment{
			Variables: make(map[string]*string),
		}
		for k, v := range m.Environment {
			input.Environment.Variables[k] = aws.String(v)
		}
	}

	if vpc != nil {
		input.VpcConfig = &lambda.VpcConfig{
			SubnetIds: aws.StringSlice(vpc.SubnetIds),
		}

		if securityGroup != nil {
			input.VpcConfig.SecurityGroupIds = aws.StringSlice([]string{
				securityGroup.GroupId,
			})
		}
	}

	input.Tags = make(map[string]*string)
	for _, t := range m.Tags {
		input.Tags[t.Key] = aws.String(t.Value)
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// UpdateCodeInput returns the AWS input for lambda.UpdateFunctionCodeInput.
func (m *AwsLambdaFunction) UpdateCodeInput(codeS3Bucket, codeS3Key string) (*lambda.UpdateFunctionCodeInput, error) {

	input := &lambda.UpdateFunctionCodeInput{
		FunctionName: aws.String(m.FunctionName),
		Publish:      aws.Bool(true),
		S3Bucket:     aws.String(codeS3Bucket),
		S3Key:        aws.String(codeS3Key),
	}

	if m.PreUpdateCode != nil {
		if err := m.PreUpdateCode(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// UpdateConfigurationInput returns the AWS input for lambda.UpdateFunctionConfigurationInput.
func (m *AwsLambdaFunction) UpdateConfigurationInput(vpc *AwsEc2VpcResult, securityGroup *AwsEc2SecurityGroupResult, existingConfig *lambda.FunctionConfiguration) (*lambda.UpdateFunctionConfigurationInput, error) {

	input := &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(m.FunctionName),
		Description:  aws.String(m.Description),
		Handler:      aws.String(m.Handler),
		MemorySize:   aws.Int64(m.MemorySize),
		Role:         aws.String(m.Role),
		Runtime:      aws.String(m.Runtime),
		Timeout:      m.Timeout,
	}

	if m.UpdateEnvironment != nil {
		if m.Environment == nil {
			m.Environment = make(map[string]string)
		}
		if err := m.UpdateEnvironment(m.Environment); err != nil {
			return nil, err
		}
	}

	if len(m.Environment) > 0 {
		input.Environment = &lambda.Environment{
			Variables: make(map[string]*string),
		}
		for k, v := range m.Environment {
			input.Environment.Variables[k] = aws.String(v)
		}
	}

	if vpc != nil {
		input.VpcConfig = &lambda.VpcConfig{
			SubnetIds: aws.StringSlice(vpc.SubnetIds),
		}

		if securityGroup != nil {
			input.VpcConfig.SecurityGroupIds = aws.StringSlice([]string{
				securityGroup.GroupId,
			})
		}
	}

	if m.PreUpdateConfiguration != nil {
		if err := m.PreUpdateConfiguration(input, existingConfig); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsCloudwatchEventRule defines the details needed to create a Cloudwatch Event rule.
type AwsCloudwatchEventRule struct {
	// The name of the rule that you're creating or updating.
	Name string

	// A description of the rule.
	Description string

	// The event bus to associate with this rule. If you omit this, the default
	// event bus is used.
	EventBusName *string

	// The event pattern. For more information, see Event Patterns (https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html)
	// in the Amazon EventBridge User Guide.
	EventPattern string

	// The Amazon Resource Name (ARN) of the IAM role associated with the rule.
	RoleArn *string

	// Or define a new role that will be associated with the rule.
	IamRole *AwsIamRole

	// The scheduling expression: for example, "cron(0 20 * * ? *)" or "rate(5 minutes)".
	ScheduleExpression string

	// The list of key-value pairs to associate with the rule.
	Tags []Tag `type:"list"`

	// List of targets to associated with the rule.
	Targets []*AwsCloudwatchEventTarget

	// Optional to provide additional details to the create input.
	PrePut func(input *cloudwatchevents.PutRuleInput, existing *cloudwatchevents.Rule) error `json:"-"`
}

// Input returns the AWS input for cloudwatchevents.PutRule.
func (m *AwsCloudwatchEventRule) Input(existingRule *cloudwatchevents.Rule) (*cloudwatchevents.PutRuleInput, error) {

	input := &cloudwatchevents.PutRuleInput{
		Name:         aws.String(m.Name),
		Description:  aws.String(m.Description),
		EventBusName: m.EventBusName,
		EventPattern: aws.String(m.EventPattern),
		State:        aws.String("enabled"),
		RoleArn:      m.RoleArn,
	}

	if m.ScheduleExpression != "" {
		input.ScheduleExpression = aws.String(m.ScheduleExpression)
	}

	input.Tags = []*cloudwatchevents.Tag{}
	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &cloudwatchevents.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	if m.PrePut != nil {
		if err := m.PrePut(input, existingRule); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsCloudwatchEventRuleResult defines information about a service derived from *cloudwatchevents.PutRuleOutput.
type AwsCloudwatchEventRuleResult struct {
	// The name of the service.
	Name string

	// The Amazon Resource Name (ARN) of the rul
	Arn string

	// The event bus to associate with this rule. If you omit this, the default
	// event bus is used.
	EventBusName *string

	// List of targets to associated with the rule.
	Targets map[string]*AwsCloudwatchEventTargetResult

	// The md5 hash of the input used to create the TargetGroup.
	InputHash string
}

// GetTarget returns *AwsCloudwatchEventTargetResult by id.
func (res *AwsCloudwatchEventRuleResult) GetTarget(targetId string) (*AwsCloudwatchEventTargetResult, error) {
	var (
		result *AwsCloudwatchEventTargetResult
		ok     bool
	)
	if res.Targets != nil {
		result, ok = res.Targets[targetId]
	}
	if !ok {
		return nil, errors.Errorf("No target configured for '%s'", targetId)
	}
	return result, nil
}

// AwsCloudwatchEventTarget defines the details needed to create a Cloudwatch Event target.
type AwsCloudwatchEventTarget struct {

	// The Amazon Resource Name (ARN) of the target.
	Arn string

	// The ID of the target.
	Id string

	// The Amazon Resource Name (ARN) of the IAM role to be used for this target
	// when the rule is triggered. If one rule triggers multiple targets, you can
	// use a different IAM role for each target.
	RoleArn *string

	// Or define a new role that will be associated with the rule.
	IamRole *AwsIamRole

	// Optional to provide additional details to the create input.
	PrePut func(rule *AwsCloudwatchEventRuleResult, target *cloudwatchevents.Target, existing *cloudwatchevents.Target) error `json:"-"`
}

// Target returns the AWS target for cloudwatchevents.PutTargets.
func (m *AwsCloudwatchEventTarget) Target(rule *AwsCloudwatchEventRuleResult, existingTarget *cloudwatchevents.Target) (*cloudwatchevents.Target, error) {

	input := existingTarget

	if input == nil {
		input = &cloudwatchevents.Target{
			RoleArn: m.RoleArn,
		}
	}
	input.Arn = aws.String(m.Arn)
	input.Id = aws.String(m.Id)

	if m.PrePut != nil {
		if rule == nil {
			rule = &AwsCloudwatchEventRuleResult{}
		}
		if err := m.PrePut(rule, input, existingTarget); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsCloudwatchEventRuleResult defines information about a service derived from *cloudwatchevents.PutRuleOutput.
type AwsCloudwatchEventTargetResult struct {
	// The Amazon Resource Name (ARN) of the target.
	Arn string

	// The ID of the target.
	Id string

	// The md5 hash of the input used to create the TargetGroup.
	InputHash string
}

// AwsSQSQueue defines the details needed to create an SQS Queue that includes additional configuration.
type AwsSQSQueue struct {
	// Name is a required field
	Name string

	// QueueName is a required field
	QueueName string

	//    * DelaySeconds - The length of time, in seconds, for which the delivery
	//    of all messages in the queue is delayed. Valid values: An integer from
	//    0 to 900 (15 minutes). Default: 0.
	DelaySeconds int

	//    * MaximumMessageSize - The limit of how many bytes a message can contain
	//    before Amazon SQS rejects it. Valid values: An integer from 1,024 bytes
	//    (1 KiB) up to 262,144 bytes (256 KiB). Default: 262,144 (256 KiB).
	MaximumMessageSize int

	//    * MessageRetentionPeriod - The length of time, in seconds, for which Amazon
	//    SQS retains a message. Valid values: An integer representing seconds,
	//    from 60 (1 minute) to 1,209,600 (14 days). Default: 345,600 (4 days).
	MessageRetentionPeriod int

	//    * ReceiveMessageWaitTimeSeconds - The length of time, in seconds, for
	//    which a ReceiveMessage action waits for a message to arrive. Valid values:
	//    an integer from 0 to 20 (seconds). Default: 0.
	ReceiveMessageWaitTimeSeconds int

	//    * Policy - The queue's policy. A valid AWS policy. For more information
	//    about policy structure, see Overview of AWS IAM Policies (https://docs.aws.amazon.com/IAM/latest/UserGuide/PoliciesOverview.html)
	//    in the Amazon IAM User Guide.
	Policy string

	//    * RedrivePolicy - The string that includes the parameters for the dead-letter
	//    queue functionality of the source queue. For more information about the
	//    redrive policy and dead-letter queues, see Using Amazon SQS Dead-Letter
	//    Queues (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)
	//    in the Amazon Simple Queue Service Developer Guide. deadLetterTargetArn
	//    - The Amazon Resource Name (ARN) of the dead-letter queue to which Amazon
	//    SQS moves messages after the value of maxReceiveCount is exceeded. maxReceiveCount
	//    - The number of times a message is delivered to the source queue before
	//    being moved to the dead-letter queue. When the ReceiveCount for a message
	//    exceeds the maxReceiveCount for a queue, Amazon SQS moves the message
	//    to the dead-letter-queue. The dead-letter queue of a FIFO queue must also
	//    be a FIFO queue. Similarly, the dead-letter queue of a standard queue
	//    must also be a standard queue.
	RedrivePolicy string

	//    * VisibilityTimeout - The visibility timeout for the queue, in seconds.
	//    Valid values: an integer from 0 to 43,200 (12 hours). Default: 30. For
	//    more information about the visibility timeout, see Visibility Timeout
	//    (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html)
	//    in the Amazon Simple Queue Service Developer Guide.
	VisibilityTimeout int

	// Optional to provide additional details to the create input.
	PreCreate func(input *sqs.CreateQueueInput) error `json:"-"`
}

// Input returns the AWS input for sqs.CreateQueue.
func (m *AwsSQSQueue) Input() (*sqs.CreateQueueInput, error) {

	input := &sqs.CreateQueueInput{
		QueueName:  aws.String(m.QueueName),
		Attributes: make(map[string]*string),
	}
	if m.DelaySeconds > 0 {
		input.Attributes["DelaySeconds"] = aws.String(strconv.Itoa(m.DelaySeconds))
	}
	if m.MaximumMessageSize > 0 {
		input.Attributes["MaximumMessageSize"] = aws.String(strconv.Itoa(m.MaximumMessageSize))
	}
	if m.MessageRetentionPeriod > 0 {
		input.Attributes["MessageRetentionPeriod"] = aws.String(strconv.Itoa(m.MessageRetentionPeriod))
	}
	if m.ReceiveMessageWaitTimeSeconds > 0 {
		input.Attributes["ReceiveMessageWaitTimeSeconds"] = aws.String(strconv.Itoa(m.ReceiveMessageWaitTimeSeconds))
	}
	if m.VisibilityTimeout > 0 {
		input.Attributes["VisibilityTimeout"] = aws.String(strconv.Itoa(m.VisibilityTimeout))
	}
	if m.Policy != "" {
		input.Attributes["Policy"] = aws.String(m.Policy)
	}
	if m.RedrivePolicy != "" {
		input.Attributes["RedrivePolicy"] = aws.String(m.RedrivePolicy)
	}

	if m.PreCreate != nil {
		if err := m.PreCreate(input); err != nil {
			return input, err
		}
	}

	return input, nil
}

// AwsSQSQueueResult defines information about a service derived from *sqs.CreateQueueOutput.
type AwsSQSQueueResult struct {
	// The Name.
	Name string

	// The Name of the queue.
	QueueName string

	// The URL of the created Amazon SQS queue.
	QueueUrl string

	// The md5 hash of the input used to create the TargetGroup.
	InputHash string
}
