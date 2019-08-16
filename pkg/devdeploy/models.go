package devdeploy

import (
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/s3"
)

// ModuleDetails defines information about the project determined from the go.mod file.
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

	// AwsCredentials defines the credentials used for deployment.
	AwsCredentials AwsCredentials `validate:"required,dive,required"`

	// AwsEcrRepository defines the name of the ECR repository and details needed to create if does not exist.
	AwsEcrRepository  *AwsEcrRepository

	// AwsEc2Vpc defines the name of the VPC and details needed to create if does not exist.
	AwsEc2Vpc *AwsEc2Vpc

	// AwsEc2SecurityGroup defines the name of the EC2 security group and details needed to create if does not exist.
	AwsEc2SecurityGroup      *AwsEc2SecurityGroup

	// GitlabRunnerEc2SecurityGroupName defines the name of the security group that was used to deploy the GitLab
	// Runners on AWS. This will allow the deploy script to ensure the GitLab Runners have access to community to through
	// the deployment EC2 Security Group.
	GitlabRunnerEc2SecurityGroupName string `validate:"required"`

	// AwsS3Buckets is the list of S3 buckets for the project.
	AwsS3Buckets               []*AwsS3Bucket

	// AwsS3BucketPublicName sets the S3 bucket name used to host static files for all services.
	AwsS3BucketPublicName      string `validate:"omitempty"`

	// AwsS3BucketPublicKeyPrefix defines the base S3 key prefix used to upload static files.
	AwsS3BucketPublicKeyPrefix string `validate:"omitempty"`

	// AwsElasticCacheCluster defines the name of the cache cluster and the details needed to create if does not exist.
	AwsElasticCacheCluster *AwsElasticCacheCluster

	// AwsRdsDBCluster defines the name of the rds cluster and the details needed to create if does not exist.
	// This is only needed for Aurora storage engine.
	AwsRdsDBCluster *AwsRdsDBCluster

	// AwsRdsDBInstance defines the name of the rds database instance and the detailed needed to create doesn't exist.
	AwsRdsDBInstance *AwsRdsDBInstance
}

// Tag describes a key/value pair that will help identify a resource.
type Tag struct {
	// One part of a key-value pair that make up a tag. A key is a general label
	// that acts like a category for more specific tag values.
	Key string `type:"string"`

	// The optional part of a key-value pair that make up a tag. A value acts as
	// a descriptor within a tag category (key).
	Value string `type:"string"`
	// contains filtered or unexported fields
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
	RepositoryName string `min:"2" type:"string" required:"true"`

	// The tag mutability setting for the repository. If this parameter is omitted,
	// the default setting of MUTABLE will be used which will allow image tags to
	// be overwritten. If IMMUTABLE is specified, all image tags within the repository
	// will be immutable which will prevent them from being overwritten.
	ImageTagMutability *string `type:"string" enum:"ImageTagMutability"`

	// The metadata that you apply to the repository to help you categorize and
	// organize them. Each tag consists of a key and an optional value, both of
	// which you define. Tag keys can have a maximum character length of 128 characters,
	// and tag values can have a maximum length of 256 characters.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecr.CreateRepositoryInput) error

	// result is an unexported field that contains Repository details.
	result *ecr.Repository
}

// AwsEc2Vpc describes an AWS EC2 VPC.
// @TODO: Apply tagging resource on create.
type AwsEc2Vpc struct {
	// The ID of the VPC. This is optional when IsDefault is set to true which will find the default VPC.
	VpcId string `type:"string"`

	// Indicates whether the VPC is the default VPC.
	IsDefault bool `type:"boolean"`

	// The IPv4 network range for the VPC, in CIDR notation. For example, 10.0.0.0/16.
	// CidrBlock is a required field for creating a custom VPC when IsDefault is false and VpcId is empty.
	CidrBlock string `required:"true"`

	// Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for
	// the VPC. You cannot specify the range of IP addresses, or the size of the CIDR block.
	// This is only optional for creating a custom VPC when IsDefault is false and VpcId is empty.
	AmazonProvidedIpv6CidrBlock *bool `type:"boolean"`

	// The set of subnets used for creating a custom VPC.
	Subnets []AwsEc2Subnet

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateVpcInput) error

	// result is an unexported field that contains VPC details.
	result *ec2.Vpc
	subnetIds []string
}

// AwsEc2Subnet describes the detailed needed for creating a subnet for a VPC when not using the default region VPC.
// @TODO: Apply tagging resource on create.
type AwsEc2Subnet struct {
	// The IPv4 network range for the subnet, in CIDR notation. For example, 10.0.0.0/24.
	// CidrBlock is a required field
	CidrBlock *string `type:"string" required:"true"`

	// The Availability Zone for the subnet.
	// Default: AWS selects one for you. If you create more than one subnet in your
	// VPC, we may not necessarily select a different zone for each subnet.
	AvailabilityZone *string `type:"string"`

	// The AZ ID of the subnet.
	AvailabilityZoneId *string `type:"string"`

	// The IPv6 network range for the subnet, in CIDR notation. The subnet size
	// must use a /64 prefix length.
	Ipv6CidrBlock *string `type:"string"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateSubnetInput) error
}

// AwsEc2SecurityGroup describes an AWS ECS security group. This will use the VPC ID defined for the deployment when
// creating a new security group.
// @TODO: Apply tagging resource on create.
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
	Description string `type:"string" required:"true"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateSecurityGroupInput) error

	// result is an unexported field that contains security group details.
	result *ec2.SecurityGroup
}

// AwsS3Bucket defines the details needed to create a bucket that includes additional configuration.
type AwsS3Bucket struct {
	// BucketName is a required field
	BucketName              string `validate:"omitempty"`

	// TempPrefix used by services for short term storage. If not empty, a lifecycle policy must be applied for the prefix.
	TempPrefix string

	// IsPublic defined if the S3 Bucket should allow public access. If false, then PublicAccessBlock is required.
	IsPublic bool

	// Specifies the region where the bucket will be created. If you don't specify
	// a region, the bucket is created in US East (N. Virginia) Region (us-east-1).
	LocationConstraint *string `type:"string" enum:"BucketLocationConstraint"`

	// A set of lifecycle rules for individual objects in an Amazon S3 bucket.
	LifecycleRules    []*s3.LifecycleRule

	// A set of allowed origins and methods.
	CORSRules         []*s3.CORSRule

	// The PublicAccessBlock configuration currently in effect for this Amazon S3 bucket.
	PublicAccessBlock *s3.PublicAccessBlockConfiguration

	// The bucket policy as a JSON document.
	Policy            string

	// Optional to provide additional details to the create input.
	PreCreate func(input *s3.CreateBucketInput) error

	CloudFront *AwsS3BucketCloudFront
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
	PreCreate func(input *cloudfront.CreateDistributionInput) error
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
	CacheClusterId string `type:"string" required:"true"`

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
	CacheNodeType string `type:"string"`

	// The initial number of cache nodes that the cluster has.
	//
	// For clusters running Redis, this value must be 1. For clusters running Memcached,
	// this value must be between 1 and 20.
	NumCacheNodes int64 `type:"integer"`

	// The name of the parameter group to associate with this cluster. If this argument
	// is omitted, the default parameter group for the specified engine is used.
	// You cannot use any parameter group which has cluster-enabled='yes' when creating
	// a cluster.
	CacheParameterGroupName string `type:"string"`

	// The name of the subnet group to be used for the cluster.
	CacheSubnetGroupName string `type:"string"`

	// The name of the cache engine to be used for this cluster.
	//
	// Valid values for this parameter are: memcached | redis
	Engine string `type:"string"`

	// The version number of the cache engine to be used for this cluster. To view
	// the supported cache engine versions, use the DescribeCacheEngineVersions
	// operation.
	EngineVersion string `type:"string"`

	// The port number on which each of the cache nodes accepts connections.
	Port int64 `type:"integer"`

	// This parameter is currently disabled.
	AutoMinorVersionUpgrade *bool `type:"boolean"`

	// One or more VPC security groups associated with the cluster.
	//
	// Use this parameter only when you are creating a cluster in an Amazon Virtual
	// Private Cloud (Amazon VPC).
	SecurityGroupIds []*string `type:"list"`

	// The number of days for which ElastiCache retains automatic snapshots before
	// deleting them. For example, if you set SnapshotRetentionLimit to 5, a snapshot
	// taken today is retained for 5 days before being deleted.
	//
	// This parameter is only valid if the Engine parameter is redis.
	//
	// Default: 0 (i.e., automatic backups are disabled for this cache cluster).
	SnapshotRetentionLimit *int64 `type:"integer"`

	// A list of cost allocation tags to be added to this resource.
	Tags []*Tag `type:"list"`

	// An array of parameter names and values for the parameter update. You must
	// supply at least one parameter name and value; subsequent arguments are optional.
	// A maximum of 20 parameters may be modified per request.
	ParameterNameValues []AwsElasticCacheParameter `type:"list" required:"true"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *elasticache.CreateCacheClusterInput) error

	// contains filtered or unexported fields
	result *elasticache.CacheCluster
}

// AwsElasticCacheParameter describes a name-value pair that is used to update the value of a parameter.
type AwsElasticCacheParameter struct {
	// The name of the parameter.
	ParameterName string `type:"string"`

	// The value of the parameter.
	ParameterValue string `type:"string"`
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
	DBClusterIdentifier string `type:"string" required:"true"`

	// The name for your database of up to 64 alpha-numeric characters.
	DatabaseName string `type:"string"`

	// The name of the database engine to be used for this DB cluster.
	//
	// Valid Values: aurora (for MySQL 5.6-compatible Aurora), aurora-mysql (for
	// MySQL 5.7-compatible Aurora), and aurora-postgresql
	//
	// Engine is a required field
	Engine string `type:"string" required:"true"`

	// The DB engine mode of the DB cluster, either provisioned, serverless, parallelquery,
	// or global.
	EngineMode string `type:"string"`

	// The port number on which the instances in the DB cluster accept connections.
	//
	// Default: 3306 if engine is set as aurora or 5432 if set to aurora-postgresql.
	Port int64 `type:"integer"`

	// The name of the master user for the DB cluster.
	//
	// Constraints:
	//    * Must be 1 to 16 letters or numbers.
	//    * First character must be a letter.
	//    * Can't be a reserved word for the chosen database engine.
	MasterUsername string `type:"string"`

	// The number of days for which automated backups are retained.
	//
	// Default: 1
	//
	// Constraints:
	//
	//    * Must be a value from 1 to 35
	BackupRetentionPeriod *int64 `type:"integer"`

	// A value that indicates that the DB cluster should be associated with the
	// specified CharacterSet.
	CharacterSetName *string `type:"string"`

	// A value that indicates whether to copy all tags from the DB cluster to snapshots
	// of the DB cluster. The default is not to copy them.
	CopyTagsToSnapshot *bool `type:"boolean"`

	// Tags to assign to the DB cluster.
	Tags []*Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *rds.CreateDBClusterInput) error

	// contains filtered or unexported fields
	result *rds.DBCluster
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
	DBInstanceIdentifier string `type:"string" required:"true"`

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
	DBName string `type:"string"`

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
	Engine string `type:"string" required:"true"`

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
	MasterUsername string `type:"string"`

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
	Port int64 `type:"integer"`

	// The compute and memory capacity of the DB instance, for example, db.m4.large.
	// Not all DB instance classes are available in all AWS Regions, or for all
	// database engines. For the full list of DB instance classes, and availability
	// for your engine, see DB Instance Class (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.html)
	// in the Amazon RDS User Guide.
	//
	// DBInstanceClass is a required field
	DBInstanceClass string `type:"string" required:"true"`

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
	AllocatedStorage int64 `type:"integer"`

	// A value that indicates whether the DB instance is publicly accessible. When
	// the DB instance is publicly accessible, it is an Internet-facing instance
	// with a publicly resolvable DNS name, which resolves to a public IP address.
	// When the DB instance is not publicly accessible, it is an internal instance
	// with a DNS name that resolves to a private IP address.
	PubliclyAccessible bool `type:"boolean"`

	// A value that indicates whether minor engine upgrades are applied automatically
	// to the DB instance during the maintenance window. By default, minor engine
	// upgrades are applied automatically.
	AutoMinorVersionUpgrade bool `type:"boolean"`

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
	BackupRetentionPeriod *int64 `type:"integer"`

	// For supported engines, indicates that the DB instance should be associated
	// with the specified CharacterSet.
	//
	// Amazon Aurora
	// 	Not applicable. The character set is managed by the DB cluster. For more
	// 	information, see CreateDBCluster.
	CharacterSetName string `type:"string"`

	// A value that indicates whether to copy tags from the DB instance to snapshots
	// of the DB instance. By default, tags are not copied.
	//
	// Amazon Aurora
	// 	Not applicable. Copying tags to snapshots is managed by the DB cluster. Setting
	// 	this value for an Aurora DB instance has no effect on the DB cluster setting.
	CopyTagsToSnapshot *bool `type:"boolean"`

	// Tags to assign to the DB instance.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *rds.CreateDBInstanceInput) error

	// contains filtered or unexported fields
	result *rds.DBInstance
}

// DeployService .......
type DeployService struct {
	DeploymentEnv  *DeploymentEnv `validate:"required,dive,required"`

	ServiceName string `validate:"required" example:"web-api"`

	EnableHTTPS        bool     `validate:"omitempty"`
	ServiceHostPrimary string   `validate:"omitempty,required_with=EnableHTTPS,fqdn"`
	ServiceHostNames   []string `validate:"omitempty,dive,fqdn"`

	Dockerfile      string `validate:"required" example:"./cmd/web-api/Dockerfile"`

	ReleaseTag  string `validate:"required"`


	StaticFilesS3Prefix string  `validate:"omitempty"`

	// AwsEcsCluster defines the name of the ecs cluster and the detailed needed to create doesn't exist.
	AwsEcsCluster *AwsEcsCluster `validate:"required"`

	// AwsEcsExecutionRole defines the name of the iam execution role for ecs task and the detailed needed to create doesn't exist.
	// This role executes ECS actions such as pulling the image and storing the application logs in cloudwatch.
	AwsEcsExecutionRole *AwsIamRole `validate:"required"`

	// AwsEcsExecutionRole defines the name of the iam task role for ecs task and the detailed needed to create doesn't exist.
	// This role is used by the task itself for calling other AWS services.
	AwsEcsTaskRole *AwsIamRole `validate:"required"`

	// AwsEcsTaskPolicy defines the name of the iam policy that will be attached to the task role.
	AwsEcsTaskPolicy         *AwsIamPolicy `validate:"required"`

	// AwsCloudWatchLogGroup defines the name of the cloudwatch log group that will be used to store logs for the ECS
	// task.
	AwsCloudWatchLogGroup *AwsCloudWatchLogGroup  `validate:"required"`

	// AwsElbLoadBalancer defines if the service should use an elastic load balancer.
	AwsElbLoadBalancer *AwsElbLoadBalancer  `validate:"omitempty"`
}

// AwsEcsCluster defines the details needed to create an ecs cluster.
type AwsEcsCluster struct {
	// The name of your cluster. If you do not specify a name for your cluster,
	// you create a cluster named default. Up to 255 letters (uppercase and lowercase),
	// numbers, and hyphens are allowed.
	ClusterName string `type:"string"`

	// The metadata that you apply to the cluster to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. Tag keys can have a maximum character length of 128 characters, and
	// tag values can have a maximum length of 256 characters.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecs.CreateClusterInput) error

	// contains filtered or unexported fields
	result *ecs.Cluster
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
	RoleName string `min:"1" type:"string" required:"true"`

	// A description of the role.
	Description string `type:"string"`

	// The trust relationship policy document that grants an entity permission to assume the role.
	//
	// AssumeRolePolicyDocument is a required field
	AssumeRolePolicyDocument string `min:"1" type:"string" required:"true"`

	// Set of the specified managed policy to attach to the IAM role.
	AttachRolePolicyArns []string

	// A list of tags that you want to attach to the newly created role. Each tag
	// consists of a key name and an associated value. For more information about
	// tagging, see Tagging IAM Identities (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html)
	// in the IAM User Guide.
	//
	// If any one of the tags is invalid or if you exceed the allowed number of
	// tags per role, then the entire request fails and the role is not created.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *iam.CreateRoleInput) error

	// contains filtered or unexported fields
	result *iam.Role
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
	PolicyName string `min:"1" type:"string" required:"true"`

	// A friendly description of the policy.
	//
	// Typically used to store information about the permissions defined in the
	// policy. For example, "Grants access to production DynamoDB tables."
	//
	// The policy description is immutable. After a value is assigned, it cannot
	// be changed.
	Description string `type:"string"`

	// The policy document that you want to use as the content for the new
	// policy.
	//
	// PolicyDocument is a required field
	PolicyDocument AwsIamPolicyDocument

	// Optional to provide additional details to the create input.
	PreCreate func(input *iam.CreatePolicyInput) error

	// contains filtered or unexported fields
	result *iam.Policy
}

// AwsIamPolicyDocument defines an AWS IAM policy used for defining access for IAM roles, users, and groups.
type AwsIamPolicyDocument struct {
	Version   string              `json:"Version"`
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
	LogGroupName string `min:"1" type:"string" required:"true"`

	// The key-value pairs to use for the tags.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *cloudwatchlogs.CreateLogGroupInput) error
}


// AwsElbLoadBalancer defines the details needed to create an elbv2 load balancer.
type AwsElbLoadBalancer struct {
	// The name of the load balancer.
	//
	// This name must be unique per region per account, can have a maximum of 32
	// characters, must contain only alphanumeric characters or hyphens, must not
	// begin or end with a hyphen, and must not begin with "internal-".
	//
	// Name is a required field
	Name string `type:"string" required:"true"`

	// [Application Load Balancers] The type of IP addresses used by the subnets
	// for your load balancer. The possible values are ipv4 (for IPv4 addresses)
	// and dualstack (for IPv4 and IPv6 addresses). Internal load balancers must
	// use ipv4.
	IpAddressType string `type:"string" enum:"IpAddressType"`

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
	Scheme string `type:"string" enum:"LoadBalancerSchemeEnum"`

	// The type of load balancer. The default is application.
	Type string `type:"string" enum:"LoadBalancerTypeEnum"`

	// The key-value pairs to use for the tags.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *elbv2.CreateLoadBalancerInput) error
}



