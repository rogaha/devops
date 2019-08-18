package devdeploy

import (
	"encoding/json"
	"net/url"

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
	"github.com/pborman/uuid"
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

	// The maximum number of images to maintain for the repository.
	MaxImages int

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecr.CreateRepositoryInput) error `json:"-"`

	// result is an unexported field that contains Repository details.
	result *ecr.Repository
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

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateVpcInput) error `json:"-"`

	// result is an unexported field that contains VPC details.
	result    *ec2.Vpc
	subnetIds []string
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
	CidrBlock string `type:"string" required:"true"`

	// The Availability Zone for the subnet.
	// Default: AWS selects one for you. If you create more than one subnet in your
	// VPC, we may not necessarily select a different zone for each subnet.
	AvailabilityZone *string `type:"string"`

	// The AZ ID of the subnet.
	AvailabilityZoneId *string `type:"string"`

	// The IPv6 network range for the subnet, in CIDR notation. The subnet size
	// must use a /64 prefix length.
	Ipv6CidrBlock *string `type:"string"`

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag `type:"list"`

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
	GroupName string `type:"string" required:"true"`

	// A description for the security group. This is informational only.
	// Constraints: Up to 255 characters in length
	// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
	// Description is a required field
	Description string `type:"string" required:"true"`

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ec2.CreateSecurityGroupInput) error `json:"-"`

	// result is an unexported field that contains security group details.
	result *ec2.SecurityGroup
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
	BucketName string `validate:"omitempty"`

	// TempPrefix used by services for short term storage. If not empty, a lifecycle policy must be applied for the prefix.
	TempPrefix string

	// IsPublic defined if the S3 Bucket should allow public access. If false, then PublicAccessBlock is required.
	IsPublic bool

	// Specifies the region where the bucket will be created. If you don't specify
	// a region, the bucket is created in US East (N. Virginia) Region (us-east-1).
	LocationConstraint *string `type:"string" enum:"BucketLocationConstraint"`

	// A set of lifecycle rules for individual objects in an Amazon S3 bucket.
	LifecycleRules []*s3.LifecycleRule

	// A set of allowed origins and methods.
	CORSRules []*s3.CORSRule

	// The PublicAccessBlock configuration currently in effect for this Amazon S3 bucket.
	PublicAccessBlock *s3.PublicAccessBlockConfiguration

	// The bucket policy as a JSON document.
	Policy string

	// Optional to provide additional details to the create input.
	PreCreate func(input *s3.CreateBucketInput) error `json:"-"`

	CloudFront *AwsS3BucketCloudFront
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

	// The number of days for which ElastiCache retains automatic snapshots before
	// deleting them. For example, if you set SnapshotRetentionLimit to 5, a snapshot
	// taken today is retained for 5 days before being deleted.
	//
	// This parameter is only valid if the Engine parameter is redis.
	//
	// Default: 0 (i.e., automatic backups are disabled for this cache cluster).
	SnapshotRetentionLimit *int64 `type:"integer"`

	// A list of cost allocation tags to be added to this resource.
	Tags []Tag `type:"list"`

	// An array of parameter names and values for the parameter update. You must
	// supply at least one parameter name and value; subsequent arguments are optional.
	// A maximum of 20 parameters may be modified per request.
	ParameterNameValues []AwsElasticCacheParameter `type:"list" required:"true"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *elasticache.CreateCacheClusterInput) error `json:"-"`

	// contains filtered or unexported fields
	result *elasticache.CacheCluster
}

// Input returns the AWS input for elasticache.CreateCacheCluster.
func (m *AwsElasticCacheCluster) Input(securityGroupIds []string) (*elasticache.CreateCacheClusterInput, error) {

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
		SecurityGroupIds:        aws.StringSlice(securityGroupIds),
		SnapshotRetentionLimit:  m.SnapshotRetentionLimit,
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
	ParameterName string `type:"string"`

	// The value of the parameter.
	ParameterValue string `type:"string"`
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

	// The password for the master database user. This password can contain any
	// printable ASCII character except "/", """, or "@".
	//
	// Constraints: Must contain from 8 to 41 characters.
	MasterUserPassword string `type:"string"`

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
	PreCreate func(input *rds.CreateDBClusterInput) error `json:"-"`

	// Optional to provide method to be excecuted after database has been created.
	AfterCreate func(res *rds.DBCluster, info *DBConnInfo) error `json:"-"`

	// contains filtered or unexported fields
	result *rds.DBCluster
}

// Input returns the AWS input for rds.CreateDBCluster.
func (m *AwsRdsDBCluster) Input(securityGroupIds []string) (*rds.CreateDBClusterInput, error) {

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
		VpcSecurityGroupIds:   aws.StringSlice(securityGroupIds),
	}

	// The the password to a random value, it can be manually overwritten with the PreCreate method.
	if input.MasterUserPassword == nil || *input.MasterUserPassword == "" {
		input.MasterUserPassword = aws.String(uuid.NewRandom().String())
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

	// The version number of the database engine to use.
	//
	// For a list of valid engine versions, use the DescribeDBEngineVersions action.
	EngineVersion *string `type:"string"`

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

	// The password for the master database user. This password can contain any
	// printable ASCII character except "/", """, or "@".
	//
	// Constraints: Must contain from 8 to 41 characters.
	MasterUserPassword string `type:"string"`

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
	CharacterSetName *string `type:"string"`

	// A value that indicates whether to copy tags from the DB instance to snapshots
	// of the DB instance. By default, tags are not copied.
	//
	// Amazon Aurora
	// 	Not applicable. Copying tags to snapshots is managed by the DB cluster. Setting
	// 	this value for an Aurora DB instance has no effect on the DB cluster setting.
	CopyTagsToSnapshot *bool `type:"boolean"`

	// The identifier of the DB cluster that the instance will belong to.
	DBClusterIdentifier *string `type:"string"`

	// Tags to assign to the DB instance.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *rds.CreateDBInstanceInput) error `json:"-"`

	// Optional to provide method to be excecuted after database has been created.
	AfterCreate func(res *rds.DBInstance, info *DBConnInfo) error `json:"-"`

	// contains filtered or unexported fields
	result *rds.DBInstance
}

// Input returns the AWS input for rds.CreateDBInstance.
func (m *AwsRdsDBInstance) Input(securityGroupIds []string) (*rds.CreateDBInstanceInput, error) {

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
		VpcSecurityGroupIds:     aws.StringSlice(securityGroupIds),
	}

	// The the password to a random value, it can be manually overwritten with the PreCreate method.
	if input.MasterUserPassword == nil || *input.MasterUserPassword == "" {
		input.MasterUserPassword = aws.String(uuid.NewRandom().String())
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
	ClusterName string `type:"string"`

	// The metadata that you apply to the cluster to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. Tag keys can have a maximum character length of 128 characters, and
	// tag values can have a maximum length of 256 characters.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecs.CreateClusterInput) error `json:"-"`

	// contains filtered or unexported fields
	result *ecs.Cluster
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

// AwsEcsService defines the details needed to create an ecs service.
type AwsEcsService struct {

	// The name of your service. Up to 255 letters (uppercase and lowercase), numbers,
	// and hyphens are allowed. Service names must be unique within a cluster, but
	// you can have similarly named services in multiple clusters within a Region
	// or across multiple Regions.
	//
	// ServiceName is a required field
	ServiceName string `locationName:"serviceName" type:"string" required:"true"`

	// The number of instantiations of the specified task definition to place and
	// keep running on your cluster.
	DesiredCount int64 `type:"integer"`

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
	DeploymentMaximumPercent int64 `type:"integer"`

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
	DeploymentMinimumHealthyPercent int64 `type:"integer"`

	// The period of time, in seconds, that the Amazon ECS service scheduler should
	// ignore unhealthy Elastic Load Balancing target health checks after a task
	// has first started. This is only valid if your service is configured to use
	// a load balancer. If your service's tasks take a while to start and respond
	// to Elastic Load Balancing health checks, you can specify a health check grace
	// period of up to 2,147,483,647 seconds. During that time, the ECS service
	// scheduler ignores health check status. This grace period can prevent the
	// ECS service scheduler from marking tasks as unhealthy and stopping them before
	// they have time to come up.
	HealthCheckGracePeriodSeconds int64 ` type:"integer"`

	// The launch type on which to run your service. For more information, see Amazon
	// ECS Launch Types (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/launch_types.html)
	// in the Amazon Elastic Container Service Developer Guide.
	LaunchType string `type:"string" enum:"LaunchType"`

	// Specifies whether to enable Amazon ECS managed tags for the tasks within
	// the service. For more information, see Tagging Your Amazon ECS Resources
	// (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html)
	// in the Amazon Elastic Container Service Developer Guide.
	EnableECSManagedTags bool `type:"boolean"`

	// The metadata that you apply to the service to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. When a service is deleted, the tags are deleted as well. Tag keys
	// can have a maximum character length of 128 characters, and tag values can
	// have a maximum length of 256 characters.
	Tags []Tag `type:"list"`

	// Force the current service is one exists to be deleted and a fresh service to be created.
	ForceRecreate bool `validate:"omitempty"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *ecs.CreateServiceInput) error `json:"-"`

	// Optional to provide additional details to the update input.
	PreUpdate func(input *ecs.UpdateServiceInput) error `json:"-"`

	// contains filtered or unexported fields
	result *ecs.Service
}

// AwsEcsTaskDefinition defines the details needed to register an ecs task definition.
type AwsEcsTaskDefinition struct {
	// The task definition input defined.
	RegisterInput *ecs.RegisterTaskDefinitionInput `validate:"required"`

	// Optional to update the placeholders before they are replaced in the task definition.
	UpdatePlaceholders func(placeholders map[string]string) error

	// Optional to provide additional details to the register input.

	PreRegister func(input *ecs.RegisterTaskDefinitionInput) error

	// contains filtered or unexported fields
	result *ecs.TaskDefinition
}

// CreateInput returns the AWS input for ecs.CreateService.
func (m *AwsEcsService) CreateInput(clusterName, taskDefinition string, subnetIds, securityGroupIds []string, ecsELBs []*ecs.LoadBalancer, sdService *AwsSdService) (*ecs.CreateServiceInput, error) {

	var (
		assignPublicIp                *string
		healthCheckGracePeriodSeconds *int64
	)
	if len(ecsELBs) > 0 {
		assignPublicIp = aws.String("DISABLED")
		healthCheckGracePeriodSeconds = aws.Int64(m.HealthCheckGracePeriodSeconds)
	} else {
		assignPublicIp = aws.String("ENABLED")
	}

	input := &ecs.CreateServiceInput{
		Cluster:      aws.String(clusterName),
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
				SecurityGroups: aws.StringSlice(securityGroupIds),
				Subnets:        aws.StringSlice(subnetIds),
			},
		},
		EnableECSManagedTags: aws.Bool(m.EnableECSManagedTags),
		TaskDefinition:       aws.String(taskDefinition),
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
			RegistryArn: aws.String(sdService.resultArn),
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
func (m *AwsEcsService) UpdateInput(clusterName, taskDefinition string) (*ecs.UpdateServiceInput, error) {

	input := &ecs.UpdateServiceInput{
		Cluster:        aws.String(clusterName),
		Service:        aws.String(m.ServiceName),
		TaskDefinition: aws.String(taskDefinition),

		// Maintain the current count set on the existing service.
		DesiredCount: m.result.DesiredCount,

		// Maintain the current grace period.
		HealthCheckGracePeriodSeconds: m.result.HealthCheckGracePeriodSeconds,
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
	PreCreate func(input *iam.CreateRoleInput) error `json:"-"`

	// contains filtered or unexported fields
	result *iam.Role
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

// Arn returns the ARN from the found or created IAM role.
func (m *AwsIamRole) Arn() string {
	if m == nil || m.result == nil || m.result.Arn == nil {
		return ""
	}
	return *m.result.Arn
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
	PreCreate func(input *iam.CreatePolicyInput) error `json:"-"`

	// contains filtered or unexported fields
	result *iam.Policy
}

// Arn returns the ARN from the found or created IAM Policy.
func (m *AwsIamPolicy) Arn() string {
	if m == nil || m.result == nil || m.result.Arn == nil {
		return ""
	}
	return *m.result.Arn
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
	LogGroupName string `min:"1" type:"string" required:"true"`

	// The key-value pairs to use for the tags.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *cloudwatchlogs.CreateLogGroupInput) error `json:"-"`
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

	// The number of seconds to wait before removing task from target group.
	EcsTaskDeregistrationDelay int `type:"long"`

	// The key-value pairs to use for the tags.
	Tags []Tag `type:"list"`

	// The set of target groups for an application load balancer.
	TargetGroup *AwsElbTargetGroup `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *elbv2.CreateLoadBalancerInput) error `json:"-"`

	// contains filtered or unexported fields
	result *elbv2.LoadBalancer
}

// Input returns the AWS input for elbv2.CreateLoadBalance.
func (m *AwsElbLoadBalancer) Input(subnetIds, securityGroupIds []string) (*elbv2.CreateLoadBalancerInput, error) {

	input := &elbv2.CreateLoadBalancerInput{
		Name:           aws.String(m.Name),
		IpAddressType:  aws.String(m.IpAddressType),
		Scheme:         aws.String(m.Scheme),
		Type:           aws.String(m.Type),
		Subnets:        aws.StringSlice(subnetIds),
		SecurityGroups: aws.StringSlice(securityGroupIds),
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

// AwsElbTargetGroup defines the details needed to create an elbv2 target group.
type AwsElbTargetGroup struct {
	// The name of the target group.
	//
	// This name must be unique per region per account, can have a maximum of 32
	// characters, must contain only alphanumeric characters or hyphens, and must
	// not begin or end with a hyphen.
	//
	// Name is a required field
	Name string `type:"string" required:"true"`

	// The port on which the targets receive traffic. This port is used unless you
	// specify a port override when registering the target. If the target is a Lambda
	// function, this parameter does not apply.
	Port int64 `min:"1" type:"integer"`

	// The protocol to use for routing traffic to the targets. For Application Load
	// Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers,
	// the supported protocols are TCP, TLS, UDP, or TCP_UDP. A TCP_UDP listener
	// must be associated with a TCP_UDP target group. If the target is a Lambda
	// function, this parameter does not apply.
	Protocol string `type:"string" enum:"ProtocolEnum"`

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
	TargetType string `type:"string" enum:"TargetTypeEnum"`

	// Indicates whether health checks are enabled. If the target type is lambda,
	// health checks are disabled by default but can be enabled. If the target type
	// is instance or ip, health checks are always enabled and cannot be disabled.
	HealthCheckEnabled bool `type:"boolean"`

	// The approximate amount of time, in seconds, between health checks of an individual
	// target. For HTTP and HTTPS health checks, the range is 5–300 seconds. For
	// TCP health checks, the supported values are 10 and 30 seconds. If the target
	// type is instance or ip, the default is 30 seconds. If the target type is
	// lambda, the default is 35 seconds.
	HealthCheckIntervalSeconds int64 `min:"5" type:"integer"`

	// [HTTP/HTTPS health checks] The ping path that is the destination on the targets
	// for health checks. The default is /.
	HealthCheckPath string `min:"1" type:"string"`

	// The protocol the load balancer uses when performing health checks on targets.
	// For Application Load Balancers, the default is HTTP. For Network Load Balancers,
	// the default is TCP. The TCP protocol is supported for health checks only
	// if the protocol of the target group is TCP, TLS, UDP, or TCP_UDP. The TLS,
	// UDP, and TCP_UDP protocols are not supported for health checks.
	HealthCheckProtocol string `type:"string" enum:"ProtocolEnum"`

	// The amount of time, in seconds, during which no response from a target means
	// a failed health check. For target groups with a protocol of HTTP or HTTPS,
	// the default is 5 seconds. For target groups with a protocol of TCP or TLS,
	// this value must be 6 seconds for HTTP health checks and 10 seconds for TCP
	// and HTTPS health checks. If the target type is lambda, the default is 30
	// seconds.
	HealthCheckTimeoutSeconds int64 `min:"2" type:"integer"`

	// The number of consecutive health checks successes required before considering
	// an unhealthy target healthy. For target groups with a protocol of HTTP or
	// HTTPS, the default is 5. For target groups with a protocol of TCP or TLS,
	// the default is 3. If the target type is lambda, the default is 5.
	HealthyThresholdCount int64 `min:"2" type:"integer"`

	// The number of consecutive health check failures required before considering
	// a target unhealthy. For target groups with a protocol of HTTP or HTTPS, the
	// default is 2. For target groups with a protocol of TCP or TLS, this value
	// must be the same as the healthy threshold count. If the target type is lambda,
	// the default is 2.
	UnhealthyThresholdCount int64 `min:"2" type:"integer"`

	// [HTTP/HTTPS health checks] The HTTP codes to use when checking for a successful
	// response from a target.
	//
	// For Application Load Balancers, you can specify values between 200 and 499,
	// and the default value is 200. You can specify multiple values (for example,
	// "200,202") or a range of values (for example, "200-299").
	//
	// HttpCode is a required field
	Matcher string `type:"string"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *elbv2.CreateTargetGroupInput) error `json:"-"`

	// contains filtered or unexported fields
	result *elbv2.TargetGroup
}

// Input returns the AWS input for elbv2.CreateTargetGroup.
func (m *AwsElbTargetGroup) Input(vpcId string) (*elbv2.CreateTargetGroupInput, error) {

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
		VpcId:                      aws.String(vpcId),
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

// AwsSdPrivateDnsNamespace defines the details needed to create a service discovery private namespace.
type AwsSdPrivateDnsNamespace struct {
	// The name that you want to assign to this namespace. When you create a private
	// DNS namespace, AWS Cloud Map automatically creates an Amazon Route 53 private
	// hosted zone that has the same name as the namespace.
	//
	// Name is a required field
	Name string `type:"string" required:"true"`

	// A description for the namespace.
	Description string `type:"string"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *servicediscovery.CreatePrivateDnsNamespaceInput) error `json:"-"`

	// The set of services for the dns namespace.
	Service *AwsSdService `type:"list"`

	// contains filtered or unexported fields
	result *servicediscovery.NamespaceSummary
}

// Input returns the AWS input for servicediscovery.CreatePrivateDnsNamespace.
func (m *AwsSdPrivateDnsNamespace) Input(vpcId string) (*servicediscovery.CreatePrivateDnsNamespaceInput, error) {

	input := &servicediscovery.CreatePrivateDnsNamespaceInput{
		Name:             aws.String(m.Name),
		Description:      aws.String(m.Description),
		Vpc:              aws.String(vpcId),
		CreatorRequestId: aws.String("devops-deploy"),
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
	Name string `type:"string" required:"true"`

	// A description for the service.
	Description string `type:"string"`

	// The amount of time, in seconds, that you want DNS resolvers to cache the
	// settings for this record.
	//
	// Alias records don't include a TTL because Route 53 uses the TTL for the AWS
	// resource that an alias record routes traffic to. If you include the AWS_ALIAS_DNS_NAME
	// attribute when you submit a RegisterInstance request, the TTL value is ignored.
	// Always specify a TTL for the service; you can use a service to register instances
	// that create either alias or non-alias records.
	//
	DnsRecordTTL int64 `type:"long" required:"true"`

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
	HealthCheckFailureThreshold int64 `min:"1" type:"integer"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *servicediscovery.CreateServiceInput) error `json:"-"`

	// contains filtered or unexported fields
	resultArn string
}

// Input returns the AWS input for servicediscovery.CreateService.
func (m *AwsSdService) Input(namespaceId string) (*servicediscovery.CreateServiceInput, error) {

	input := &servicediscovery.CreateServiceInput{
		Name:        aws.String(m.Name),
		Description: aws.String(m.Description),
		NamespaceId: aws.String(namespaceId),
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
	FunctionName string `min:"1" type:"string" required:"true"`

	// A description of the function.
	Description string `type:"string"`

	// The name of the method within your code that Lambda calls to execute your
	// function. The format includes the file name. It can also include namespaces
	// and other qualifiers, depending on the runtime. For more information, see
	// Programming Model (https://docs.aws.amazon.com/lambda/latest/dg/programming-model-v2.html).
	Handler string `type:"string" required:"true"`

	// The amount of memory that your function has access to. Increasing the function's
	// memory also increases its CPU allocation. The default value is 128 MB. The
	// value must be a multiple of 64 MB.
	MemorySize int64 `min:"128" type:"integer"`

	// The Amazon Resource Name (ARN) of the function's execution role.
	Role string `type:"string" required:"true"`

	// The identifier of the function's runtime (https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html).
	Runtime string `type:"string" required:"true" enum:"Runtime"`

	// The amount of time that Lambda allows a function to run before stopping it.
	// The default is 3 seconds. The maximum allowed value is 900 seconds.
	Timeout *int64 `min:"1" type:"integer"`

	// Environment variables that are accessible from function code during execution.
	Environment map[string]string `type:"map" sensitive:"true"`

	// The metadata that you apply to the service to help you categorize and organize
	// them. Each tag consists of a key and an optional value, both of which you
	// define. When a service is deleted, the tags are deleted as well. Tag keys
	// can have a maximum character length of 128 characters, and tag values can
	// have a maximum length of 256 characters.
	Tags []Tag `type:"list"`

	// Optional to provide additional details to the create input.
	PreCreate func(input *lambda.CreateFunctionInput) error `json:"-"`

	// Optional to provide additional details to the update code input.
	PreUpdateCode func(input *lambda.UpdateFunctionCodeInput) error `json:"-"`

	// Optional to provide additional details to the update configuration input.
	PreUpdateConfiguration func(input *lambda.UpdateFunctionConfigurationInput) error `json:"-"`

	// Optional to update the Environment before create function or updateConfiguration is executed.
	UpdateEnvironment func(vars map[string]string) error

	// contains filtered or unexported fields
	result *lambda.FunctionConfiguration
}

// CreateInput returns the AWS input for lambda.CreateFunction.
func (m *AwsLambdaFunction) CreateInput(codeS3Bucket, codeS3Key string, subnetIds, securityGroupIds []string, enableVPC bool) (*lambda.CreateFunctionInput, error) {

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

	if enableVPC {
		input.VpcConfig = &lambda.VpcConfig{
			SubnetIds:        aws.StringSlice(subnetIds),
			SecurityGroupIds: aws.StringSlice(securityGroupIds),
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
func (m *AwsLambdaFunction) UpdateConfigurationInput(subnetIds, securityGroupIds []string, enableVPC bool) (*lambda.UpdateFunctionConfigurationInput, error) {

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

	if enableVPC {
		input.VpcConfig = &lambda.VpcConfig{
			SubnetIds:        aws.StringSlice(subnetIds),
			SecurityGroupIds: aws.StringSlice(securityGroupIds),
		}
	}

	if m.PreUpdateConfiguration != nil {
		if err := m.PreUpdateConfiguration(input); err != nil {
			return input, err
		}
	}

	return input, nil
}
