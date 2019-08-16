package devdeploy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

// DeploymentEnv defines the details needed to build the target deployment environment for AWS.
type DeploymentEnv struct {
	*BuildEnv `validate:"required,dive,required"`

	// AwsEc2Vpc defines the name of the VPC and details needed to create if does not exist.
	AwsEc2Vpc *AwsEc2Vpc

	// AwsEc2SecurityGroup defines the name of the EC2 security group and details needed to create if does not exist.
	AwsEc2SecurityGroup *AwsEc2SecurityGroup

	// GitlabRunnerEc2SecurityGroupName defines the name of the security group that was used to deploy the GitLab
	// Runners on AWS. This will allow the deploy script to ensure the GitLab Runners have access to community to through
	// the deployment EC2 Security Group.
	GitlabRunnerEc2SecurityGroupName string `validate:"required"`

	// AwsS3BucketPrivate sets the S3 bucket used internally for services.
	AwsS3BucketPrivate *AwsS3Bucket

	// AwsS3BucketPublic sets the S3 bucket used to host static files for all services.
	AwsS3BucketPublic *AwsS3Bucket

	// AwsS3BucketPublicKeyPrefix defines the base S3 key prefix used to upload static files.
	AwsS3BucketPublicKeyPrefix string `validate:"omitempty"`

	// AwsElasticCacheCluster defines the name of the cache cluster and the details needed to create if does not exist.
	AwsElasticCacheCluster *AwsElasticCacheCluster

	// AwsRdsDBCluster defines the name of the rds cluster and the details needed to create if does not exist.
	// This is only needed for Aurora storage engine.
	AwsRdsDBCluster *AwsRdsDBCluster

	// AwsRdsDBInstance defines the name of the rds database instance and the detailed needed to create doesn't exist.
	AwsRdsDBInstance *AwsRdsDBInstance

	// DBConnInfo defines the database connection details.
	DBConnInfo *DBConnInfo
}

// SecretID returns the secret name with a standard prefix.
func (deployEnv *DeploymentEnv) SecretID(secretName string) string {
	return filepath.Join(deployEnv.ProjectName, deployEnv.Env, secretName)
}

// Ec2TagResource is a helper function to tag EC2 resources.
func (deployEnv *DeploymentEnv) Ec2TagResource(resource, name string, tags ...Tag) error {
	svc := ec2.New(deployEnv.AwsSession())

	existingKeys := make(map[string]bool)
	ec2Tags := []*ec2.Tag{}
	for _, t := range tags {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(t.Key), Value: aws.String(t.Value)})
		existingKeys[t.Key] = true
	}

	if !existingKeys[AwsTagNameProject] {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameProject), Value: aws.String(deployEnv.ProjectName)})
	}

	if !existingKeys[AwsTagNameEnv] {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameEnv), Value: aws.String(deployEnv.Env)})
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

// SetupDeploymentEnv ensures all the resources for the project are setup before deploying a single ECS service or
// Lambda function. This will ensure the following AWS are available for deployment:
// 1. AWS EC2 VPC
// 2. AWS EC2 Security Group
// 3. AWS S3 buckets
// 4. AWS Elastic Cache Cluster
// 5. AWS RDS database Cluster
// 6. AWS RDS database Instance
func SetupDeploymentEnv(log *log.Logger, buildEnv *BuildEnv, deployEnv *DeploymentEnv) error {
	deployEnv.BuildEnv = buildEnv

	log.Printf("Setup deployment environment %s\n", deployEnv.Env)

	log.Println("\tValidate request.")
	errs := validator.New().Struct(deployEnv)
	if errs != nil {
		return errs
	}

	// Step 1: Find or create the AWS EC2 VPC.
	{
		log.Println("\tEC2 - Find Subnets")

		svc := ec2.New(deployEnv.AwsSession())

		var subnets []*ec2.Subnet
		if deployEnv.AwsEc2Vpc.IsDefault {
			log.Println("\t\tFind all subnets are that default for each availability zone in the zone")

			// Find all subnets that are default for each availability zone.
			err := svc.DescribeSubnetsPages(&ec2.DescribeSubnetsInput{}, func(res *ec2.DescribeSubnetsOutput, lastPage bool) bool {
				for _, s := range res.Subnets {
					if *s.DefaultForAz {
						subnets = append(subnets, s)
					}
				}
				return !lastPage
			})
			if err != nil {
				return errors.Wrap(err, "Failed to find default subnets")
			}

			// Iterate through subnets and make sure they belong to the same VPC as the project.
			for _, s := range subnets {
				if s.VpcId == nil {
					continue
				}
				if deployEnv.AwsEc2Vpc.VpcId == "" {
					deployEnv.AwsEc2Vpc.VpcId = *s.VpcId

					log.Printf("\t\tFound VPC: %s", deployEnv.AwsEc2Vpc.VpcId)

				} else if deployEnv.AwsEc2Vpc.VpcId != *s.VpcId {
					return errors.Errorf("Invalid subnet %s, all subnets should belong to the same VPC, expected %s, got %s", *s.SubnetId, deployEnv.AwsEc2Vpc.VpcId, *s.VpcId)
				}
			}
		} else {

			if deployEnv.AwsEc2Vpc.VpcId != "" {
				log.Printf("\t\tFind VPC '%s'\n", deployEnv.AwsEc2Vpc.VpcId)

				// Find all subnets that are default for each availability zone.
				err := svc.DescribeVpcsPages(&ec2.DescribeVpcsInput{
					VpcIds: aws.StringSlice([]string{deployEnv.AwsEc2Vpc.VpcId}),
				}, func(res *ec2.DescribeVpcsOutput, lastPage bool) bool {
					for _, s := range res.Vpcs {
						if *s.VpcId == deployEnv.AwsEc2Vpc.VpcId {
							deployEnv.AwsEc2Vpc.result = s
							break
						}
					}
					return !lastPage
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to describe vpc '%s'.", deployEnv.AwsEc2Vpc.VpcId)
				}
			}

			// If there is no VPC id set and IsDefault is false, a new VPC needs to be created with the given details.
			if deployEnv.AwsEc2Vpc.result == nil {

				input, err := deployEnv.AwsEc2Vpc.Input()
				if err != nil {
					return err
				}

				createRes, err := svc.CreateVpc(input)
				if err != nil {
					return errors.Wrap(err, "Failed to create VPC")
				}
				deployEnv.AwsEc2Vpc.result = createRes.Vpc
				deployEnv.AwsEc2Vpc.VpcId = *createRes.Vpc.VpcId
				log.Printf("\t\tCreated VPC %s", deployEnv.AwsEc2Vpc.VpcId)

				err = deployEnv.Ec2TagResource(*createRes.Vpc.VpcId, "", deployEnv.AwsEc2Vpc.Tags...)
				if err != nil {
					return errors.Wrapf(err, "Failed to tag vpc '%s'.", deployEnv.AwsEc2Vpc.VpcId)
				}

			} else {
				log.Println("\t\tFind all subnets for VPC.")

				// Find all subnets that are default for each availability zone.
				err := svc.DescribeSubnetsPages(&ec2.DescribeSubnetsInput{}, func(res *ec2.DescribeSubnetsOutput, lastPage bool) bool {
					for _, s := range res.Subnets {
						if *s.VpcId == deployEnv.AwsEc2Vpc.VpcId {
							subnets = append(subnets, s)
						}
					}
					return !lastPage
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to find subnets for VPC '%s'", deployEnv.AwsEc2Vpc.VpcId)
				}
			}

			for _, sn := range deployEnv.AwsEc2Vpc.Subnets {
				var found bool
				for _, t := range subnets {
					if t.CidrBlock != nil && *t.CidrBlock == sn.CidrBlock {
						found = true
						break
					}
				}

				if !found {
					input, err := sn.Input(deployEnv.AwsEc2Vpc.VpcId)
					if err != nil {
						return err
					}

					createRes, err := svc.CreateSubnet(input)
					if err != nil {
						return errors.Wrap(err, "Failed to create VPC")
					}
					subnets = append(subnets, createRes.Subnet)

					log.Printf("\t\tCreated Subnet %s", *createRes.Subnet.SubnetId)

					err = deployEnv.Ec2TagResource(*createRes.Subnet.SubnetId, "", sn.Tags...)
					if err != nil {
						return errors.Wrapf(err, "Failed to tag subnet '%s'.", *createRes.Subnet.SubnetId)
					}
				}
			}
		}

		// This deployment process requires at least one subnet.
		// Each AWS account gets a default VPC and default subnet for each availability zone.
		// Likely error with AWs is can not find at least one.
		if len(subnets) == 0 {
			return errors.New("Failed to find any subnets, expected at least 1")
		}

		log.Printf("\t\tVPC '%s' has %d subnets", deployEnv.AwsEc2Vpc.VpcId)
		for _, sn := range subnets {
			deployEnv.AwsEc2Vpc.subnetIds = append(deployEnv.AwsEc2Vpc.subnetIds, *sn.SubnetId)
			log.Printf("\t\t\tSubnet: %s", *sn.SubnetId)
		}

		log.Printf("\t%s\tEC2 subnets available\n", Success)
	}

	// Step 2: Find or create  AWS EC2 Security Group.
	var securityGroupId string
	{
		log.Println("\tEC2 - Find Security Group")

		svc := ec2.New(deployEnv.AwsSession())

		securityGroupName := deployEnv.AwsEc2SecurityGroup.GroupName

		// Find all the security groups and then parse the group name to get the Id of the security group.
		var runnerSgId string
		err := svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
			GroupNames: aws.StringSlice([]string{securityGroupName, deployEnv.GitlabRunnerEc2SecurityGroupName}),
		}, func(res *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
			for _, s := range res.SecurityGroups {
				if *s.GroupName == securityGroupName {
					deployEnv.AwsEc2SecurityGroup.result = s
				} else if *s.GroupName == deployEnv.GitlabRunnerEc2SecurityGroupName {
					runnerSgId = *s.GroupId
				}
			}
			return !lastPage
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidGroup.NotFound" {
				return errors.Wrapf(err, "Failed to find security group '%s'", securityGroupName)
			}
		}

		if deployEnv.AwsEc2SecurityGroup.result == nil {
			input, err := deployEnv.AwsEc2SecurityGroup.Input(deployEnv.AwsEc2Vpc.VpcId)
			if err != nil {
				return err
			}

			// If no security group was found, create one.
			createRes, err := svc.CreateSecurityGroup(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create security group '%s'", securityGroupName)
			}
			deployEnv.AwsEc2SecurityGroup.result = &ec2.SecurityGroup{
				GroupId:   createRes.GroupId,
				GroupName: input.GroupName,
				VpcId:     input.VpcId,
			}

			log.Printf("\t\tCreated: %s", securityGroupName)

			err = deployEnv.Ec2TagResource(*createRes.GroupId, "", deployEnv.AwsEc2SecurityGroup.Tags...)
			if err != nil {
				return errors.Wrapf(err, "Failed to tag security group '%s'.", securityGroupName)
			}
		} else {
			log.Printf("\t\tFound: %s", securityGroupName)
		}

		securityGroupId = *deployEnv.AwsEc2SecurityGroup.result.GroupId

		// Create a list of ingress rules for the security group.
		ingressInputs := []*ec2.AuthorizeSecurityGroupIngressInput{
			// Enable services to be publicly available via HTTP port 80
			&ec2.AuthorizeSecurityGroupIngressInput{
				IpProtocol: aws.String("tcp"),
				CidrIp:     aws.String("0.0.0.0/0"),
				FromPort:   aws.Int64(80),
				ToPort:     aws.Int64(80),
				GroupId:    aws.String(securityGroupId),
			},
			// Allow all services in the security group to access other services.
			&ec2.AuthorizeSecurityGroupIngressInput{
				SourceSecurityGroupName: aws.String(securityGroupName),
				GroupId:                 aws.String(securityGroupId),
			},
		}

		// When a database cluster/instance is defined, deploy needs access to handle executing schema migration.
		if deployEnv.AwsRdsDBCluster != nil || deployEnv.AwsRdsDBInstance != nil {
			// The gitlab runner security group is required when a db instance is defined.
			if runnerSgId == "" {
				return errors.Errorf("Failed to find security group '%s'", deployEnv.GitlabRunnerEc2SecurityGroupName)
			}

			// Enable GitLab runner to communicate with deployment created services.
			ingressInputs = append(ingressInputs, &ec2.AuthorizeSecurityGroupIngressInput{
				SourceSecurityGroupName: aws.String(deployEnv.GitlabRunnerEc2SecurityGroupName),
				GroupId:                 aws.String(securityGroupId),
			})
		}

		// Add all the default ingress to the security group.
		for _, ingressInput := range ingressInputs {
			_, err = svc.AuthorizeSecurityGroupIngress(ingressInput)
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidPermission.Duplicate" {
					return errors.Wrapf(err, "Failed to add ingress for security group '%s'", securityGroupName)
				}
			}
		}

		log.Printf("\t%s\tSecurity Group configured\n", Success)
	}

	// Step 3: Find or create the list of AWS S3 buckets.
	{
		log.Println("\tS3 - Setup Buckets")

		svc := s3.New(deployEnv.AwsSession())

		s3Buckets := []*AwsS3Bucket{
			deployEnv.AwsS3BucketPrivate,
			deployEnv.AwsS3BucketPublic,
		}

		for _, s3Bucket := range s3Buckets {
			bucketName := s3Bucket.BucketName

			input, err := s3Bucket.Input()
			if err != nil {
				return err
			}

			_, err = svc.CreateBucket(input)
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != s3.ErrCodeBucketAlreadyExists && aerr.Code() != s3.ErrCodeBucketAlreadyOwnedByYou) {
					return errors.Wrapf(err, "failed to create s3 bucket '%s'", bucketName)
				}

				// If bucket found during create, returns it.
				log.Printf("\t\tFound: %s\n", bucketName)
			} else {

				// If no bucket found during create, create new one.
				log.Printf("\t\tCreated: %s\n", bucketName)
			}
		}

		log.Println("\t\tWait for S3 Buckets to exist")

		// S3 has a delay between when one is created vs when it is available to use.
		// Thus, need to iterate through each bucket and wait until it exists.
		for _, s3Bucket := range s3Buckets {
			bucketName := s3Bucket.BucketName

			log.Printf("\t\t\t%s", bucketName)
			err := svc.WaitUntilBucketExists(&s3.HeadBucketInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				return errors.Wrapf(err, "Failed to wait for s3 bucket '%s' to exist", bucketName)
			}
		}

		// Loop through each S3 bucket and configure policies.
		log.Println("\t\tConfiguring each S3 Bucket")
		for _, s3Bucket := range s3Buckets {
			bucketName := s3Bucket.BucketName

			log.Printf("\t\t\t%s", bucketName)

			// Add all the defined lifecycle rules for the bucket.
			if len(s3Bucket.LifecycleRules) > 0 {
				_, err := svc.PutBucketLifecycleConfiguration(&s3.PutBucketLifecycleConfigurationInput{
					Bucket: aws.String(bucketName),
					LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
						Rules: s3Bucket.LifecycleRules,
					},
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to configure lifecycle rule for s3 bucket '%s'", bucketName)
				}

				for _, r := range s3Bucket.LifecycleRules {
					log.Printf("\t\t\t\tAdded lifecycle '%s'\n", *r.ID)
				}
			}

			// Add all the defined CORS rules for the bucket.
			if len(s3Bucket.CORSRules) > 0 {
				_, err := svc.PutBucketCors(&s3.PutBucketCorsInput{
					Bucket: aws.String(bucketName),
					CORSConfiguration: &s3.CORSConfiguration{
						CORSRules: s3Bucket.CORSRules,
					},
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to put CORS on s3 bucket '%s'", bucketName)
				}
				log.Println("\t\t\t\tUpdated CORS")
			}

			// Block public access for all non-public buckets.
			if s3Bucket.PublicAccessBlock != nil {
				_, err := svc.PutPublicAccessBlock(&s3.PutPublicAccessBlockInput{
					Bucket:                         aws.String(bucketName),
					PublicAccessBlockConfiguration: s3Bucket.PublicAccessBlock,
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to block public access for s3 bucket '%s'", bucketName)
				}
				log.Println("\t\t\t\tBlocked public access")
			}

			// Add the bucket policy if not empty.
			if s3Bucket.Policy != "" {
				_, err := svc.PutBucketPolicy(&s3.PutBucketPolicyInput{
					Bucket: aws.String(bucketName),
					Policy: aws.String(s3Bucket.Policy),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to put bucket policy for s3 bucket '%s'", bucketName)
				}
				log.Println("\t\t\t\tUpdated bucket policy")
			}

			if s3Bucket.CloudFront != nil {
				log.Println("\t\t\t\tSetup Cloudfront Distribution")

				bucketLoc := deployEnv.AwsCredentials.Region
				if s3Bucket.LocationConstraint != nil && *s3Bucket.LocationConstraint != "" {
					bucketLoc = *s3Bucket.LocationConstraint
				}

				allowedMethods := &cloudfront.AllowedMethods{
					Items: aws.StringSlice(s3Bucket.CloudFront.CachedMethods),
				}
				allowedMethods.Quantity = aws.Int64(int64(len(allowedMethods.Items)))

				cacheMethods := &cloudfront.CachedMethods{
					Items: aws.StringSlice(s3Bucket.CloudFront.CachedMethods),
				}
				cacheMethods.Quantity = aws.Int64(int64(len(cacheMethods.Items)))
				allowedMethods.SetCachedMethods(cacheMethods)

				domainId := "S3-" + s3Bucket.BucketName
				domainName := fmt.Sprintf("%s.s3.%s.amazonaws.com", s3Bucket.BucketName, bucketLoc)

				origins := &cloudfront.Origins{
					Items: []*cloudfront.Origin{
						&cloudfront.Origin{
							Id:         aws.String(domainId),
							DomainName: aws.String(domainName),
							OriginPath: aws.String(s3Bucket.CloudFront.OriginPath),
							S3OriginConfig: &cloudfront.S3OriginConfig{
								OriginAccessIdentity: aws.String(""),
							},
							CustomHeaders: &cloudfront.CustomHeaders{
								Quantity: aws.Int64(0),
							},
						},
					},
				}
				origins.Quantity = aws.Int64(int64(len(origins.Items)))

				s3Bucket.CloudFront.DistributionConfig.DefaultCacheBehavior.TargetOriginId = aws.String(domainId)
				s3Bucket.CloudFront.DistributionConfig.DefaultCacheBehavior.AllowedMethods = allowedMethods
				s3Bucket.CloudFront.DistributionConfig.Origins = origins

				input, err := s3Bucket.CloudFront.Input()
				if err != nil {
					return err
				}

				targetOriginId := *input.DistributionConfig.DefaultCacheBehavior.TargetOriginId

				_, err = cloudfront.New(deployEnv.AwsSession()).CreateDistribution(input)
				if err != nil {
					if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != cloudfront.ErrCodeDistributionAlreadyExists) {
						return errors.Wrapf(err, "Failed to create cloudfront distribution '%s'", targetOriginId)
					}

					// If bucket found during create, returns it.
					log.Printf("\t\t\t\t\tFound: %s.", targetOriginId)
				} else {

					// If no bucket found during create, create new one.
					log.Printf("\t\t\t\t\tCreated: %s.", targetOriginId)
				}
			}
		}

		log.Printf("\t%s\tS3 buckets configured successfully.\n", Success)
	}

	// Step 4: Find or create the AWS Elastic Cache Cluster.
	if deployEnv.AwsElasticCacheCluster != nil {
		log.Println("\tElastic Cache - Get or Create Cache Cluster")

		svc := elasticache.New(deployEnv.AwsSession())

		cacheClusterId := deployEnv.AwsElasticCacheCluster.CacheClusterId

		// Find Elastic Cache cluster given Id.
		var cacheCluster *elasticache.CacheCluster
		descRes, err := svc.DescribeCacheClusters(&elasticache.DescribeCacheClustersInput{
			CacheClusterId:    aws.String(cacheClusterId),
			ShowCacheNodeInfo: aws.Bool(true),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elasticache.ErrCodeCacheClusterNotFoundFault {
				return errors.Wrapf(err, "Failed to describe cache cluster '%s'", cacheClusterId)
			}
		} else if len(descRes.CacheClusters) > 0 {
			cacheCluster = descRes.CacheClusters[0]
			deployEnv.AwsElasticCacheCluster.result = cacheCluster
		}

		if deployEnv.AwsElasticCacheCluster.result == nil {

			input, err := deployEnv.AwsElasticCacheCluster.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no repository was found, create one.
			createRes, err := svc.CreateCacheCluster(input)
			if err != nil {
				return errors.Wrapf(err, "failed to create cluster '%s'", cacheClusterId)
			}
			cacheCluster = createRes.CacheCluster
			deployEnv.AwsElasticCacheCluster.result = cacheCluster

			log.Printf("\t\tCreated: %s", *cacheCluster.CacheClusterId)
		} else {
			log.Printf("\t\tFound: %s", *cacheCluster.CacheClusterId)
		}

		// The status of the cluster.
		log.Printf("\t\t\tStatus: %s", *cacheCluster.CacheClusterStatus)

		// If the cache cluster is not active because it was recently created, wait for it to become active.
		if *cacheCluster.CacheClusterStatus != "available" {
			log.Printf("\t\tWhat for cluster to become available.")
			err = svc.WaitUntilCacheClusterAvailable(&elasticache.DescribeCacheClustersInput{
				CacheClusterId: aws.String(cacheClusterId),
			})
			if err != nil {
				return errors.Wrapf(err, "Failed to wait for cache cluster '%s' to enter available state", cacheClusterId)
			}
			cacheCluster.CacheClusterStatus = aws.String("available")
		}

		// TODO: Tag cache cluster, ARN for the cache cluster when it is not readily available.
		_, err = svc.AddTagsToResource(&elasticache.AddTagsToResourceInput{
			ResourceName: aws.String(cacheClusterId),
			Tags: []*elasticache.Tag{
				{Key: aws.String(AwsTagNameProject), Value: aws.String(deployEnv.ProjectName)},
				{Key: aws.String(AwsTagNameEnv), Value: aws.String(deployEnv.Env)},
			},
		})
		if err != nil {
			return errors.Wrapf(err, "Failed to tag cache cluster '%s'", cacheClusterId)
		}

		// If there are custom cache group parameters set, then create a new group and keep them modified.
		if len(deployEnv.AwsElasticCacheCluster.ParameterNameValues) > 0 {

			customCacheParameterGroupName := fmt.Sprintf("%s-%s%s",
				strings.ToLower(deployEnv.ProjectNameCamel()),
				*cacheCluster.Engine,
				*cacheCluster.EngineVersion)

			customCacheParameterGroupName = strings.Replace(customCacheParameterGroupName, ".", "-", -1)

			// If the cache cluster is using the default parameter group, create a new custom group.
			if strings.HasPrefix(*cacheCluster.CacheParameterGroup.CacheParameterGroupName, "default") {
				// Lookup the group family from the current cache parameter group.
				descRes, err := svc.DescribeCacheParameterGroups(&elasticache.DescribeCacheParameterGroupsInput{
					CacheParameterGroupName: cacheCluster.CacheParameterGroup.CacheParameterGroupName,
				})
				if err != nil {
					if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elasticache.ErrCodeCacheClusterNotFoundFault {
						return errors.Wrapf(err, "Failed to describe cache parameter group '%s'", cacheClusterId)
					}
				}

				log.Printf("\t\tCreated custom Cache Parameter Group : %s", customCacheParameterGroupName)
				_, err = svc.CreateCacheParameterGroup(&elasticache.CreateCacheParameterGroupInput{
					CacheParameterGroupFamily: descRes.CacheParameterGroups[0].CacheParameterGroupFamily,
					CacheParameterGroupName:   aws.String(customCacheParameterGroupName),
					Description:               aws.String(fmt.Sprintf("Customized default parameter group for %s %s", *cacheCluster.Engine, *cacheCluster.EngineVersion)),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to cache parameter group '%s'", customCacheParameterGroupName)
				}

				log.Printf("\t\tSet Cache Parameter Group : %s", customCacheParameterGroupName)
				updateRes, err := svc.ModifyCacheCluster(&elasticache.ModifyCacheClusterInput{
					CacheClusterId:          cacheCluster.CacheClusterId,
					CacheParameterGroupName: aws.String(customCacheParameterGroupName),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed modify cache parameter group '%s' for cache cluster '%s'", customCacheParameterGroupName, *cacheCluster.CacheClusterId)
				}
				cacheCluster = updateRes.CacheCluster
			}

			// Only modify the cache parameter group if the cache cluster is custom one created to allow other groups to
			// be set on the cache cluster but not modified.
			if *cacheCluster.CacheParameterGroup.CacheParameterGroupName == customCacheParameterGroupName {
				log.Printf("\t\tUpdating Cache Parameter Group : %s", customCacheParameterGroupName)

				input, err := deployEnv.AwsElasticCacheCluster.CacheParameterGroupInput(customCacheParameterGroupName)
				if err != nil {
					return err
				}
				_, err = svc.ModifyCacheParameterGroup(input)
				if err != nil {
					return errors.Wrapf(err, "failed to modify cache parameter group '%s'", *cacheCluster.CacheParameterGroup.CacheParameterGroupName)
				}

				for _, p := range deployEnv.AwsElasticCacheCluster.ParameterNameValues {
					log.Printf("\t\t\tSet '%s' to '%s'", p.ParameterName, p.ParameterValue)
				}
			}
		}

		// Ensure cache nodes are set after updating parameters.
		if len(cacheCluster.CacheNodes) == 0 {
			// Find Elastic Cache cluster given Id.
			descRes, err := svc.DescribeCacheClusters(&elasticache.DescribeCacheClustersInput{
				CacheClusterId:    aws.String(cacheClusterId),
				ShowCacheNodeInfo: aws.Bool(true),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elasticache.ErrCodeCacheClusterNotFoundFault {
					return errors.Wrapf(err, "Failed to describe cache cluster '%s'", cacheClusterId)
				}
			} else if len(descRes.CacheClusters) > 0 {
				cacheCluster = descRes.CacheClusters[0]
				deployEnv.AwsElasticCacheCluster.result = cacheCluster
			}
		}

		log.Printf("\t%s\tElastic Cache cluster configured for %s\n", Success, *cacheCluster.Engine)
	}

	// Step 5: Find or create the AWS RDS database Cluster.
	// This is only used when service uses Aurora via RDS for serverless Postgres and database cluster is defined.
	// Aurora Postgres is limited to specific AWS regions and thus not used by default.
	// If an Aurora Postgres cluster is defined, ensure it exists with RDS else create a new one.
	if deployEnv.AwsRdsDBCluster != nil {
		log.Println("\tRDS - Get or Create Database Cluster")

		svc := rds.New(deployEnv.AwsSession())

		dBClusterIdentifier := deployEnv.AwsRdsDBCluster.DBClusterIdentifier

		// Secret ID used to store the DB username and password across deploys.
		dbSecretId := deployEnv.SecretID(dBClusterIdentifier)

		// Retrieve the current secret value if something is stored.
		{
			sm := secretsmanager.New(deployEnv.AwsSession())
			res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(dbSecretId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
					return errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
				}
			} else {
				err = json.Unmarshal([]byte(*res.SecretString), &deployEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to json decode db credentials")
				}
			}
		}

		// Try to find a RDS database cluster using cluster identifier.
		descRes, err := svc.DescribeDBClusters(&rds.DescribeDBClustersInput{
			DBClusterIdentifier: aws.String(dBClusterIdentifier),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBClusterNotFoundFault {
				return errors.Wrapf(err, "Failed to describe database cluster '%s'", dBClusterIdentifier)
			}
		} else if len(descRes.DBClusters) > 0 {
			deployEnv.AwsRdsDBCluster.result = descRes.DBClusters[0]
		}

		if deployEnv.AwsRdsDBCluster.result == nil {
			if deployEnv.DBConnInfo != nil && deployEnv.DBConnInfo.Pass != "" {
				deployEnv.AwsRdsDBCluster.MasterUserPassword = deployEnv.DBConnInfo.User
				deployEnv.AwsRdsDBCluster.MasterUserPassword = deployEnv.DBConnInfo.Pass
			}

			// Store the secret first in the event that create fails.
			if deployEnv.DBConnInfo == nil {
				// Only set the password right now,
				// all other configuration details will be set after the database instance is created.
				deployEnv.DBConnInfo = &DBConnInfo{
					Pass: deployEnv.AwsRdsDBCluster.MasterUserPassword,
				}

				// Json encode the db details to be stored as secret text.
				dat, err := json.Marshal(deployEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Create the new entry in AWS Secret Manager with the database password.
				sm := secretsmanager.New(deployEnv.AwsSession())
				_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
					Name:         aws.String(dbSecretId),
					SecretString: aws.String(string(dat)),
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create new secret with db credentials")
				}
				log.Printf("\t\tStored Secret\n")
			}

			input, err := deployEnv.AwsRdsDBCluster.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no cluster was found, create one.
			createRes, err := svc.CreateDBCluster(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create cluster '%s'", dBClusterIdentifier)
			}
			deployEnv.AwsRdsDBCluster.result = createRes.DBCluster

			log.Printf("\t\tCreated: %s", *deployEnv.AwsRdsDBCluster.result.DBClusterArn)
		} else {
			log.Printf("\t\tFound: %s", *deployEnv.AwsRdsDBCluster.result.DBClusterArn)
		}

		dbCluster := *deployEnv.AwsRdsDBCluster.result

		// The status of the cluster.
		log.Printf("\t\t\tStatus: %s", *dbCluster.Status)

		// Update the secret with the DB cluster details. This happens after DB create to help address when the
		// DB cluster was successfully created, but the secret failed to save. The DB details host should be empty or
		// match the current cluster endpoint.
		curHost := *dbCluster.Endpoint
		if curHost != deployEnv.DBConnInfo.Host {

			// Copy the cluster details to the DB struct.
			deployEnv.DBConnInfo.Host = curHost
			deployEnv.DBConnInfo.User = *dbCluster.MasterUsername
			deployEnv.DBConnInfo.Database = *dbCluster.DatabaseName
			deployEnv.DBConnInfo.Driver = *dbCluster.Engine
			deployEnv.DBConnInfo.DisableTLS = false

			// Json encode the DB details to be stored as text via AWS Secrets Manager.
			dat, err := json.Marshal(deployEnv.DBConnInfo)
			if err != nil {
				return errors.Wrap(err, "Failed to marshal db credentials")
			}

			// Update the current AWS Secret.
			sm := secretsmanager.New(deployEnv.AwsSession())
			_, err = sm.UpdateSecret(&secretsmanager.UpdateSecretInput{
				SecretId:     aws.String(dbSecretId),
				SecretString: aws.String(string(dat)),
			})
			if err != nil {
				return errors.Wrap(err, "Failed to update secret with db credentials")
			}
			log.Printf("\t\tUpdate Secret\n")

			// Ensure the newly created database is seeded.
			log.Printf("\t\tOpen database connection")
		}

		log.Printf("\t%s\tDB Cluster available\n", Success)
	}

	// Step 6: Find or create the AWS RDS database Instance.
	// Regardless if deployment is using Aurora or not, still need to setup database instance.
	// If a database instance is defined, then ensure it exists with RDS in else create a new one.
	if deployEnv.AwsRdsDBInstance != nil {
		log.Println("\tRDS - Get or Create Database Instance")

		dBInstanceIdentifier := deployEnv.AwsRdsDBInstance.DBInstanceIdentifier

		// Secret ID used to store the DB username and password across deploys.
		dbSecretId := deployEnv.SecretID(dBInstanceIdentifier)

		// Retrieve the current secret value if something is stored.
		{
			sm := secretsmanager.New(deployEnv.AwsSession())
			res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(dbSecretId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
					return errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
				}
			} else {
				err = json.Unmarshal([]byte(*res.SecretString), &deployEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to json decode db credentials")
				}
			}
		}

		// Init a new RDS client.
		svc := rds.New(deployEnv.AwsSession())

		// Try to find an existing DB instance with the same identifier.
		descRes, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(dBInstanceIdentifier),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBInstanceNotFoundFault {
				return errors.Wrapf(err, "Failed to describe database instance '%s'", dBInstanceIdentifier)
			}
		} else if len(descRes.DBInstances) > 0 {
			deployEnv.AwsRdsDBInstance.result = descRes.DBInstances[0]
		}

		// No DB instance was found, so create a new one.
		if deployEnv.AwsRdsDBInstance.result == nil {

			if deployEnv.DBConnInfo != nil && deployEnv.DBConnInfo.Pass != "" {
				deployEnv.AwsRdsDBCluster.MasterUserPassword = deployEnv.DBConnInfo.User
				deployEnv.AwsRdsDBCluster.MasterUserPassword = deployEnv.DBConnInfo.Pass
			}

			if deployEnv.AwsRdsDBCluster != nil {
				deployEnv.AwsRdsDBInstance.DBClusterIdentifier = aws.String(deployEnv.AwsRdsDBCluster.DBClusterIdentifier)
			} else {
				// Only store the db password for the instance when no cluster is defined.
				// Store the secret first in the event that create fails.
				if deployEnv.DBConnInfo == nil {
					// Only set the password right now,
					// all other configuration details will be set after the database instance is created.
					deployEnv.DBConnInfo = &DBConnInfo{
						Pass: deployEnv.AwsRdsDBCluster.MasterUserPassword,
					}

					// Json encode the db details to be stored as secret text.
					dat, err := json.Marshal(deployEnv.DBConnInfo)
					if err != nil {
						return errors.Wrap(err, "Failed to marshal db credentials")
					}

					// Create the new entry in AWS Secret Manager with the database password.
					sm := secretsmanager.New(deployEnv.AwsSession())
					_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
						Name:         aws.String(dbSecretId),
						SecretString: aws.String(string(dat)),
					})
					if err != nil {
						return errors.Wrap(err, "Failed to create new secret with db credentials")
					}
					log.Printf("\t\tStored Secret\n")
				}
			}

			input, err := deployEnv.AwsRdsDBInstance.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no instance was found, create one.
			createRes, err := svc.CreateDBInstance(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create instance '%s'", dBInstanceIdentifier)
			}
			deployEnv.AwsRdsDBInstance.result = createRes.DBInstance

			log.Printf("\t\tCreated: %s", *deployEnv.AwsRdsDBInstance.result.DBInstanceArn)
		} else {
			log.Printf("\t\tFound: %s", *deployEnv.AwsRdsDBInstance.result.DBInstanceArn)
		}

		dbInstance := *deployEnv.AwsRdsDBInstance.result

		// The status of the instance.
		log.Printf("\t\t\tStatus: %s", *dbInstance.DBInstanceStatus)

		// If the instance is not active because it was recently created, wait for it to become active.
		if *dbInstance.DBInstanceStatus != "available" {
			log.Printf("\t\tWait for instance to become available.")
			err = svc.WaitUntilDBInstanceAvailable(&rds.DescribeDBInstancesInput{
				DBInstanceIdentifier: dbInstance.DBInstanceIdentifier,
			})
			if err != nil {
				return errors.Wrapf(err, "Failed to wait for database instance '%s' to enter available state", dBInstanceIdentifier)
			}
			dbInstance.DBInstanceStatus = aws.String("available")
		}

		// If a database cluster is not defined, update the database details with the current instance.
		if deployEnv.AwsRdsDBCluster == nil {
			// Update the secret with the DB instance details. This happens after DB create to help address when the
			// DB instance was successfully created, but the secret failed to save. The DB details host should be empty or
			// match the current instance endpoint.
			curHost := fmt.Sprintf("%s:%d", *dbInstance.Endpoint.Address, *dbInstance.Endpoint.Port)
			if curHost != deployEnv.DBConnInfo.Host {

				// Copy the instance details to the DB struct.
				deployEnv.DBConnInfo.Host = curHost
				deployEnv.DBConnInfo.User = *dbInstance.MasterUsername
				deployEnv.DBConnInfo.Database = *dbInstance.DBName
				deployEnv.DBConnInfo.Driver = *dbInstance.Engine
				deployEnv.DBConnInfo.DisableTLS = false

				// Json encode the DB details to be stored as text via AWS Secrets Manager.
				dat, err := json.Marshal(deployEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Update the current AWS Secret.
				sm := secretsmanager.New(deployEnv.AwsSession())
				_, err = sm.UpdateSecret(&secretsmanager.UpdateSecretInput{
					SecretId:     aws.String(dbSecretId),
					SecretString: aws.String(string(dat)),
				})
				if err != nil {
					return errors.Wrap(err, "Failed to update secret with db credentials")
				}
				log.Printf("\t\tUpdate Secret\n")

				// Ensure the newly created database is seeded.
				log.Printf("\t\tOpen database connection")
			}
		}

		log.Printf("\t%s\tDB Instance available\n", Success)
	}

	return nil
}

// LoadModuleDetails returns the project details based on the go.mod file.
func LoadModuleDetails(workDir string) (ModuleDetails, error) {
	var (
		resp ModuleDetails
		err  error
	)

	resp.GoModFile, err = findProjectGoModFile(workDir)
	if err != nil {
		return resp, err
	}
	resp.ProjectRoot = filepath.Dir(resp.GoModFile)

	resp.GoModName, err = loadGoModName(resp.GoModFile)
	if err != nil {
		return resp, err
	}
	resp.ProjectName = filepath.Base(resp.GoModName)

	return resp, nil
}

// findProjectGoModFile finds the project root directory from the current working directory.
func findProjectGoModFile(workDir string) (string, error) {

	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return "", errors.WithMessage(err, "failed to get current working directory")
		}
	}

	// Try to find the project root for looking for the go.mod file in a parent directory.
	var goModFile string
	testDir := workDir
	for i := 0; i < 3; i++ {
		if goModFile != "" {
			testDir = filepath.Join(testDir, "../")
		}
		goModFile = filepath.Join(testDir, "go.mod")
		ok, _ := exists(goModFile)
		if ok {
			workDir = testDir
			break
		}
	}

	// Verify the go.mod file was found.
	ok, err := exists(goModFile)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to load go.mod for project using project root %s", workDir)
	} else if !ok {
		return "", errors.Errorf("failed to locate project go.mod in project root %s", workDir)
	}

	return goModFile, nil
}

// loadGoModName parses out the module name from go.mod.
func loadGoModName(goModFile string) (string, error) {
	ok, err := exists(goModFile)
	if err != nil {
		return "", errors.WithMessage(err, "Failed to load go.mod for project")
	} else if !ok {
		return "", errors.Errorf("Failed to locate project go.mod at %s", goModFile)
	}

	b, err := ioutil.ReadFile(goModFile)
	if err != nil {
		return "", errors.WithMessagef(err, "Failed to read go.mod at %s", goModFile)
	}

	var name string
	lines := strings.Split(string(b), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "module ") {
			name = strings.TrimSpace(strings.Split(l, " ")[1])
			break
		}
	}

	return name, nil
}

// GitLabCiReleaseTag returns the name used for tagging a release image will always include one with environment and
// service name. If the env var CI_COMMIT_REF_NAME is set, it will be appended.
func GitLabCiReleaseTag(env, serviceName string) string {

	tag1 := env + "-" + serviceName

	// Generate tags for the release image.
	var releaseTag string
	if v := os.Getenv("CI_COMMIT_SHA"); v != "" {
		tag2 := tag1 + "-" + v[0:8]
		releaseTag = tag2
	} else if v := os.Getenv("CI_COMMIT_REF_NAME"); v != "" {
		tag2 := tag1 + "-" + v
		releaseTag = tag2
	} else {
		releaseTag = tag1
	}
	return releaseTag
}

// exists returns a bool as to whether a file path exists.
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// GetTargetEnv checks for an env var that is prefixed with the current target env.
func GetTargetEnv(targetEnv, envName string) string {
	k := fmt.Sprintf("%s_%s", strings.ToUpper(targetEnv), envName)

	if v := os.Getenv(k); v != "" {
		// Set the non prefixed env var with the prefixed value.
		os.Setenv(envName, v)
		return v
	}

	return os.Getenv(envName)
}
