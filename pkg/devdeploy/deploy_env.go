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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

/*
	// Register informs the sqlxtrace package of the driver that we will be using in our program.
	// It uses a default service name, in the below case "postgres.db". To use a custom service
	// name use RegisterWithServiceName.
	sqltrace.Register(db.Driver, &pq.Driver{}, sqltrace.WithServiceName("devops:migrate"))
	masterDb, err := sqlxtrace.Open(db.Driver, db.URL())
	if err != nil {
		return errors.WithStack(err)
	}
	defer masterDb.Close()

	// Start the database migrations.
	log.Printf("\t\tStart migrations.")
	if err = schema.Migrate(masterDb, log, false); err != nil {
		return errors.WithStack(err)
	}
	log.Printf("\t\tFinished migrations.")
*/

// ProjectNameCamel takes a project name and returns the camel cased version.
func (devEnv *DeploymentEnv) ProjectNameCamel() string {
	s := strings.Replace(devEnv.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
}

// SecretID returns the secret name with a standard prefix.
func (devEnv *DeploymentEnv) SecretID(secretName string) string {
	return filepath.Join(devEnv.ProjectName, devEnv.Env, secretName)
}

// AwsSession returns the AWS session based on the defined credentials.
func (devEnv *DeploymentEnv) AwsSession() *session.Session {
	return devEnv.AwsCredentials.Session()
}

// Ec2TagResource is ah elper function to tag EC2 resources.
func (devEnv *DeploymentEnv) Ec2TagResource(resource, name string, tags ...*ec2.Tag) error {
	svc := ec2.New(devEnv.AwsSession())

	ec2Tags := []*ec2.Tag{
		{Key: aws.String(AwsTagNameProject), Value: aws.String(devEnv.ProjectName)},
		{Key: aws.String(AwsTagNameEnv), Value: aws.String(devEnv.Env)},
	}

	if name != "" {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameName), Value: aws.String(name)})
	}

	if tags != nil {
		for _, t := range tags {
			ec2Tags = append(ec2Tags, t)
		}
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
// 1. AWS ECR repository
// 2. AWS EC2 VPC
// 3. AWS EC2 Security Group
// 4. AWS S3 buckets
// 5. AWS Elastic Cache Cluster
// 6. AWS RDS database Cluster
// 7. AWS RDS database Instance
func SetupDeploymentEnv(log *log.Logger, devEnv *DeploymentEnv) error {

	log.Println("Setup Deployment Environment")

	log.Println("\tValidate request.")
	errs := validator.New().Struct(devEnv)
	if errs != nil {
		return errs
	}

	// Step 1: Find or create the AWS ECR repository.
	{
		log.Println("\tECR - Get or create repository")

		svc := ecr.New(devEnv.AwsSession())

		repositoryName := devEnv.AwsEcrRepository.RepositoryName

		descRes, err := svc.DescribeRepositories(&ecr.DescribeRepositoriesInput{
			RepositoryNames: []*string{aws.String(repositoryName)},
		})
		if err != nil {
			// The repository should have been created by build or manually created and should exist at this point.
			return errors.Wrapf(err, "Failed to describe repository '%s'.", repositoryName)
		} else if len(descRes.Repositories) > 0 {
			devEnv.AwsEcrRepository.result = descRes.Repositories[0]
		}

		if devEnv.AwsEcrRepository.result == nil {
			input, err := devEnv.AwsEcrRepository.Input()
			if err != nil {
				return err
			}

			// If no repository was found, create one.
			createRes, err := svc.CreateRepository(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create repository '%s'", repositoryName)
			}
			devEnv.AwsEcrRepository.result = createRes.Repository
			log.Printf("\t\tCreated: %s", *devEnv.AwsEcrRepository.result.RepositoryArn)
		} else {
			log.Printf("\t\tFound: %s", *devEnv.AwsEcrRepository.result.RepositoryArn)

			log.Println("\t\tChecking old ECR images.")
			maxImages := devEnv.AwsEcrRepository.MaxImages
			if maxImages == 0 || maxImages > AwsRegistryMaximumImages {
				maxImages = AwsRegistryMaximumImages
			}
			delIds, err := EcrPurgeImages(devEnv.AwsCredentials, repositoryName, maxImages)
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

		log.Printf("\t%s\tECR Respository available\n", Success)
	}

	// Step 2: Find or create the AWS EC2 VPC.
	{
		log.Println("\tEC2 - Find Subnets")

		svc := ec2.New(devEnv.AwsSession())

		var subnets []*ec2.Subnet
		if devEnv.AwsEc2Vpc.IsDefault {
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
				if devEnv.AwsEc2Vpc.VpcId == "" {
					devEnv.AwsEc2Vpc.VpcId = *s.VpcId

					log.Printf("\t\tFound VPC: %s", devEnv.AwsEc2Vpc.VpcId)

				} else if devEnv.AwsEc2Vpc.VpcId != *s.VpcId {
					return errors.Errorf("Invalid subnet %s, all subnets should belong to the same VPC, expected %s, got %s", *s.SubnetId, devEnv.AwsEc2Vpc.VpcId, *s.VpcId)
				}
			}
		} else {

			if devEnv.AwsEc2Vpc.VpcId != "" {
				log.Printf("\t\tFind VPC '%s'\n", devEnv.AwsEc2Vpc.VpcId)

				// Find all subnets that are default for each availability zone.
				err := svc.DescribeVpcsPages(&ec2.DescribeVpcsInput{
					VpcIds: aws.StringSlice([]string{devEnv.AwsEc2Vpc.VpcId}),
				}, func(res *ec2.DescribeVpcsOutput, lastPage bool) bool {
					for _, s := range res.Vpcs {
						if *s.VpcId == devEnv.AwsEc2Vpc.VpcId {
							devEnv.AwsEc2Vpc.result = s
							break
						}
					}
					return !lastPage
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to describe vpc '%s'.", devEnv.AwsEc2Vpc.VpcId)
				}
			}

			// If there is no VPC id set and IsDefault is false, a new VPC needs to be created with the given details.
			if devEnv.AwsEc2Vpc.result == nil {

				input, err := devEnv.AwsEc2Vpc.Input()
				if err != nil {
					return err
				}

				createRes, err := svc.CreateVpc(input)
				if err != nil {
					return errors.Wrap(err, "Failed to create VPC")
				}
				devEnv.AwsEc2Vpc.result = createRes.Vpc
				devEnv.AwsEc2Vpc.VpcId = *createRes.Vpc.VpcId
				log.Printf("\t\tCreated VPC %s", devEnv.AwsEc2Vpc.VpcId)

				err = devEnv.Ec2TagResource(*createRes.Vpc.VpcId, "")
				if err != nil {
					return errors.Wrapf(err, "Failed to tag vpc '%s'.", devEnv.AwsEc2Vpc.VpcId)
				}

			} else {
				log.Println("\t\tFind all subnets for VPC.")

				// Find all subnets that are default for each availability zone.
				err := svc.DescribeSubnetsPages(&ec2.DescribeSubnetsInput{}, func(res *ec2.DescribeSubnetsOutput, lastPage bool) bool {
					for _, s := range res.Subnets {
						if *s.VpcId == devEnv.AwsEc2Vpc.VpcId {
							subnets = append(subnets, s)
						}
					}
					return !lastPage
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to find subnets for VPC '%s'", devEnv.AwsEc2Vpc.VpcId)
				}
			}

			for _, sn := range devEnv.AwsEc2Vpc.Subnets {
				var found bool
				for _, t := range subnets {
					if t.CidrBlock != nil && *t.CidrBlock == sn.CidrBlock {
						found = true
						break
					}
				}

				if !found {
					input, err := sn.Input(devEnv.AwsEc2Vpc.VpcId)
					if err != nil {
						return err
					}

					createRes, err := svc.CreateSubnet(input)
					if err != nil {
						return errors.Wrap(err, "Failed to create VPC")
					}
					subnets = append(subnets, createRes.Subnet)

					log.Printf("\t\tCreated Subnet %s", *createRes.Subnet.SubnetId)

					err = devEnv.Ec2TagResource(*createRes.Subnet.SubnetId, "")
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

		log.Printf("\t\tVPC '%s' has %d subnets", devEnv.AwsEc2Vpc.VpcId)
		for _, sn := range subnets {
			devEnv.AwsEc2Vpc.subnetIds = append(devEnv.AwsEc2Vpc.subnetIds, *sn.SubnetId)
			log.Printf("\t\t\tSubnet: %s", *sn.SubnetId)
		}

		log.Printf("\t%s\tEC2 subnets available\n", Success)
	}

	// Step 3: Find or create  AWS EC2 Security Group.
	var securityGroupId string
	{
		log.Println("\tEC2 - Find Security Group")

		svc := ec2.New(devEnv.AwsSession())

		securityGroupName := devEnv.AwsEc2SecurityGroup.GroupName

		// Find all the security groups and then parse the group name to get the Id of the security group.
		var runnerSgId string
		err := svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
			GroupNames: aws.StringSlice([]string{securityGroupName, devEnv.GitlabRunnerEc2SecurityGroupName}),
		}, func(res *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
			for _, s := range res.SecurityGroups {
				if *s.GroupName == securityGroupName {
					devEnv.AwsEc2SecurityGroup.result = s
				} else if *s.GroupName == devEnv.GitlabRunnerEc2SecurityGroupName {
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

		if devEnv.AwsEc2SecurityGroup.result == nil {
			input, err := devEnv.AwsEc2SecurityGroup.Input(devEnv.AwsEc2Vpc.VpcId)
			if err != nil {
				return err
			}

			// If no security group was found, create one.
			createRes, err := svc.CreateSecurityGroup(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create security group '%s'", securityGroupName)
			}
			devEnv.AwsEc2SecurityGroup.result = &ec2.SecurityGroup{
				GroupId:   createRes.GroupId,
				GroupName: input.GroupName,
				VpcId:     input.VpcId,
			}

			log.Printf("\t\tCreated: %s", securityGroupName)

			err = devEnv.Ec2TagResource(*createRes.GroupId, "")
			if err != nil {
				return errors.Wrapf(err, "Failed to tag security group '%s'.", securityGroupName)
			}
		} else {
			log.Printf("\t\tFound: %s", securityGroupName)
		}

		securityGroupId = *devEnv.AwsEc2SecurityGroup.result.GroupId

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
		if devEnv.AwsRdsDBCluster != nil || devEnv.AwsRdsDBInstance != nil {
			// The gitlab runner security group is required when a db instance is defined.
			if runnerSgId == "" {
				return errors.Errorf("Failed to find security group '%s'", devEnv.GitlabRunnerEc2SecurityGroupName)
			}

			// Enable GitLab runner to communicate with deployment created services.
			ingressInputs = append(ingressInputs, &ec2.AuthorizeSecurityGroupIngressInput{
				SourceSecurityGroupName: aws.String(devEnv.GitlabRunnerEc2SecurityGroupName),
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

	// Step 4: Find or create the list of AWS S3 buckets.
	{
		log.Println("\tS3 - Setup Buckets")

		svc := s3.New(devEnv.AwsSession())

		s3Buckets := []*AwsS3Bucket{
			devEnv.AwsS3BucketPrivate,
			devEnv.AwsS3BucketPublic,
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

				bucketLoc := devEnv.AwsCredentials.Region
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

				_, err = cloudfront.New(devEnv.AwsSession()).CreateDistribution(input)
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

	// Step 5: Find or create the AWS Elastic Cache Cluster.
	if devEnv.AwsElasticCacheCluster != nil {
		log.Println("\tElastic Cache - Get or Create Cache Cluster")

		svc := elasticache.New(devEnv.AwsSession())

		cacheClusterId := devEnv.AwsElasticCacheCluster.CacheClusterId

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
			devEnv.AwsElasticCacheCluster.result = cacheCluster
		}

		if devEnv.AwsElasticCacheCluster.result == nil {

			input, err := devEnv.AwsElasticCacheCluster.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no repository was found, create one.
			createRes, err := svc.CreateCacheCluster(input)
			if err != nil {
				return errors.Wrapf(err, "failed to create cluster '%s'", cacheClusterId)
			}
			cacheCluster = createRes.CacheCluster
			devEnv.AwsElasticCacheCluster.result = cacheCluster

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
				{Key: aws.String(AwsTagNameProject), Value: aws.String(devEnv.ProjectName)},
				{Key: aws.String(AwsTagNameEnv), Value: aws.String(devEnv.Env)},
			},
		})
		if err != nil {
			return errors.Wrapf(err, "Failed to tag cache cluster '%s'", cacheClusterId)
		}

		// If there are custom cache group parameters set, then create a new group and keep them modified.
		if len(devEnv.AwsElasticCacheCluster.ParameterNameValues) > 0 {

			customCacheParameterGroupName := fmt.Sprintf("%s-%s%s",
				strings.ToLower(devEnv.ProjectNameCamel()),
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

				input, err := devEnv.AwsElasticCacheCluster.CacheParameterGroupInput(customCacheParameterGroupName)
				if err != nil {
					return err
				}
				_, err = svc.ModifyCacheParameterGroup(input)
				if err != nil {
					return errors.Wrapf(err, "failed to modify cache parameter group '%s'", *cacheCluster.CacheParameterGroup.CacheParameterGroupName)
				}

				for _, p := range devEnv.AwsElasticCacheCluster.ParameterNameValues {
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
				devEnv.AwsElasticCacheCluster.result = cacheCluster
			}
		}

		log.Printf("\t%s\tElastic Cache cluster configured for %s\n", Success, *cacheCluster.Engine)
	}

	// Step 6: Find or create the AWS RDS database Cluster.
	// This is only used when service uses Aurora via RDS for serverless Postgres and database cluster is defined.
	// Aurora Postgres is limited to specific AWS regions and thus not used by default.
	// If an Aurora Postgres cluster is defined, ensure it exists with RDS else create a new one.
	if devEnv.AwsRdsDBCluster != nil {
		log.Println("\tRDS - Get or Create Database Cluster")

		svc := rds.New(devEnv.AwsSession())

		dBClusterIdentifier := devEnv.AwsRdsDBCluster.DBClusterIdentifier

		// Secret ID used to store the DB username and password across deploys.
		dbSecretId := devEnv.SecretID(dBClusterIdentifier)

		// Retrieve the current secret value if something is stored.
		{
			sm := secretsmanager.New(devEnv.AwsSession())
			res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(dbSecretId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
					return errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
				}
			} else {
				err = json.Unmarshal([]byte(*res.SecretString), &devEnv.DBConnInfo)
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
			devEnv.AwsRdsDBCluster.result = descRes.DBClusters[0]
		}

		if devEnv.AwsRdsDBCluster.result == nil {
			if devEnv.DBConnInfo != nil && devEnv.DBConnInfo.Pass != "" {
				devEnv.AwsRdsDBCluster.MasterUserPassword = devEnv.DBConnInfo.User
				devEnv.AwsRdsDBCluster.MasterUserPassword = devEnv.DBConnInfo.Pass
			}

			// Store the secret first in the event that create fails.
			if devEnv.DBConnInfo == nil {
				// Only set the password right now,
				// all other configuration details will be set after the database instance is created.
				devEnv.DBConnInfo = &DBConnInfo{
					Pass: devEnv.AwsRdsDBCluster.MasterUserPassword,
				}

				// Json encode the db details to be stored as secret text.
				dat, err := json.Marshal(devEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Create the new entry in AWS Secret Manager with the database password.
				sm := secretsmanager.New(devEnv.AwsSession())
				_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
					Name:         aws.String(dbSecretId),
					SecretString: aws.String(string(dat)),
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create new secret with db credentials")
				}
				log.Printf("\t\tStored Secret\n")
			}

			input, err := devEnv.AwsRdsDBCluster.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no cluster was found, create one.
			createRes, err := svc.CreateDBCluster(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create cluster '%s'", dBClusterIdentifier)
			}
			devEnv.AwsRdsDBCluster.result = createRes.DBCluster

			log.Printf("\t\tCreated: %s", *devEnv.AwsRdsDBCluster.result.DBClusterArn)
		} else {
			log.Printf("\t\tFound: %s", *devEnv.AwsRdsDBCluster.result.DBClusterArn)
		}

		dbCluster := *devEnv.AwsRdsDBCluster.result

		// The status of the cluster.
		log.Printf("\t\t\tStatus: %s", *dbCluster.Status)

		// Update the secret with the DB cluster details. This happens after DB create to help address when the
		// DB cluster was successfully created, but the secret failed to save. The DB details host should be empty or
		// match the current cluster endpoint.
		curHost := *dbCluster.Endpoint
		if curHost != devEnv.DBConnInfo.Host {

			// Copy the cluster details to the DB struct.
			devEnv.DBConnInfo.Host = curHost
			devEnv.DBConnInfo.User = *dbCluster.MasterUsername
			devEnv.DBConnInfo.Database = *dbCluster.DatabaseName
			devEnv.DBConnInfo.Driver = *dbCluster.Engine
			devEnv.DBConnInfo.DisableTLS = false

			// Json encode the DB details to be stored as text via AWS Secrets Manager.
			dat, err := json.Marshal(devEnv.DBConnInfo)
			if err != nil {
				return errors.Wrap(err, "Failed to marshal db credentials")
			}

			// Update the current AWS Secret.
			sm := secretsmanager.New(devEnv.AwsSession())
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

	// Step 7: Find or create the AWS RDS database Instance.
	// Regardless if deployment is using Aurora or not, still need to setup database instance.
	// If a database instance is defined, then ensure it exists with RDS in else create a new one.
	if devEnv.AwsRdsDBInstance != nil {
		log.Println("\tRDS - Get or Create Database Instance")

		dBInstanceIdentifier := devEnv.AwsRdsDBInstance.DBInstanceIdentifier

		// Secret ID used to store the DB username and password across deploys.
		dbSecretId := devEnv.SecretID(dBInstanceIdentifier)

		// Retrieve the current secret value if something is stored.
		{
			sm := secretsmanager.New(devEnv.AwsSession())
			res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(dbSecretId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
					return errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
				}
			} else {
				err = json.Unmarshal([]byte(*res.SecretString), &devEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to json decode db credentials")
				}
			}
		}

		// Init a new RDS client.
		svc := rds.New(devEnv.AwsSession())

		// Try to find an existing DB instance with the same identifier.
		descRes, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(dBInstanceIdentifier),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBInstanceNotFoundFault {
				return errors.Wrapf(err, "Failed to describe database instance '%s'", dBInstanceIdentifier)
			}
		} else if len(descRes.DBInstances) > 0 {
			devEnv.AwsRdsDBInstance.result = descRes.DBInstances[0]
		}

		// No DB instance was found, so create a new one.
		if devEnv.AwsRdsDBInstance.result == nil {

			if devEnv.DBConnInfo != nil && devEnv.DBConnInfo.Pass != "" {
				devEnv.AwsRdsDBCluster.MasterUserPassword = devEnv.DBConnInfo.User
				devEnv.AwsRdsDBCluster.MasterUserPassword = devEnv.DBConnInfo.Pass
			}

			if devEnv.AwsRdsDBCluster != nil {
				devEnv.AwsRdsDBInstance.DBClusterIdentifier = aws.String(devEnv.AwsRdsDBCluster.DBClusterIdentifier)
			} else {
				// Only store the db password for the instance when no cluster is defined.
				// Store the secret first in the event that create fails.
				if devEnv.DBConnInfo == nil {
					// Only set the password right now,
					// all other configuration details will be set after the database instance is created.
					devEnv.DBConnInfo = &DBConnInfo{
						Pass: devEnv.AwsRdsDBCluster.MasterUserPassword,
					}

					// Json encode the db details to be stored as secret text.
					dat, err := json.Marshal(devEnv.DBConnInfo)
					if err != nil {
						return errors.Wrap(err, "Failed to marshal db credentials")
					}

					// Create the new entry in AWS Secret Manager with the database password.
					sm := secretsmanager.New(devEnv.AwsSession())
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

			input, err := devEnv.AwsRdsDBInstance.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no instance was found, create one.
			createRes, err := svc.CreateDBInstance(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create instance '%s'", dBInstanceIdentifier)
			}
			devEnv.AwsRdsDBInstance.result = createRes.DBInstance

			log.Printf("\t\tCreated: %s", *devEnv.AwsRdsDBInstance.result.DBInstanceArn)
		} else {
			log.Printf("\t\tFound: %s", *devEnv.AwsRdsDBInstance.result.DBInstanceArn)
		}

		dbInstance := *devEnv.AwsRdsDBInstance.result

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
		if devEnv.AwsRdsDBCluster == nil {
			// Update the secret with the DB instance details. This happens after DB create to help address when the
			// DB instance was successfully created, but the secret failed to save. The DB details host should be empty or
			// match the current instance endpoint.
			curHost := fmt.Sprintf("%s:%d", *dbInstance.Endpoint.Address, *dbInstance.Endpoint.Port)
			if curHost != devEnv.DBConnInfo.Host {

				// Copy the instance details to the DB struct.
				devEnv.DBConnInfo.Host = curHost
				devEnv.DBConnInfo.User = *dbInstance.MasterUsername
				devEnv.DBConnInfo.Database = *dbInstance.DBName
				devEnv.DBConnInfo.Driver = *dbInstance.Engine
				devEnv.DBConnInfo.DisableTLS = false

				// Json encode the DB details to be stored as text via AWS Secrets Manager.
				dat, err := json.Marshal(devEnv.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Update the current AWS Secret.
				sm := secretsmanager.New(devEnv.AwsSession())
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

// getTargetEnv checks for an env var that is prefixed with the current target env.
func GetTargetEnv(targetEnv, envName string) string {
	k := fmt.Sprintf("%s_%s", strings.ToUpper(targetEnv), envName)

	if v := os.Getenv(k); v != "" {
		// Set the non prefixed env var with the prefixed value.
		os.Setenv(envName, v)
		return v
	}

	return os.Getenv(envName)
}
