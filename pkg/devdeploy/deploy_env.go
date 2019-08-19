package devdeploy

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

// SetupDeploymentEnv ensures all the resources for the project are setup before deploying a single ECS service or
// Lambda function. This will ensure the following AWS are available for deployment:
// 1. AWS IAM Policy
// 2. AWS S3 buckets
// 3. AWS EC2 VPC
// 4. AWS EC2 Security Group
// 5. AWS Elastic Cache Cluster
// 6. AWS RDS database Cluster
// 7. AWS RDS database Instance
func SetupDeploymentEnv(log *log.Logger, cfg *Config) error {

	log.Printf("Setup deployment environment %s\n", cfg.Env)

	log.Println("\tValidate request.")
	errs := validator.New().Struct(cfg)
	if errs != nil {
		return errs
	}

	// Step 1: Find or create the AWS IAM policy.
	{
		_, err := SetupIamPolicy(log, cfg, cfg.AwsIamPolicy)
		if err != nil {
			return err
		}

		log.Printf("\t%s\tConfigured default service policy.\n", Success)
	}

	// Step 2: Find or create the list of AWS S3 buckets.
	{
		log.Println("\tS3 - Setup Buckets")

		err := SetupS3Buckets(log, cfg, cfg.AwsS3BucketPrivate, cfg.AwsS3BucketPublic)
		if err != nil {
			return err
		}

		log.Printf("\t%s\tS3 buckets configured successfully.\n", Success)
	}

	// Step 3: Find or create the AWS EC2 VPC.
	{
		log.Println("\tEC2 - Find Subnets")

		svc := ec2.New(cfg.AwsSession())

		var subnets []*ec2.Subnet
		if cfg.AwsEc2Vpc.IsDefault {
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
				if cfg.AwsEc2Vpc.VpcId == "" {
					cfg.AwsEc2Vpc.VpcId = *s.VpcId

					log.Printf("\t\tFound VPC: %s", cfg.AwsEc2Vpc.VpcId)

				} else if cfg.AwsEc2Vpc.VpcId != *s.VpcId {
					return errors.Errorf("Invalid subnet %s, all subnets should belong to the same VPC, expected %s, got %s", *s.SubnetId, cfg.AwsEc2Vpc.VpcId, *s.VpcId)
				}
			}
		} else {

			if cfg.AwsEc2Vpc.VpcId != "" {
				log.Printf("\t\tFind VPC '%s'\n", cfg.AwsEc2Vpc.VpcId)

				// Find all subnets that are default for each availability zone.
				err := svc.DescribeVpcsPages(&ec2.DescribeVpcsInput{
					VpcIds: aws.StringSlice([]string{cfg.AwsEc2Vpc.VpcId}),
				}, func(res *ec2.DescribeVpcsOutput, lastPage bool) bool {
					for _, s := range res.Vpcs {
						if *s.VpcId == cfg.AwsEc2Vpc.VpcId {
							cfg.AwsEc2Vpc.result = s
							break
						}
					}
					return !lastPage
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to describe vpc '%s'.", cfg.AwsEc2Vpc.VpcId)
				}
			}

			// If there is no VPC id set and IsDefault is false, a new VPC needs to be created with the given details.
			if cfg.AwsEc2Vpc.result == nil {

				input, err := cfg.AwsEc2Vpc.Input()
				if err != nil {
					return err
				}

				createRes, err := svc.CreateVpc(input)
				if err != nil {
					return errors.Wrap(err, "Failed to create VPC")
				}
				cfg.AwsEc2Vpc.result = createRes.Vpc
				cfg.AwsEc2Vpc.VpcId = *createRes.Vpc.VpcId
				log.Printf("\t\tCreated VPC %s", cfg.AwsEc2Vpc.VpcId)

				err = cfg.Ec2TagResource(*createRes.Vpc.VpcId, "", cfg.AwsEc2Vpc.Tags...)
				if err != nil {
					return errors.Wrapf(err, "Failed to tag vpc '%s'.", cfg.AwsEc2Vpc.VpcId)
				}

			} else {
				log.Println("\t\tFind all subnets for VPC.")

				// Find all subnets that are default for each availability zone.
				err := svc.DescribeSubnetsPages(&ec2.DescribeSubnetsInput{}, func(res *ec2.DescribeSubnetsOutput, lastPage bool) bool {
					for _, s := range res.Subnets {
						if *s.VpcId == cfg.AwsEc2Vpc.VpcId {
							subnets = append(subnets, s)
						}
					}
					return !lastPage
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to find subnets for VPC '%s'", cfg.AwsEc2Vpc.VpcId)
				}
			}

			for _, sn := range cfg.AwsEc2Vpc.Subnets {
				var found bool
				for _, t := range subnets {
					if t.CidrBlock != nil && *t.CidrBlock == sn.CidrBlock {
						found = true
						break
					}
				}

				if !found {
					input, err := sn.Input(cfg.AwsEc2Vpc.VpcId)
					if err != nil {
						return err
					}

					createRes, err := svc.CreateSubnet(input)
					if err != nil {
						return errors.Wrap(err, "Failed to create VPC")
					}
					subnets = append(subnets, createRes.Subnet)

					log.Printf("\t\tCreated Subnet %s", *createRes.Subnet.SubnetId)

					err = cfg.Ec2TagResource(*createRes.Subnet.SubnetId, "", sn.Tags...)
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

		log.Printf("\t\tVPC '%s' has %d subnets", cfg.AwsEc2Vpc.VpcId)
		for _, sn := range subnets {
			cfg.AwsEc2Vpc.subnetIds = append(cfg.AwsEc2Vpc.subnetIds, *sn.SubnetId)
			log.Printf("\t\t\tSubnet: %s", *sn.SubnetId)
		}

		log.Printf("\t%s\tEC2 subnets available\n", Success)
	}

	// Step 4: Find or create  AWS EC2 Security Group.
	var securityGroupId string
	{
		log.Println("\tEC2 - Find Security Group")

		svc := ec2.New(cfg.AwsSession())

		securityGroupName := cfg.AwsEc2SecurityGroup.GroupName

		// Find all the security groups and then parse the group name to get the Id of the security group.
		var runnerSgId string
		err := svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("group-name"),
					Values: aws.StringSlice([]string{securityGroupName, cfg.GitlabRunnerEc2SecurityGroupName}),
				},
			},
		}, func(res *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
			for _, s := range res.SecurityGroups {
				if *s.GroupName == securityGroupName {
					cfg.AwsEc2SecurityGroup.result = s
				} else if *s.GroupName == cfg.GitlabRunnerEc2SecurityGroupName {
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

		if runnerSgId == "" {
			runngerSg := &AwsEc2SecurityGroup{
				GroupName:   cfg.GitlabRunnerEc2SecurityGroupName,
				Description: "Gitlab runners for running CICD.",

				// A list of cost allocation tags to be added to this resource.
				Tags: cfg.AwsEc2SecurityGroup.Tags,
			}

			input, err := runngerSg.Input(cfg.AwsEc2Vpc.VpcId)
			if err != nil {
				return err
			}

			// If no security group was found, create one.
			createRes, err := svc.CreateSecurityGroup(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create security group '%s'", cfg.GitlabRunnerEc2SecurityGroupName)
			}
			runnerSgId = *createRes.GroupId

			ingressInputs := []*ec2.AuthorizeSecurityGroupIngressInput{
				// Allow all services in the security group to access other services.
				&ec2.AuthorizeSecurityGroupIngressInput{
					SourceSecurityGroupName: aws.String(cfg.GitlabRunnerEc2SecurityGroupName),
					GroupId:                 aws.String(runnerSgId),
				},
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
		}

		if cfg.AwsEc2SecurityGroup.result == nil {
			input, err := cfg.AwsEc2SecurityGroup.Input(cfg.AwsEc2Vpc.VpcId)
			if err != nil {
				return err
			}

			// If no security group was found, create one.
			createRes, err := svc.CreateSecurityGroup(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create security group '%s'", securityGroupName)
			}
			cfg.AwsEc2SecurityGroup.result = &ec2.SecurityGroup{
				GroupId:   createRes.GroupId,
				GroupName: input.GroupName,
				VpcId:     input.VpcId,
			}

			log.Printf("\t\tCreated: %s", securityGroupName)

			err = cfg.Ec2TagResource(*createRes.GroupId, "", cfg.AwsEc2SecurityGroup.Tags...)
			if err != nil {
				return errors.Wrapf(err, "Failed to tag security group '%s'.", securityGroupName)
			}
		} else {
			log.Printf("\t\tFound: %s", securityGroupName)
		}

		securityGroupId = *cfg.AwsEc2SecurityGroup.result.GroupId

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
		if cfg.AwsRdsDBCluster != nil || cfg.AwsRdsDBInstance != nil {
			// The gitlab runner security group is required when a db instance is defined.
			if runnerSgId == "" {
				return errors.Errorf("Failed to find security group '%s'", cfg.GitlabRunnerEc2SecurityGroupName)
			}

			// Enable GitLab runner to communicate with deployment created services.
			ingressInputs = append(ingressInputs, &ec2.AuthorizeSecurityGroupIngressInput{
				SourceSecurityGroupName: aws.String(cfg.GitlabRunnerEc2SecurityGroupName),
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

	// Step 5: Find or create the AWS Elastic Cache Cluster.
	if cfg.AwsElasticCacheCluster != nil {
		log.Println("\tElastic Cache - Get or Create Cache Cluster")

		svc := elasticache.New(cfg.AwsSession())

		cacheClusterId := cfg.AwsElasticCacheCluster.CacheClusterId

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
			cfg.AwsElasticCacheCluster.result = cacheCluster
		}

		if cfg.AwsElasticCacheCluster.result == nil {

			input, err := cfg.AwsElasticCacheCluster.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// If no repository was found, create one.
			createRes, err := svc.CreateCacheCluster(input)
			if err != nil {
				return errors.Wrapf(err, "failed to create cluster '%s'", cacheClusterId)
			}
			cacheCluster = createRes.CacheCluster
			cfg.AwsElasticCacheCluster.result = cacheCluster

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
		//_, err = svc.AddTagsToResource(&elasticache.AddTagsToResourceInput{
		//	ResourceName: aws.String(cacheClusterArn),
		//	Tags: []*elasticache.Tag{
		//		{Key: aws.String(AwsTagNameProject), Value: aws.String(cfg.ProjectName)},
		//		{Key: aws.String(AwsTagNameEnv), Value: aws.String(cfg.Env)},
		//	},
		//})
		//if err != nil {
		//	return errors.Wrapf(err, "Failed to tag cache cluster '%s'", cacheClusterId)
		//}

		// If there are custom cache group parameters set, then create a new group and keep them modified.
		if len(cfg.AwsElasticCacheCluster.ParameterNameValues) > 0 {

			customCacheParameterGroupName := fmt.Sprintf("%s-%s%s",
				strings.ToLower(cfg.ProjectNameCamel()),
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

				input, err := cfg.AwsElasticCacheCluster.CacheParameterGroupInput(customCacheParameterGroupName)
				if err != nil {
					return err
				}
				_, err = svc.ModifyCacheParameterGroup(input)
				if err != nil {
					return errors.Wrapf(err, "failed to modify cache parameter group '%s'", *cacheCluster.CacheParameterGroup.CacheParameterGroupName)
				}

				for _, p := range cfg.AwsElasticCacheCluster.ParameterNameValues {
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
				cfg.AwsElasticCacheCluster.result = cacheCluster
			}
		}

		log.Printf("\t%s\tElastic Cache cluster configured for %s\n", Success, *cacheCluster.Engine)
	}

	// Step 6: Find or create the AWS RDS database Cluster.
	// This is only used when service uses Aurora via RDS for serverless Postgres and database cluster is defined.
	// Aurora Postgres is limited to specific AWS regions and thus not used by default.
	// If an Aurora Postgres cluster is defined, ensure it exists with RDS else create a new one.
	if cfg.AwsRdsDBCluster != nil {
		log.Println("\tRDS - Get or Create Database Cluster")

		svc := rds.New(cfg.AwsSession())

		dBClusterIdentifier := cfg.AwsRdsDBCluster.DBClusterIdentifier

		// Secret ID used to store the DB username and password across deploys.
		dbSecretId := cfg.SecretID(filepath.Join("rds", dBClusterIdentifier))

		// Retrieve the current secret value if something is stored.
		{
			sm := secretsmanager.New(cfg.AwsSession())
			res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(dbSecretId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
					return errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
				}
			} else {
				err = json.Unmarshal([]byte(*res.SecretString), &cfg.DBConnInfo)
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
			cfg.AwsRdsDBCluster.result = descRes.DBClusters[0]
		}

		var created bool
		if cfg.AwsRdsDBCluster.result == nil {
			if cfg.DBConnInfo != nil && cfg.DBConnInfo.Pass != "" {
				cfg.AwsRdsDBCluster.MasterUsername = cfg.DBConnInfo.User
				cfg.AwsRdsDBCluster.MasterUserPassword = cfg.DBConnInfo.Pass
			}

			input, err := cfg.AwsRdsDBCluster.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// Store the secret first in the event that create fails.
			if cfg.DBConnInfo == nil {
				// Only set the password right now,
				// all other configuration details will be set after the database instance is created.
				cfg.DBConnInfo = &DBConnInfo{
					Pass: *input.MasterUserPassword,
				}

				// Json encode the db details to be stored as secret text.
				dat, err := json.Marshal(cfg.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Create the new entry in AWS Secret Manager with the database password.
				sm := secretsmanager.New(cfg.AwsSession())
				_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
					Name:         aws.String(dbSecretId),
					SecretString: aws.String(string(dat)),
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create new secret with db credentials")
				}
				log.Printf("\t\tStored Secret\n")
			}

			// If no cluster was found, create one.
			createRes, err := svc.CreateDBCluster(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create cluster '%s'", dBClusterIdentifier)
			}
			cfg.AwsRdsDBCluster.result = createRes.DBCluster
			created = true

			log.Printf("\t\tCreated: %s", *cfg.AwsRdsDBCluster.result.DBClusterArn)
		} else {
			log.Printf("\t\tFound: %s", *cfg.AwsRdsDBCluster.result.DBClusterArn)
		}

		dbCluster := cfg.AwsRdsDBCluster.result

		// The status of the cluster.
		log.Printf("\t\t\tStatus: %s", *dbCluster.Status)

		// Update the secret with the DB cluster details. This happens after DB create to help address when the
		// DB cluster was successfully created, but the secret failed to save. The DB details host should be empty or
		// match the current cluster endpoint.
		curHost := *dbCluster.Endpoint
		if curHost != cfg.DBConnInfo.Host {

			// Copy the cluster details to the DB struct.
			cfg.DBConnInfo.Host = curHost
			cfg.DBConnInfo.User = *dbCluster.MasterUsername
			cfg.DBConnInfo.Database = *dbCluster.DatabaseName
			cfg.DBConnInfo.Driver = *dbCluster.Engine
			cfg.DBConnInfo.DisableTLS = false

			// Json encode the DB details to be stored as text via AWS Secrets Manager.
			dat, err := json.Marshal(cfg.DBConnInfo)
			if err != nil {
				return errors.Wrap(err, "Failed to marshal db credentials")
			}

			// Update the current AWS Secret.
			sm := secretsmanager.New(cfg.AwsSession())
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

		// Execute the post AwsRdsDBCluster method if defined.
		if created && cfg.AwsRdsDBInstance.AfterCreate != nil {
			err = cfg.AwsRdsDBCluster.AfterCreate(dbCluster, cfg.DBConnInfo)
			if err != nil {
				return err
			}
		}

		log.Printf("\t%s\tDB Cluster available\n", Success)
	}

	// Step 7: Find or create the AWS RDS database Instance.
	// Regardless if deployment is using Aurora or not, still need to setup database instance.
	// If a database instance is defined, then ensure it exists with RDS in else create a new one.
	if cfg.AwsRdsDBInstance != nil {
		log.Println("\tRDS - Get or Create Database Instance")

		dBInstanceIdentifier := cfg.AwsRdsDBInstance.DBInstanceIdentifier

		// Secret ID used to store the DB username and password across deploys.
		dbSecretId := cfg.SecretID(filepath.Join("rds", dBInstanceIdentifier))

		// Retrieve the current secret value if something is stored.
		{
			sm := secretsmanager.New(cfg.AwsSession())
			res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(dbSecretId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
					return errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
				}
			} else {
				err = json.Unmarshal([]byte(*res.SecretString), &cfg.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to json decode db credentials")
				}
			}
		}

		// Init a new RDS client.
		svc := rds.New(cfg.AwsSession())

		// Try to find an existing DB instance with the same identifier.
		descRes, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(dBInstanceIdentifier),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBInstanceNotFoundFault {
				return errors.Wrapf(err, "Failed to describe database instance '%s'", dBInstanceIdentifier)
			}
		} else if len(descRes.DBInstances) > 0 {
			cfg.AwsRdsDBInstance.result = descRes.DBInstances[0]
		}

		// No DB instance was found, so create a new one.
		var created bool
		if cfg.AwsRdsDBInstance.result == nil {

			if cfg.DBConnInfo != nil && cfg.DBConnInfo.Pass != "" {
				cfg.AwsRdsDBInstance.MasterUsername = cfg.DBConnInfo.User
				cfg.AwsRdsDBInstance.MasterUserPassword = cfg.DBConnInfo.Pass
			}

			if cfg.AwsRdsDBCluster != nil {
				cfg.AwsRdsDBInstance.DBClusterIdentifier = aws.String(cfg.AwsRdsDBCluster.DBClusterIdentifier)
			}

			input, err := cfg.AwsRdsDBInstance.Input([]string{securityGroupId})
			if err != nil {
				return err
			}

			// Only store the db password for the instance when no cluster is defined.
			// Store the secret first in the event that create fails.
			if cfg.AwsRdsDBCluster == nil && cfg.DBConnInfo == nil {
				cfg.DBConnInfo = &DBConnInfo{
					Pass: *input.MasterUserPassword,
				}

				// Json encode the db details to be stored as secret text.
				dat, err := json.Marshal(cfg.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Create the new entry in AWS Secret Manager with the database password.
				sm := secretsmanager.New(cfg.AwsSession())
				_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
					Name:         aws.String(dbSecretId),
					SecretString: aws.String(string(dat)),
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create new secret with db credentials")
				}
				log.Printf("\t\tStored Secret\n")
			}

			// If no instance was found, create one.
			createRes, err := svc.CreateDBInstance(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create instance '%s'", dBInstanceIdentifier)
			}
			cfg.AwsRdsDBInstance.result = createRes.DBInstance
			created = true

			log.Printf("\t\tCreated: %s", *cfg.AwsRdsDBInstance.result.DBInstanceArn)
		} else {
			log.Printf("\t\tFound: %s", *cfg.AwsRdsDBInstance.result.DBInstanceArn)
		}

		dbInstance := cfg.AwsRdsDBInstance.result

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

			// Try to find an existing DB instance with the same identifier.
			descRes, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
				DBInstanceIdentifier: aws.String(dBInstanceIdentifier),
			})
			if err != nil {
				return errors.Wrapf(err, "Failed to describe database instance '%s'", dBInstanceIdentifier)
			} else if len(descRes.DBInstances) > 0 {
				dbInstance = descRes.DBInstances[0]
			}
		}

		// If a database cluster is not defined, update the database details with the current instance.
		if cfg.AwsRdsDBCluster == nil {
			// Update the secret with the DB instance details. This happens after DB create to help address when the
			// DB instance was successfully created, but the secret failed to save. The DB details host should be empty or
			// match the current instance endpoint.
			curHost := fmt.Sprintf("%s:%d", *dbInstance.Endpoint.Address, *dbInstance.Endpoint.Port)
			if curHost != cfg.DBConnInfo.Host {

				// Copy the instance details to the DB struct.
				cfg.DBConnInfo.Host = curHost
				cfg.DBConnInfo.User = *dbInstance.MasterUsername
				cfg.DBConnInfo.Database = *dbInstance.DBName
				cfg.DBConnInfo.Driver = *dbInstance.Engine
				cfg.DBConnInfo.DisableTLS = false

				// Json encode the DB details to be stored as text via AWS Secrets Manager.
				dat, err := json.Marshal(cfg.DBConnInfo)
				if err != nil {
					return errors.Wrap(err, "Failed to marshal db credentials")
				}

				// Update the current AWS Secret.
				sm := secretsmanager.New(cfg.AwsSession())
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

		cfg.AwsRdsDBInstance.result = dbInstance

		// Execute the post created method if defined.
		if created && cfg.AwsRdsDBInstance.AfterCreate != nil {
			err = cfg.AwsRdsDBInstance.AfterCreate(dbInstance, cfg.DBConnInfo)
			if err != nil {
				return err
			}
		}

		log.Printf("\t%s\tDB Instance available\n", Success)
	}

	return nil
}

func SetupIamPolicy(log *log.Logger, cfg *Config, targetPolicy *AwsIamPolicy) (*iam.Policy, error) {

	svc := iam.New(cfg.AwsSession())

	policyName := targetPolicy.PolicyName

	log.Printf("\tFind default service policy %s.", policyName)

	var policy *iam.Policy
	err := svc.ListPoliciesPages(&iam.ListPoliciesInput{}, func(res *iam.ListPoliciesOutput, lastPage bool) bool {
		for _, p := range res.Policies {
			if *p.PolicyName == policyName {
				policy = p
				return false
			}
		}

		return !lastPage
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list IAM policies")
	}

	if policy != nil {
		log.Printf("\t\t\tFound policy '%s' versionId '%s'", *policy.Arn, *policy.DefaultVersionId)

		res, err := svc.GetPolicyVersion(&iam.GetPolicyVersionInput{
			PolicyArn: policy.Arn,
			VersionId: policy.DefaultVersionId,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != iam.ErrCodeNoSuchEntityException {
				return nil, errors.Wrapf(err, "Failed to read policy '%s' version '%s'", policyName, *policy.DefaultVersionId)
			}
		}

		// The policy document returned in this structure is URL-encoded compliant with
		// RFC 3986 (https://tools.ietf.org/html/rfc3986). You can use a URL decoding
		// method to convert the policy back to plain JSON text.
		curJson, err := url.QueryUnescape(*res.PolicyVersion.Document)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to url unescape policy document - %s", string(*res.PolicyVersion.Document))
		}

		// Compare policy documents and add any missing actions for each statement by matching Sid.
		var curDoc AwsIamPolicyDocument
		err = json.Unmarshal([]byte(curJson), &curDoc)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to json decode policy document - %s", string(curJson))
		}

		var updateDoc bool
		for _, baseStmt := range targetPolicy.PolicyDocument.Statement {
			var found bool
			for curIdx, curStmt := range curDoc.Statement {
				if baseStmt.Sid != curStmt.Sid {
					continue
				}

				found = true

				for _, baseAction := range baseStmt.Action {
					var hasAction bool
					for _, curAction := range curStmt.Action {
						if baseAction == curAction {
							hasAction = true
							break
						}
					}

					if !hasAction {
						log.Printf("\t\t\t\tAdded new action %s for '%s'", curStmt.Sid)
						curStmt.Action = append(curStmt.Action, baseAction)
						curDoc.Statement[curIdx] = curStmt
						updateDoc = true
					}
				}
			}

			if !found {
				log.Printf("\t\t\t\tAdded new statement '%s'", baseStmt.Sid)
				curDoc.Statement = append(curDoc.Statement, baseStmt)
				updateDoc = true
			}
		}

		if updateDoc {
			dat, err := json.Marshal(curDoc)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to json encode policy document")
			}

			res, err := svc.CreatePolicyVersion(&iam.CreatePolicyVersionInput{
				PolicyArn:      policy.Arn,
				PolicyDocument: aws.String(string(dat)),
				SetAsDefault:   aws.Bool(true),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != iam.ErrCodeNoSuchEntityException {
					return nil, errors.Wrapf(err, "Failed to read policy '%s' version '%s'", policyName, *policy.DefaultVersionId)
				}
			}
			policy.DefaultVersionId = res.PolicyVersion.VersionId
		}

	} else {
		input, err := targetPolicy.Input()
		if err != nil {
			return nil, err
		}

		// If no repository was found, create one.
		res, err := svc.CreatePolicy(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create task policy '%s'", policyName)
		}
		policy = res.Policy

		log.Printf("\t\t\tCreated policy '%s'", *res.Policy.Arn)
	}

	targetPolicy.result = policy

	return policy, nil
}

func SetupIamRole(log *log.Logger, cfg *Config, targetRole *AwsIamRole, policyArns ...string) (*iam.Role, error) {
	svc := iam.New(cfg.AwsSession())

	roleName := targetRole.RoleName

	res, err := svc.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != iam.ErrCodeNoSuchEntityException {
			return nil, errors.Wrapf(err, "Failed to find task role '%s'", roleName)
		}
	}

	var role *iam.Role
	if res.Role != nil {
		role = res.Role
		log.Printf("\t\t\tFound role '%s'", *role.Arn)
	} else {
		input, err := targetRole.Input()
		if err != nil {
			return nil, err
		}

		// If no role was found, create one.
		res, err := svc.CreateRole(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create task role '%s'", roleName)
		}
		role = res.Role

		log.Printf("\t\t\tCreated role '%s'", *role.Arn)

		//_, err = svc.UpdateAssumeRolePolicy(&iam.UpdateAssumeRolePolicyInput{
		//	PolicyDocument: ,
		//	RoleName:       aws.String(roleName),
		//})
		//if err != nil {
		//	return errors.Wrapf(err, "failed to create task role '%s'", roleName)
		//}
	}
	targetRole.result = role

	for _, policyArn := range policyArns {
		_, err = svc.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to attach policy '%s' to task role '%s'", policyArn, roleName)
		}

		log.Printf("\t\t\tRole attached policy %s.\n", policyArn)
	}

	return role, nil
}

// SetupS3Buckets handles configuring s3 buckets.
func SetupS3Buckets(log *log.Logger, cfg *Config, s3Buckets ...*AwsS3Bucket) error {
	svc := s3.New(cfg.AwsSession())

	for _, s3Bucket := range s3Buckets {
		bucketName := s3Bucket.BucketName

		_, err := svc.HeadBucket(&s3.HeadBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != s3.ErrCodeNoSuchBucket {
				return errors.Wrapf(err, "failed to find s3 bucket '%s'", bucketName)
			}

			// If the bucket was not found, create it.
			input, err := s3Bucket.Input()
			if err != nil {
				return err
			}

			_, err = svc.CreateBucket(input)
			if err != nil {
				return errors.Wrapf(err, "failed to create s3 bucket '%s'", bucketName)
			}
			log.Printf("\t\tCreated: %s\n", bucketName)
		} else {

			log.Printf("\t\tFound: %s\n", bucketName)
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

			bucketLoc := cfg.AwsCredentials.Region
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

			_, err = cloudfront.New(cfg.AwsSession()).CreateDistribution(input)
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
