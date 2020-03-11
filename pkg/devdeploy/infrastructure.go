package devdeploy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/iancoleman/strcase"
	"github.com/jmoiron/sqlx"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"gitlab.com/geeks-accelerator/oss/devops/internal/retry"
	"gopkg.in/go-playground/validator.v9"
)

type SetupOption int

const (
	// SetupOptionBuildEnv ensures only the resources are available for the build stage.
	SetupOptionBuildEnv SetupOption = iota
	SetupOptionSkipCache
)

type SetupOptions []SetupOption

// Infrastructure defines all the resources used for build and deploy of functions and services.
type Infrastructure struct {
	// secretID is the key path used to store an instance of this in Aws Secrets Manager.
	secretID string

	// skipCache is a flag to bypass the cached copy of a single resource and reload it from the provider.
	skipCache bool

	// awsCredentials defines the credentials used to access AWS services.
	awsCredentials AwsCredentials `json:"-"`

	// The target env for infrastructure.
	Env string

	// ProjectName will be used for prefixing AWS resources.
	ProjectName string

	// AwsEcrRepository defines the name of the ECR repository and details needed to create if does not exist.
	AwsEcrRepository map[string]*AwsEcrRepositoryResult

	// AwsIamPolicy defines the name of the iam policy that will be attached to ecs tasks and functions.
	AwsIamPolicy map[string]*AwsIamPolicyResult

	// AwsIamRole defines the name of the iam policy that will be attached to ecs tasks and functions.
	AwsIamRole map[string]*AwsIamRoleResult

	// AwsS3Buckets defines both the public and private S3 buckets.
	AwsS3Buckets map[string]*AwsS3BucketResult

	// AwsEc2Vpc defines the name of the VPC and details needed to create if does not exist.
	AwsEc2Vpc map[string]*AwsEc2VpcResult

	// AwsEc2SecurityGroup defines the name of the EC2 security group and details needed to create if does not exist.
	AwsEc2SecurityGroup map[string]*AwsEc2SecurityGroupResult

	// AwsElasticCacheCluster defines the name of the cache cluster and the details needed to create if does not exist.
	AwsElasticCacheCluster map[string]*AwsElasticCacheClusterResult

	// AwsRdsDBCluster defines the name of the rds cluster and the details needed to create if does not exist.
	// This is only needed for Aurora storage engine.
	AwsRdsDBCluster map[string]*AwsRdsDBClusterResult

	// AwsRdsDBInstance defines the name of the rds database instance and the detailed needed to create doesn't exist.
	AwsRdsDBInstance map[string]*AwsRdsDBInstanceResult

	// AwsEcsCluster defines the name of the ecs cluster and the details needed to create doesn't exist.
	AwsEcsCluster map[string]*AwsEcsClusterResult

	// AwsEcsService defines the name of the ecs service and the details needed to create doesn't exist.
	AwsEcsService map[string]*AwsEcsServiceResult

	// AwsCloudWatchLogGroup defines the name of the cloudwatch log group that will be used to store logs for the ECS
	// task.
	AwsCloudWatchLogGroup map[string]*AwsCloudWatchLogGroupResult

	// AwsElbLoadBalancer defines if the service should use an elastic load balancer.
	AwsElbLoadBalancer map[string]*AwsElbLoadBalancerResult

	// AwsSdPrivateDnsNamespace defines the name of the service discovery group and the details needed to create if
	// it does not exist with the associated services.
	AwsSdPrivateDnsNamespace map[string]*AwsSdPrivateDnsNamespaceResult

	// AwsRoute53Zone defines the Route 53 zones.
	AwsRoute53Zone map[string]*AwsRoute53ZoneResult

	// AwsAcmCertificate defines the ACM certificates.
	AwsAcmCertificate map[string]*AwsAcmCertificateResult

	// AwsCloudwatchEventRule defines the Cloudwatch Event rules.
	AwsCloudwatchEventRule map[string]*AwsCloudwatchEventRuleResult

	// AwsAppAutoscalingPolicy defines the Application Autoscaling policies.
	AwsAppAutoscalingPolicy map[string]*AwsAppAutoscalingPolicyResult

	// AwsSQSQueueResult defines the SQS Queues.
	AwsSQSQueueResult map[string]*AwsSQSQueueResult

	// AwsS3Store is set when the secret is too big to store in secret manager.
	AwsS3Store AwsS3Store

	// awsS3PrivateBucketName is the name of the private S3 bucket.
	awsS3PrivateBucketName string
}

// AwsS3Store defines the location of the infrastructure stored on S3 when it's too big to store in Secret Manager.
type AwsS3Store struct {
	// S3Bucket defined the S3 bucket the key is stored in.
	S3Bucket string

	// S3Key defined the S3 key for the secret.
	S3Key string

	// Passphrase is the 32 bit string used to encrypt the data.
	Passphrase []byte
}

// NewInfrastructure load the currently deploy infrastructure from AWS Secrets Manager.
func NewInfrastructure(cfg *Config) (*Infrastructure, error) {

	errs := validator.New().Struct(cfg)
	if errs != nil {
		return nil, errs
	}

	var secretID string
	if cfg.AwsSecretPrefix != "" {
		secretID = AwsSecretID(cfg.AwsSecretPrefix, cfg.Env, "infrastructure/json")
	} else {
		secretID = AwsSecretID(cfg.ProjectName, cfg.Env, "infrastructure/json")
	}

	var infra *Infrastructure
	dat, err := SecretManagerGetBinary(cfg.AwsCredentials.Session(), secretID)
	if err != nil {
		if errors.Cause(err) != ErrSecreteNotFound {
			return nil, err
		}
	} else {
		err = json.Unmarshal(dat, &infra)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to json decode db credentials")
		}
	}

	var loaded bool
	if infra != nil {
		loaded = true
	} else {
		infra = &Infrastructure{}
	}

	if infra.AwsS3Store.S3Key != "" {
		res, err := s3.New(cfg.AwsCredentials.Session()).GetObject(&s3.GetObjectInput{
			Bucket: aws.String(infra.AwsS3Store.S3Bucket),
			Key:    aws.String(infra.AwsS3Store.S3Key),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read infrastructure on Aws S3 at s3://%s/%s", infra.AwsS3Store.S3Bucket, infra.AwsS3Store.S3Key)
		}

		encDat, err := ioutil.ReadAll(res.Body)
		defer res.Body.Close()
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read infrastructure response on Aws S3 at s3://%s/%s", infra.AwsS3Store.S3Bucket, infra.AwsS3Store.S3Key)
		}

		dat, err = decrypt(encDat, infra.AwsS3Store.Passphrase)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to decrypt infrastructure")
		}

		err = json.Unmarshal(dat, &infra)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to json decode db credentials")
		}
	}

	infra.secretID = secretID
	infra.awsCredentials = cfg.AwsCredentials
	infra.Env = cfg.Env
	infra.ProjectName = cfg.ProjectName
	infra.awsS3PrivateBucketName = cfg.AwsS3BucketPrivate.BucketName

	if loaded && cfg.AfterLoad != nil {
		err = cfg.AfterLoad(infra)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return infra, nil
}

// Save json encodes Infrastructure and updates the secret in AWS Secrets Manager.
func (i *Infrastructure) Save(log *log.Logger) error {

	dat, err := json.Marshal(i)
	if err != nil {
		return err
	}

	// Store on S3 because the file is too big.
	var saveToS3 bool
	if i.AwsS3Store.S3Key != "" {
		saveToS3 = true
	} else {
		sm := secretsmanager.New(i.awsCredentials.Session())

		// Update the current AWS Secret.
		_, err = sm.UpdateSecret(&secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(i.secretID),
			SecretBinary: dat,
		})
		if err != nil {
			aerr, ok := err.(awserr.Error)

			if ok && aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException {
				log.Printf("\tCreating new entry in AWS Secret Manager using secret ID %s\n", i.secretID)

				_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
					Name:         aws.String(i.secretID),
					SecretBinary: dat,
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create secret with infrastructure")
				}

			} else if ok && aerr.Code() == secretsmanager.ErrCodeInvalidRequestException {
				// InvalidRequestException: You can't create this secret because a secret with this
				// 							 name is already scheduled for deletion.

				// Restore secret after it was already previously deleted.
				_, err = sm.RestoreSecret(&secretsmanager.RestoreSecretInput{
					SecretId: aws.String(i.secretID),
				})
				if err != nil {
					return errors.Wrapf(err, "failed to restore secret %s", i.secretID)
				}

				_, err = sm.UpdateSecret(&secretsmanager.UpdateSecretInput{
					SecretId:     aws.String(i.secretID),
					SecretBinary: dat,
				})
				if err != nil {
					return errors.Wrap(err, "Failed to update secret with infrastructure")
				}
			} else if strings.Contains(err.Error(), "Member must have length less than") {
				// Need to store file on S3. Value at 'secretBinary' failed to satisfy constraint: Member must have length less than or equal to 10240
				saveToS3 = true
			} else {
				return errors.Wrap(err, "Failed to update secret with infrastructure")
			}
		}

		log.Printf("\tSaving Infrastructure to Aws Secret Manager using secret ID %s\n", i.secretID)
	}

	if saveToS3 {
		if i.AwsS3Store.S3Bucket == "" {
			i.AwsS3Store.S3Bucket = i.awsS3PrivateBucketName
		}

		// Ensure the S3 Bucket is setup.
		_, err = i.GetAwsS3Bucket(i.AwsS3Store.S3Bucket)
		if err != nil {
			return errors.Wrap(err, "Failed to encrypt infrastructure")
		}

		if i.AwsS3Store.S3Key == "" {
			i.AwsS3Store.S3Key = filepath.Join("devdeploy", "config", "infra.json.enc")
		}

		if len(i.AwsS3Store.Passphrase) == 0 {
			i.AwsS3Store.Passphrase = []byte(uuid.NewRandom().String()[0:32])
		}

		log.Printf("\tSaving Infrastructure data to Aws S3 at s3://%s/%s\n", i.AwsS3Store.S3Bucket, i.AwsS3Store.S3Key)

		encDat, err := encrypt(dat, i.AwsS3Store.Passphrase)
		if err != nil {
			return errors.Wrap(err, "Failed to encrypt infrastructure")
		}

		_, err = s3.New(i.awsCredentials.Session()).PutObject(&s3.PutObjectInput{
			Bucket:               aws.String(i.AwsS3Store.S3Bucket),
			Key:                  aws.String(i.AwsS3Store.S3Key),
			ACL:                  aws.String("private"),
			Body:                 bytes.NewReader(encDat),
			ContentLength:        aws.Int64(int64(len(encDat))),
			ServerSideEncryption: aws.String("AES256"),
		})
		if err != nil {
			return errors.Wrapf(err, "Failed to save infrastructure to Aws S3 at s3://%s/%s", i.AwsS3Store.S3Bucket, i.AwsS3Store.S3Key)
		}
	}

	return nil
}

// SetupDeploymentEnv ensures all the resources for the project are setup before deploying a single ECS service or
// Lambda function. This will ensure the following AWS are available for deployment:
// 1. AWS ECR repository
// 2. AWS IAM Policy
// 3. AWS S3 buckets
// 4. AWS EC2 VPC
// 5. AWS EC2 Security Group
// 6. AWS Elastic Cache Cluster
// 7. AWS RDS database Cluster
// 8. AWS RDS database Instance
// 9. AWS SQS queues.
// 10. Function Resources
// 11. Service Resources
func SetupInfrastructure(log *log.Logger, cfg *Config, opts ...SetupOption) (*Infrastructure, error) {

	log.Printf("Setup infrastructure for environment %s\n", cfg.Env)

	infra, err := NewInfrastructure(cfg)
	if err != nil {
		return nil, err
	}

	// Always ensure we save any progress before exiting, even on error.
	defer func() {
		if err := infra.Save(log); err != nil {
			log.Fatalf("%+v", err)
		}
	}()

	var buildEnv bool
	for _, opt := range opts {
		if opt == SetupOptionBuildEnv {
			buildEnv = true
		} else if opt == SetupOptionSkipCache {
			infra.skipCache = true
		}
	}

	// Step 1: Find or create the AWS ECR repository.
	{
		repo, err := infra.setupAwsEcrRepository(log, cfg.AwsEcrRepository)
		if err != nil {
			return nil, err
		}

		// Since ECR has max number of repository images, need to delete old ones so can stay under limit.
		// If there are image IDs to delete, delete them.
		log.Println("\tChecking old ECR images.")
		maxImages := cfg.AwsEcrRepository.MaxImages
		if maxImages == 0 || maxImages > AwsRegistryMaximumImages {
			maxImages = AwsRegistryMaximumImages
		}
		delIds, err := EcrPurgeImages(cfg.AwsCredentials, repo.RepositoryName, maxImages)
		if err != nil {
			return nil, err
		}

		if len(delIds) > 0 {
			log.Printf("\tDeleted %d images that exceeded limit of %d", len(delIds), maxImages)
		}
	}

	// If we are just ensure we have the resources for build provisioned, then exit.
	if buildEnv {
		return infra, nil
	}

	// Step 2: Find or create the AWS IAM policy.
	var defaultPolicy *AwsIamPolicyResult
	{
		defaultPolicy, err = infra.setupAwsIamPolicy(log, cfg.AwsIamPolicy)
		if err != nil {
			return nil, err
		}
	}

	// Step 3: Find or create the list of AWS S3 buckets.
	{
		_, err := infra.setupAwsS3Buckets(log, cfg.AwsS3BucketPrivate, cfg.AwsS3BucketPublic)
		if err != nil {
			return nil, err
		}
	}

	// Step 4: Find or create the AWS EC2 VPC.
	var vpc *AwsEc2VpcResult
	{
		vpc, err = infra.setupAwsEc2Vpc(log, cfg.AwsEc2Vpc)
		if err != nil {
			return nil, err
		}
	}

	// Step 5: Find or create  AWS EC2 Security Group.
	var securityGroup *AwsEc2SecurityGroupResult
	{
		// Enable services to communicate between each other.
		cfg.AwsEc2SecurityGroup.IngressRules = append(cfg.AwsEc2SecurityGroup.IngressRules, &ec2.AuthorizeSecurityGroupIngressInput{
			SourceSecurityGroupName: aws.String(AwsSecurityGroupSourceGroupSelf),
		})

		// When a database cluster/instance is defined, deploy needs access to handle executing schema migration.
		if cfg.AwsRdsDBCluster != nil || cfg.AwsRdsDBInstance != nil {
			// The gitlab runner security group is required when a db instance is defined.
			if cfg.GitlabRunnerEc2SecurityGroupName == "" {
				return nil, errors.Errorf("Failed to find security group '%s'", cfg.GitlabRunnerEc2SecurityGroupName)
			}

			// Enable GitLab runner to communicate with deployment created services.
			cfg.AwsEc2SecurityGroup.IngressRules = append(cfg.AwsEc2SecurityGroup.IngressRules, &ec2.AuthorizeSecurityGroupIngressInput{
				SourceSecurityGroupName: aws.String(cfg.GitlabRunnerEc2SecurityGroupName),
			})
		}

		securityGroup, err = infra.setupAwsEc2SecurityGroup(log, cfg.AwsEc2SecurityGroup, vpc)
		if err != nil {
			return nil, err
		}
	}

	// Step 6: Find or create the AWS Elastic Cache Cluster.
	if cfg.AwsElasticCacheCluster != nil {
		_, err := infra.setupAwsElasticCacheCluster(log, cfg.AwsElasticCacheCluster, securityGroup)
		if err != nil {
			return nil, err
		}
	} else {
		infra.AwsElasticCacheCluster = nil
	}

	// Step 7: Find or create the AWS RDS database Cluster.
	// This is only used when service uses Aurora via RDS for serverless Postgres and database cluster is defined.
	// Aurora Postgres is limited to specific AWS regions and thus not used by default.
	// If an Aurora Postgres cluster is defined, ensure it exists with RDS else create a new one.
	if cfg.AwsRdsDBCluster != nil {
		dbCluster, err := infra.setupAwsRdsDbCluster(log, cfg.AwsRdsDBCluster, securityGroup)
		if err != nil {
			return nil, err
		}
		cfg.DBConnInfo = dbCluster.DBConnInfo
	} else {
		infra.AwsRdsDBCluster = nil
	}

	// Step 8: Find or create the AWS RDS database Instance.
	// Regardless if deployment is using Aurora or not, still need to setup database instance.
	// If a database instance is defined, then ensure it exists with RDS in else create a new one.
	if cfg.AwsRdsDBInstance != nil {
		dbInstance, err := infra.setupAwsRdsDbInstance(log, cfg.AwsRdsDBInstance, securityGroup)
		if err != nil {
			return nil, err
		}
		cfg.DBConnInfo = dbInstance.DBConnInfo
	} else {
		infra.AwsRdsDBInstance = nil
	}

	// Step 9: Find or create the AWS SQS Queues
	if len(cfg.AwsSQSQueues) > 0 {
		for _, q := range cfg.AwsSQSQueues {
			_, err = infra.setupAwsSQSQueue(log, q)
			if err != nil {
				return nil, err
			}
		}
	}

	// Step 10: Resources need to build and deploy functions.
	for _, targetFunc := range cfg.ProjectFunctions {

		// Validate the function.
		errs := validator.New().Struct(targetFunc)
		if errs != nil {
			return nil, errs
		}

		// Find or create the AWS IAM policy.
		var policyArns []string
		if targetFunc.AwsIamPolicy != nil {
			policy, err := infra.setupAwsIamPolicy(log, targetFunc.AwsIamPolicy)
			if err != nil {
				return nil, err
			}
			policyArns = append(policyArns, policy.Arn)
		} else if defaultPolicy != nil {
			policyArns = append(policyArns, defaultPolicy.Arn)
		}

		//  Find or create the AWS IAM role.
		if targetFunc.AwsIamRole != nil {
			targetFunc.AwsIamRole.AttachRolePolicyArns = append(targetFunc.AwsIamRole.AttachRolePolicyArns, policyArns...)

			_, err = infra.setupAwsIamRole(log, targetFunc.AwsIamRole)
			if err != nil {
				return nil, err
			}
		}

		//  Find or create the AWS IAM role for events.
		for _, eventRule := range targetFunc.AwsCloudwatchEventRules {
			if eventRule.IamRole != nil {
				_, err = infra.setupAwsIamRole(log, eventRule.IamRole)
				if err != nil {
					return nil, err
				}
			}

			for _, eventTarget := range eventRule.Targets {
				if eventTarget.IamRole != nil {
					_, err = infra.setupAwsIamRole(log, eventTarget.IamRole)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	// Regex to determine if a hostname starts with a number.
	r, err := regexp.Compile(`^(\d+)`)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Step 11: Resources need to build and deploy services.
	for _, targetSrvc := range cfg.ProjectServices {

		// Workaround for domains that start with a numeric value like 8north.com
		// Validation fails with error: failed on the 'fqdn' tag
		origServiceHostPrimary := targetSrvc.ServiceHostPrimary
		matches := r.FindAllString(targetSrvc.ServiceHostPrimary, -1)
		if len(matches) > 0 {
			for _, m := range matches {
				targetSrvc.ServiceHostPrimary = strings.Replace(targetSrvc.ServiceHostPrimary, m, "X", -1)
			}
		}

		// Validate the service.
		errs := validator.New().Struct(targetSrvc)
		if errs != nil {
			return nil, errs
		}

		// Set the primary hostname back to original value.
		targetSrvc.ServiceHostPrimary = origServiceHostPrimary

		//  Find or create the AWS ECS Execution role if set.
		if targetSrvc.AwsEcsExecutionRole != nil {
			_, err = infra.setupAwsIamRole(log, targetSrvc.AwsEcsExecutionRole)
			if err != nil {
				return nil, err
			}
		}

		//  Find or create the AWS ECS Task role if set.
		if targetSrvc.AwsEcsTaskRole != nil {
			if defaultPolicy != nil {
				targetSrvc.AwsEcsTaskRole.AttachRolePolicyArns = append(targetSrvc.AwsEcsTaskRole.AttachRolePolicyArns, defaultPolicy.Arn)
			}

			_, err = infra.setupAwsIamRole(log, targetSrvc.AwsEcsTaskRole)
			if err != nil {
				return nil, err
			}
		}

		// Find the AWS ECS Cluster or create it.
		_, err = infra.setupAwsEcsCluster(log, targetSrvc.AwsEcsCluster)
		if err != nil {
			return nil, err
		}

		//  Find or create the AWS ECS Task role if set.
		if targetSrvc.AwsCloudWatchLogGroup != nil {
			_, err = infra.setupAwsCloudWatchLogGroup(log, targetSrvc.AwsCloudWatchLogGroup)
			if err != nil {
				return nil, err
			}
		}

		// Find or create the AWS Service Discovery namespace and service if set.
		if targetSrvc.AwsSdPrivateDnsNamespace != nil && !cfg.AwsCredentials.IsGov() {
			sdNamespace, err := infra.setupAwsSdPrivateDnsNamespace(log, targetSrvc.AwsSdPrivateDnsNamespace, vpc)
			if err != nil {
				return nil, err
			}

			if targetSrvc.AwsSdPrivateDnsNamespace.Service != nil {
				_, err = infra.setupAwsSdService(log, sdNamespace, targetSrvc.AwsSdPrivateDnsNamespace.Service)
				if err != nil {
					return nil, err
				}
			}
		}

		// Route 53 zone lookup when hostname is set. Supports both top level domains or sub domains.
		var zones map[string]*AwsRoute53ZoneResult
		{
			lookupDomains := []string{}
			if targetSrvc.ServiceHostPrimary != "" {
				lookupDomains = append(lookupDomains, targetSrvc.ServiceHostPrimary)
			}
			for _, dn := range targetSrvc.ServiceHostNames {
				if dn != targetSrvc.ServiceHostPrimary {
					lookupDomains = append(lookupDomains, dn)
				}
			}

			zones, err = infra.setupAwsRoute53Zones(log, lookupDomains, vpc)
			if err != nil {
				return nil, err
			}
		}

		// If an Elastic Load Balancer is enabled, then ensure one exists else create one.
		if targetSrvc.AwsElbLoadBalancer != nil {
			elbSgReq := &AwsEc2SecurityGroup{
				GroupName: "elb-"+securityGroup.GroupName,
				Description: fmt.Sprintf("Handles load balancer requests for %s", securityGroup.GroupName),
				IngressRules:  []*ec2.AuthorizeSecurityGroupIngressInput{
					&ec2.AuthorizeSecurityGroupIngressInput{
						IpProtocol: aws.String("tcp"),
						CidrIp:     aws.String("0.0.0.0/0"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
					},
					&ec2.AuthorizeSecurityGroupIngressInput{
						IpProtocol: aws.String("tcp"),
						CidrIp:     aws.String("0.0.0.0/0"),
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
					},
				},
			}

			elbSg, err := infra.setupAwsEc2SecurityGroup(log, elbSgReq, vpc)
			if err != nil {
				return nil, err
			}

			_, err = infra.setupAwsElbLoadBalancer(log, targetSrvc.AwsElbLoadBalancer, vpc, elbSg, zones, targetSrvc)
			if err != nil {
				return nil, err
			}

			// Enable services to be accessible on port 80 by ELB.
			log.Println("\tEC2 - Enable HTTP port 80 for security group from elb.")
			svc := ec2.New(infra.AwsSession())
			_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				SourceSecurityGroupName: &securityGroup.GroupName,
				FromPort:   aws.Int64(80),
				ToPort:     aws.Int64(80),
				GroupId:    aws.String(elbSg.GroupId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidPermission.Duplicate" {
					return nil, errors.Wrapf(err, "Failed to add ingress for security group '%s'",
						elbSg.GroupName)
				}
			}
		} else {

			svc := ec2.New(infra.AwsSession())

			log.Println("\tEC2 - Enable HTTP port 80 for security group.")
			_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				IpProtocol: aws.String("tcp"),
				CidrIp:     aws.String("0.0.0.0/0"),
				FromPort:   aws.Int64(80),
				ToPort:     aws.Int64(80),
				GroupId:    aws.String(securityGroup.GroupId),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidPermission.Duplicate" {
					return nil, errors.Wrapf(err, "Failed to add ingress for security group '%s'",
						securityGroup.GroupName)
				}
			}

			// When not using an Elastic Load Balancer, services need to support direct access via HTTPS.
			// HTTPS is terminated via the web server and not on the Load Balancer.
			if targetSrvc.EnableHTTPS {
				log.Println("\tEC2 - Enable HTTPS port 443 for security group.")

				// Enable services to be publicly available via HTTPS port 443.
				_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
					IpProtocol: aws.String("tcp"),
					CidrIp:     aws.String("0.0.0.0/0"),
					FromPort:   aws.Int64(443),
					ToPort:     aws.Int64(443),
					GroupId:    aws.String(securityGroup.GroupId),
				})
				if err != nil {
					if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidPermission.Duplicate" {
						return nil, errors.Wrapf(err, "Failed to add ingress for security group '%s'",
							cfg.AwsEc2SecurityGroup.GroupName)
					}
				}
			}
		}
	}

	return infra, nil
}

// ProjectNameCamel takes a project name and returns the camel cased version.
func (infra *Infrastructure) ProjectNameCamel() string {
	s := strings.Replace(infra.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
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

	resp.GoModName, err = LoadGoModName(resp.GoModFile)
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
			return "", errors.Wrap(err, "failed to get current working directory")
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
		return "", errors.Wrapf(err, "failed to load go.mod for project using project root %s", workDir)
	} else if !ok {
		return "", errors.Errorf("failed to locate project go.mod in project root %s", workDir)
	}

	return goModFile, nil
}

// LoadGoModName parses out the module name from go.mod.
func LoadGoModName(goModFile string) (string, error) {
	ok, err := exists(goModFile)
	if err != nil {
		return "", errors.Wrap(err, "Failed to load go.mod for project")
	} else if !ok {
		return "", errors.Errorf("Failed to locate project go.mod at %s", goModFile)
	}

	b, err := ioutil.ReadFile(goModFile)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to read go.mod at %s", goModFile)
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

// openDbConn opens a db connection to a database waiting for the host to come online to help handle errors such as:
// 	no such host
func openDbConn(log *log.Logger, dbInfo *DBConnInfo) (*sqlx.DB, error) {

	st := time.Now().Unix()

	var (
		dbConn *sqlx.DB
		err    error
	)
	retryFunc := func() (bool, error) {
		dbConn, err = sqlx.Open(dbInfo.Driver, dbInfo.URL())
		if err != nil {
			// Wait no longer than 50 minutes trying to connect to the database.
			if time.Now().Unix()-st > 300 {
				return true, errors.Wrap(err, "Failed to connect to db.")
			}

			log.Printf("openDbConn - %s\n", err)
			return false, nil
		}

		_, err = dbConn.Exec("SELECT 1")
		if err != nil {
			// Wait no longer than 50 minutes trying to connect to the database.
			if time.Now().Unix()-st > 300 {
				return true, errors.Wrap(err, "Failed to connect to db.")
			}

			log.Printf("openDbConn - %s\n", err)
			return false, nil
		}

		return true, nil
	}
	err = retry.Retry(context.Background(), nil, retryFunc)

	return dbConn, err
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
