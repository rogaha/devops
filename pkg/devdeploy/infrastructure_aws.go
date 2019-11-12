package devdeploy

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/google/go-cmp/cmp"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"gitlab.com/geeks-accelerator/oss/devops/internal/retry"
)

const AwsSecurityGroupSourceGroupSelf = "self"

// AwsSecretID defines the key path for a secret by name.
func AwsSecretID(projectName, env, secretName string) string {
	return filepath.Join(projectName, env, secretName)
}

// AwsSession returns the AWS session based on the defined credentials.
func (infra *Infrastructure) AwsSession() *session.Session {
	return infra.awsCredentials.Session()
}

// SecretID returns the secret name with a standard prefix.
func (infra *Infrastructure) SecretID(secretName string) string {
	return AwsSecretID(infra.ProjectName, infra.Env, secretName)
}

// Ec2TagResource is a helper function to tag EC2 resources.
func (infra *Infrastructure) Ec2TagResource(resource, name string, tags ...Tag) error {
	svc := ec2.New(infra.AwsSession())

	existingKeys := make(map[string]bool)
	ec2Tags := []*ec2.Tag{}
	for _, t := range tags {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(t.Key), Value: aws.String(t.Value)})
		existingKeys[t.Key] = true
	}

	if !existingKeys[AwsTagNameProject] {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameProject), Value: aws.String(infra.ProjectName)})
	}

	if !existingKeys[AwsTagNameEnv] {
		ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(AwsTagNameEnv), Value: aws.String(infra.Env)})
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

// GetAwsEcrRepository returns *AwsEcrRepositoryResult by repository name.
func (infra *Infrastructure) GetAwsEcrRepository(repositoryName string) (*AwsEcrRepositoryResult, error) {
	var (
		result *AwsEcrRepositoryResult
		ok     bool
	)
	if infra.AwsEcrRepository != nil {
		result, ok = infra.AwsEcrRepository[repositoryName]
	}
	if !ok {
		return nil, errors.Errorf("No repository configured for '%s'", repositoryName)
	}
	return result, nil
}

// setupAwsEcrRepository ensures the AWS ECR repository exists else creates it.
func (infra *Infrastructure) setupAwsEcrRepository(log *log.Logger, repo *AwsEcrRepository) (*AwsEcrRepositoryResult, error) {

	log.Println("\tECR - Get or create repository")

	input, err := repo.Input()
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsEcrRepository == nil {
		infra.AwsEcrRepository = make(map[string]*AwsEcrRepositoryResult)
	}

	result, ok := infra.AwsEcrRepository[repo.RepositoryName]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.RepositoryArn)
		return result, nil
	}

	svc := ecr.New(infra.awsCredentials.Session())

	repositoryName := repo.RepositoryName

	var repository *ecr.Repository
	descRes, err := svc.DescribeRepositories(&ecr.DescribeRepositoriesInput{
		RepositoryNames: []*string{aws.String(repositoryName)},
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != ecr.ErrCodeRepositoryNotFoundException {
			return nil, errors.Wrapf(err, "Failed to describe repository '%s'.", repositoryName)
		}
	} else if len(descRes.Repositories) > 0 {
		repository = descRes.Repositories[0]
	}

	if repository == nil {
		// If no repository was found, create one.
		createRes, err := svc.CreateRepository(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create repository '%s'", repositoryName)
		}
		repository = createRes.Repository
		log.Printf("\t\tCreated: %s", *repository.RepositoryArn)
	} else {
		log.Printf("\t\tFound: %s", *repository.RepositoryArn)
	}

	result = &AwsEcrRepositoryResult{
		RepositoryName: *repository.RepositoryName,
		RepositoryArn:  *repository.RepositoryArn,
		RepositoryUri:  *repository.RepositoryUri,
		CreatedAt:      *repository.CreatedAt,
		InputHash:      inputHash,
	}
	infra.AwsEcrRepository[repo.RepositoryName] = result

	log.Printf("\t%s\tECR Respository available\n", Success)

	return result, nil
}

// GetAwsIamPolicy returns *AwsIamPolicyResult by policy name.
func (infra *Infrastructure) GetAwsIamPolicy(policyName string) (*AwsIamPolicyResult, error) {
	var (
		result *AwsIamPolicyResult
		ok     bool
	)
	if infra.AwsIamPolicy != nil {
		result, ok = infra.AwsIamPolicy[policyName]
	}
	if !ok {
		return nil, errors.Errorf("No policy configured for '%s'", policyName)
	}
	return result, nil
}

// setupAwsIamPolicy ensures the AWS IAM policy exists else creates it.
func (infra *Infrastructure) setupAwsIamPolicy(log *log.Logger, targetPolicy *AwsIamPolicy) (*AwsIamPolicyResult, error) {

	log.Println("\tIAM - Setup IAM Policy")

	input, err := targetPolicy.Input()
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsIamPolicy == nil {
		infra.AwsIamPolicy = make(map[string]*AwsIamPolicyResult)
	}

	result, ok := infra.AwsIamPolicy[targetPolicy.PolicyName]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.Arn)
		return result, nil
	}

	svc := iam.New(infra.awsCredentials.Session())

	policyName := targetPolicy.PolicyName

	log.Printf("\tFind policy %s.", policyName)

	var policy *iam.Policy
	err = svc.ListPoliciesPages(&iam.ListPoliciesInput{}, func(res *iam.ListPoliciesOutput, lastPage bool) bool {
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

		// If no policy was found, create one.
		res, err := svc.CreatePolicy(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create task policy '%s'", policyName)
		}
		policy = res.Policy

		log.Printf("\t\t\tCreated policy '%s'", *res.Policy.Arn)
	}

	result = &AwsIamPolicyResult{
		PolicyId:   *policy.PolicyId,
		PolicyName: *policy.PolicyName,
		Arn:        *policy.Arn,
		CreatedAt:  *policy.CreateDate,
		InputHash:  inputHash,
	}
	infra.AwsIamPolicy[targetPolicy.PolicyName] = result

	log.Printf("\t%s\tConfigured IAM policy.\n", Success)

	return result, nil
}

// GetAwsIamRole returns *AwsIamRoleResult by role name.
func (infra *Infrastructure) GetAwsIamRole(roleName string) (*AwsIamRoleResult, error) {
	var (
		result *AwsIamRoleResult
		ok     bool
	)
	if infra.AwsIamRole != nil {
		result, ok = infra.AwsIamRole[roleName]
	}
	if !ok {
		return nil, errors.Errorf("No role configured for '%s'", roleName)
	}
	return result, nil
}

// setupAwsIamRole ensures the AWS IAM role exists else creates it.
func (infra *Infrastructure) setupAwsIamRole(log *log.Logger, targetRole *AwsIamRole) (*AwsIamRoleResult, error) {

	log.Println("\tIAM - Setup IAM Role")

	input, err := targetRole.Input()
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input, targetRole.AttachRolePolicyArns)

	if infra.AwsIamRole == nil {
		infra.AwsIamRole = make(map[string]*AwsIamRoleResult)
	}

	result, ok := infra.AwsIamRole[targetRole.RoleName]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.Arn)
		return result, nil
	}

	svc := iam.New(infra.awsCredentials.Session())

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

	for _, policyArn := range targetRole.AttachRolePolicyArns {
		_, err = svc.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(roleName),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to attach policy '%s' to task role '%s'", policyArn, roleName)
		}

		log.Printf("\t\t\tRole attached policy %s.\n", policyArn)
	}

	result = &AwsIamRoleResult{
		RoleId:    *role.RoleId,
		RoleName:  *role.RoleName,
		Arn:       *role.Arn,
		CreatedAt: *role.CreateDate,
		InputHash: inputHash,
	}
	infra.AwsIamRole[targetRole.RoleName] = result

	log.Printf("\t%s\tConfigured IAM role.\n", Success)

	return result, nil
}

// GetAwsS3Bucket returns *AwsS3BucketResult by bucket name.
func (infra *Infrastructure) GetAwsS3Bucket(bucketName string) (*AwsS3BucketResult, error) {
	var (
		result *AwsS3BucketResult
		ok     bool
	)
	if infra.AwsS3Buckets != nil {
		result, ok = infra.AwsS3Buckets[bucketName]
	}
	if !ok {
		return nil, errors.Errorf("No vpc configured for '%s'", bucketName)
	}
	return result, nil
}

// setupAwsS3Buckets handles configuring s3 buckets.
func (infra *Infrastructure) setupAwsS3Buckets(log *log.Logger, s3Buckets ...*AwsS3Bucket) (map[string]*AwsS3BucketResult, error) {

	log.Println("\tS3 - Setup Buckets")

	svc := s3.New(infra.awsCredentials.Session())

	if infra.AwsS3Buckets == nil {
		infra.AwsS3Buckets = make(map[string]*AwsS3BucketResult)
	}

	var results []*AwsS3BucketResult

	var configure bool
	for _, s3Bucket := range s3Buckets {
		bucketName := s3Bucket.BucketName

		input, err := s3Bucket.Input()
		if err != nil {
			return nil, err
		}

		vals := []interface{}{
			s3Bucket.LifecycleRules,
			s3Bucket.CORSRules,
			s3Bucket.Policy,
			s3Bucket.PublicAccessBlock,
		}

		if s3Bucket.CloudFront != nil {
			cfInput, err := s3Bucket.CloudFront.Input()
			if err != nil {
				return nil, err
			}
			vals = append(vals, cfInput)
		}

		inputHash := getInputHash(input, vals...)

		result, ok := infra.AwsS3Buckets[bucketName]
		if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
			log.Printf("\t\tExists: %s", result.BucketName)
		} else {
			_, err := svc.HeadBucket(&s3.HeadBucketInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != s3.ErrCodeNoSuchBucket && aerr.Code() != "NotFound") {
					return nil, errors.Wrapf(err, "failed to find s3 bucket '%s'", bucketName)
				}

				_, err = svc.CreateBucket(input)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to create s3 bucket '%s'", bucketName)
				}
				log.Printf("\t\tCreated: %s\n", bucketName)
			} else {

				log.Printf("\t\tFound: %s\n", bucketName)
			}

			bucketRegion := infra.awsCredentials.Region
			if s3Bucket.LocationConstraint != nil && *s3Bucket.LocationConstraint != "" {
				bucketRegion = *s3Bucket.LocationConstraint
			}

			results = append(results, &AwsS3BucketResult{
				BucketName: bucketName,
				TempPrefix: s3Bucket.TempPrefix,
				IsPublic:   s3Bucket.IsPublic,
				Region:     bucketRegion,
				InputHash:  inputHash,
			})
			configure = true
		}
	}

	if !configure {
		return infra.AwsS3Buckets, nil
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
			return nil, errors.Wrapf(err, "Failed to wait for s3 bucket '%s' to exist", bucketName)
		}
	}

	// Loop through each S3 bucket and configure policies.
	log.Println("\t\tConfiguring each S3 Bucket")
	for _, s3Bucket := range s3Buckets {
		bucketName := s3Bucket.BucketName

		log.Printf("\t\t\t%s", bucketName)

		// Add all the defined lifecycle rules for the bucket.
		if len(s3Bucket.LifecycleRules) > 0 {
			var curRules []*s3.LifecycleRule
			res, err := svc.GetBucketLifecycleConfiguration(&s3.GetBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != "NoSuchLifecycleConfiguration") {
					return nil, errors.Wrapf(err, "Failed to get lifecycle rules for s3 bucket '%s'", bucketName)
				}
			} else {
				curRules = res.Rules
			}

			if diff := cmp.Diff(curRules, s3Bucket.LifecycleRules); diff != "" {
				log.Printf("\t\t\t\tLifecycle rules diff - %s\n", diff)

				_, err = svc.PutBucketLifecycleConfiguration(&s3.PutBucketLifecycleConfigurationInput{
					Bucket: aws.String(bucketName),
					LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
						Rules: s3Bucket.LifecycleRules,
					},
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to configure lifecycle rule for s3 bucket '%s'", bucketName)
				}

				for _, r := range s3Bucket.LifecycleRules {
					log.Printf("\t\t\t\tAdded lifecycle '%s'\n", *r.ID)
				}
			}
		}

		// Add all the defined CORS rules for the bucket.
		if len(s3Bucket.CORSRules) > 0 {
			var curRules []*s3.CORSRule
			res, err := svc.GetBucketCors(&s3.GetBucketCorsInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != "NoSuchCORSConfiguration") {
					return nil, errors.Wrapf(err, "Failed to get CORS rules for s3 bucket '%s'", bucketName)
				}
			} else {
				curRules = s3Bucket.CORSRules
			}

			if diff := cmp.Diff(res.CORSRules, curRules); diff != "" {
				log.Printf("\t\t\t\tCORS rules diff - %s\n", diff)

				_, err := svc.PutBucketCors(&s3.PutBucketCorsInput{
					Bucket: aws.String(bucketName),
					CORSConfiguration: &s3.CORSConfiguration{
						CORSRules: s3Bucket.CORSRules,
					},
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to put CORS rules on s3 bucket '%s'", bucketName)
				}
				log.Println("\t\t\t\tUpdated CORS")
			}
		}

		// Add the bucket policy if not empty.
		if s3Bucket.Policy != "" {

			// Remove the whitespace from the provided policy to ensure the diff compare works.
			var policyMap map[string]interface{}
			if err := json.Unmarshal([]byte(s3Bucket.Policy), &policyMap); err != nil {
				return nil, errors.Wrapf(err, "Failed JSON decode policy for s3 bucket '%s'", bucketName)
			}

			var curMap map[string]interface{}
			res, err := svc.GetBucketPolicy(&s3.GetBucketPolicyInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != "NoSuchBucketPolicy") {
					return nil, errors.Wrapf(err, "Failed to get bucket policy for s3 bucket '%s'", bucketName)
				}
			} else {
				// Remove the whitespace from the provided policy to ensure the diff compare works.
				if res != nil && res.Policy != nil && *res.Policy != "" {
					if err := json.Unmarshal([]byte(*res.Policy), &curMap); err != nil {
						return nil, errors.Wrapf(err, "Failed JSON decode policy for s3 bucket '%s'", bucketName)
					}
				}
			}

			if diff := cmp.Diff(curMap, policyMap); diff != "" {
				log.Printf("\t\t\t\tPolicy diff - %s\n", diff)

				_, err = svc.PutBucketPolicy(&s3.PutBucketPolicyInput{
					Bucket: aws.String(bucketName),
					Policy: aws.String(s3Bucket.Policy),
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to put bucket policy for s3 bucket '%s'", bucketName)
				}
				log.Println("\t\t\t\tUpdated bucket policy")
			}
		}

		// Block public access for all non-public buckets.
		if s3Bucket.PublicAccessBlock != nil {
			var curPublicAccessBlock *s3.PublicAccessBlockConfiguration
			res, err := svc.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != "NoSuchPublicAccessBlockConfiguration") {
					return nil, errors.Wrapf(err, "Failed to get public access block for s3 bucket '%s'", bucketName)
				}
			} else {
				curPublicAccessBlock = res.PublicAccessBlockConfiguration
			}

			if diff := cmp.Diff(s3Bucket.PublicAccessBlock, curPublicAccessBlock); diff != "" {
				log.Printf("\t\t\t\tPublic access bloc diff - %s\n", diff)

				_, err = svc.PutPublicAccessBlock(&s3.PutPublicAccessBlockInput{
					Bucket:                         aws.String(bucketName),
					PublicAccessBlockConfiguration: s3Bucket.PublicAccessBlock,
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to put public access block for s3 bucket '%s'", bucketName)
				}
				log.Println("\t\t\t\tBlocked public access")
			}
		}

		if s3Bucket.CloudFront != nil {

			var cloudfrontResult *AwsCloudFrontDistributionResult
			if bucketRes, ok := infra.AwsS3Buckets[bucketName]; ok {
				if bucketRes.CloudFront != nil {
					cloudfrontResult = bucketRes.CloudFront
				}
			}

			input, err := s3Bucket.CloudFront.Input()
			if err != nil {
				return nil, err
			}
			inputHash := getInputHash(input)

			if cloudfrontResult != nil {
				if cloudfrontResult.InputHash == inputHash && !infra.skipCache {
					// If bucket found during create, returns it.
					log.Printf("\t\t\t\t\tCloudFront Domain: %s.", cloudfrontResult.DomainName)
				} else {
					cloudfrontResult = nil
				}
			}

			if cloudfrontResult == nil {
				log.Println("\t\t\t\tSetup Cloudfront Distribution")

				bucketLoc := infra.awsCredentials.Region
				if s3Bucket.LocationConstraint != nil && *s3Bucket.LocationConstraint != "" {
					bucketLoc = *s3Bucket.LocationConstraint
				}
				domainName := fmt.Sprintf("%s.s3.%s.amazonaws.com", s3Bucket.BucketName, bucketLoc)

				cf := cloudfront.New(infra.awsCredentials.Session())

				res, err := cf.ListDistributions(&cloudfront.ListDistributionsInput{})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to list cloudfront distributions for s3 bucket '%s'", bucketName)
				}

				var existingId string
				for _, d := range res.DistributionList.Items {
					if d.Origins == nil || len(d.Origins.Items) == 0 {
						continue
					}

					var found bool
					for _, i := range d.Origins.Items {
						if *i.DomainName == domainName {
							found = true
							break
						}
					}

					if found {
						existingId = *d.Id
						break
					}
				}

				var curDist *cloudfront.Distribution
				if existingId == "" {
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
						return nil, err
					}

					targetOriginId := *input.DistributionConfig.DefaultCacheBehavior.TargetOriginId

					res, err := cf.CreateDistribution(input)
					if err != nil {
						if aerr, ok := err.(awserr.Error); !ok || (aerr.Code() != cloudfront.ErrCodeDistributionAlreadyExists) {
							return nil, errors.Wrapf(err, "Failed to create cloudfront distribution '%s'", targetOriginId)
						}
					}
					curDist = res.Distribution

					// If no bucket found during create, create new one.
					log.Printf("\t\t\t\t\t%s created: %s.", domainName, targetOriginId)
				} else {
					// If bucket found during create, returns it.
					log.Printf("\t\t\t\t\tFound: %s.", domainName)

					res, err := cf.GetDistribution(&cloudfront.GetDistributionInput{
						Id: aws.String(existingId),
					})
					if err != nil {
						return nil, err
					}

					curDist = res.Distribution
				}

				// The status of the distribution.
				log.Printf("\t\t\t\tStatus: %s", *curDist.Status)

				// If the distribute to become deployed so the domain name is set.
				if *curDist.Status != "Deployed" {
					log.Printf("\t\t\t\tWait for distribution to become deployed.")

					err = cf.WaitUntilDistributionDeployed(&cloudfront.GetDistributionInput{
						Id: curDist.Id,
					})
					if err != nil {
						return nil, err
					}

					res, err := cf.GetDistribution(&cloudfront.GetDistributionInput{
						Id: curDist.Id,
					})
					if err != nil {
						return nil, err
					}
					curDist = res.Distribution

					s3Bucket.CloudFront.DistributionConfig = res.Distribution.DistributionConfig

					// The status of the distribution.
					log.Printf("\t\t\t\tStatus: %s", *curDist.Status)
				}

				cloudfrontResult = &AwsCloudFrontDistributionResult{
					Id:                 *curDist.Id,
					DomainName:         *curDist.DomainName,
					ARN:                *curDist.ARN,
					DistributionConfig: *s3Bucket.CloudFront.DistributionConfig,
					InputHash:          inputHash,
				}

				for _, result := range results {
					if result.BucketName == s3Bucket.BucketName {
						result.CloudFront = cloudfrontResult
						break
					}
				}
			}
		}
	}

	// Now that we have successfully configured the s3 buckets, they can be added for saving.
	for _, result := range results {
		infra.AwsS3Buckets[result.BucketName] = result
	}

	log.Printf("\t%s\tS3 buckets configured successfully.\n", Success)

	return infra.AwsS3Buckets, nil
}

// GetAwsEc2Vpc returns *AwsEc2VpcResult by vpc ID.
func (infra *Infrastructure) GetAwsEc2Vpc(cidrBlock string) (*AwsEc2VpcResult, error) {
	var (
		result *AwsEc2VpcResult
		ok     bool
	)
	if infra.AwsEc2Vpc != nil {
		result, ok = infra.AwsEc2Vpc[cidrBlock]
	}
	if !ok {
		return nil, errors.Errorf("No vpc configured for '%s'", cidrBlock)
	}
	return result, nil
}

// GetAwsEc2Vpc returns *AwsEc2VpcResult by vpc ID.
func (infra *Infrastructure) GetAwsEc2DefaultVpc() (*AwsEc2VpcResult, error) {
	vpcId := "default"
	return infra.GetAwsEc2Vpc(vpcId)
}

// setupAwsEc2Vpc ensures the AWS EC2 VPC and it's subnets exists else creates it.
func (infra *Infrastructure) setupAwsEc2Vpc(log *log.Logger, targetVpc *AwsEc2Vpc) (*AwsEc2VpcResult, error) {

	log.Println("\tEC2 - Setup VPC")

	vpcInput, err := targetVpc.Input()
	if err != nil {
		return nil, err
	}
	vpcInputHash := getInputHash(vpcInput)

	if infra.AwsEc2Vpc == nil {
		infra.AwsEc2Vpc = make(map[string]*AwsEc2VpcResult)
	}

	var resultKey string
	if targetVpc.IsDefault {
		resultKey = "default"
	} else if targetVpc.VpcId != "" {
		resultKey = targetVpc.VpcId
	} else {
		resultKey = targetVpc.CidrBlock
	}

	vpcResult, ok := infra.AwsEc2Vpc[resultKey]
	if ok && vpcResult != nil {
		if vpcResult.InputHash == vpcInputHash && !infra.skipCache {
			log.Printf("\t\tExists: %s", resultKey)
			return vpcResult, nil
		}
	}

	svc := ec2.New(infra.awsCredentials.Session())

	var vpcId string
	var subnets []*ec2.Subnet
	if targetVpc.IsDefault {
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
			return nil, errors.Wrap(err, "Failed to find default subnets")
		}

		// Iterate through subnets and make sure they belong to the same VPC as the project.
		for _, s := range subnets {
			if s.VpcId == nil {
				continue
			}
			if vpcId == "" {
				vpcId = *s.VpcId

				log.Printf("\t\tFound VPC: %s", vpcId)

			} else if vpcId != *s.VpcId {
				return nil, errors.Errorf("Invalid subnet %s, all subnets should belong to the same VPC, expected %s, got %s", *s.SubnetId, vpcId, *s.VpcId)
			}
		}
	} else {

		var vpc *ec2.Vpc
		if targetVpc.VpcId != "" {
			log.Printf("\t\tFind VPC '%s'\n", targetVpc.VpcId)

			// Find all subnets that are default for each availability zone.
			err := svc.DescribeVpcsPages(&ec2.DescribeVpcsInput{
				VpcIds: aws.StringSlice([]string{targetVpc.VpcId}),
			}, func(res *ec2.DescribeVpcsOutput, lastPage bool) bool {
				for _, s := range res.Vpcs {
					if *s.VpcId == targetVpc.VpcId {
						vpc = s
						break
					}
				}
				return !lastPage
			})
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to describe vpc '%s'.", targetVpc.VpcId)
			}
		}

		// If there is no VPC id set and IsDefault is false, a new VPC needs to be created with the given details.
		if vpc == nil {
			createRes, err := svc.CreateVpc(vpcInput)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to create VPC")
			}
			vpc = createRes.Vpc
			targetVpc.VpcId = *vpc.VpcId

			log.Printf("\t\tCreated VPC %s", *vpc.VpcId)

			err = infra.Ec2TagResource(*vpc.VpcId, "", targetVpc.Tags...)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to tag vpc '%s'.", targetVpc.VpcId)
			}
		} else {
			log.Println("\t\tFind all subnets for VPC.")

			// Find all subnets that are default for each availability zone.
			err := svc.DescribeSubnetsPages(&ec2.DescribeSubnetsInput{}, func(res *ec2.DescribeSubnetsOutput, lastPage bool) bool {
				for _, s := range res.Subnets {
					if *s.VpcId == *vpc.VpcId {
						subnets = append(subnets, s)
					}
				}
				return !lastPage
			})
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to find subnets for VPC '%s'", targetVpc.VpcId)
			}
		}
		vpcId = *vpc.VpcId

		for _, sn := range targetVpc.Subnets {
			var found bool
			for _, t := range subnets {
				if t.CidrBlock != nil && *t.CidrBlock == sn.CidrBlock {
					found = true
					break
				}
			}

			if !found {
				input, err := sn.Input(targetVpc.VpcId)
				if err != nil {
					return nil, err
				}

				createRes, err := svc.CreateSubnet(input)
				if err != nil {
					return nil, errors.Wrap(err, "Failed to create VPC")
				}
				subnets = append(subnets, createRes.Subnet)

				log.Printf("\t\tCreated Subnet %s", *createRes.Subnet.SubnetId)

				err = infra.Ec2TagResource(*createRes.Subnet.SubnetId, "", sn.Tags...)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to tag subnet '%s'.", *createRes.Subnet.SubnetId)
				}
			}
		}
	}

	// This deployment process requires at least one subnet.
	// Each AWS account gets a default VPC and default subnet for each availability zone.
	// Likely error with AWs is can not find at least one.
	if len(subnets) == 0 {
		return nil, errors.New("Failed to find any subnets, expected at least 1")
	}

	var subnetIds []string
	for _, s := range subnets {
		subnetIds = append(subnetIds, *s.SubnetId)
	}

	vpcResult = &AwsEc2VpcResult{
		VpcId:     vpcId,
		IsDefault: targetVpc.IsDefault,
		SubnetIds: subnetIds,
		InputHash: vpcInputHash,
	}
	infra.AwsEc2Vpc[resultKey] = vpcResult

	log.Printf("\t\tVPC '%s' has %d subnets", vpcResult.VpcId, len(vpcResult.SubnetIds))
	for _, sn := range vpcResult.SubnetIds {
		log.Printf("\t\t\tSubnet: %s", sn)
	}

	log.Printf("\t%s\tEC2 VPC available\n", Success)

	return vpcResult, nil
}

// GetAwsEc2SecurityGroup returns *AwsEc2SecurityGroupResult by security group name.
func (infra *Infrastructure) GetAwsEc2SecurityGroup(groupName string) (*AwsEc2SecurityGroupResult, error) {
	var (
		result *AwsEc2SecurityGroupResult
		ok     bool
	)
	if infra.AwsEc2SecurityGroup != nil {
		result, ok = infra.AwsEc2SecurityGroup[groupName]
	}
	if !ok {
		return nil, errors.Errorf("No bucket configured for '%s'", groupName)
	}
	return result, nil
}

// setupAwsEc2SecurityGroup ensures the AWS EC2 security group exists else creates it.
func (infra *Infrastructure) setupAwsEc2SecurityGroup(log *log.Logger, targetSg *AwsEc2SecurityGroup, vpc *AwsEc2VpcResult) (*AwsEc2SecurityGroupResult, error) {

	log.Println("\tEC2 - Find Security Group")

	input, err := targetSg.Input(vpc.VpcId)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input, targetSg.IngressRules)

	if infra.AwsEc2SecurityGroup == nil {
		infra.AwsEc2SecurityGroup = make(map[string]*AwsEc2SecurityGroupResult)
	}

	result, ok := infra.AwsEc2SecurityGroup[targetSg.GroupName]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.GroupId)
		return result, nil
	}

	svc := ec2.New(infra.awsCredentials.Session())

	securityGroupName := targetSg.GroupName

	filterNames := []string{
		securityGroupName,
	}

	includeGroupNames := make(map[string]bool)
	for _, r := range targetSg.IngressRules {
		if r.SourceSecurityGroupName != nil && *r.SourceSecurityGroupName != AwsSecurityGroupSourceGroupSelf {
			includeGroupNames[*r.SourceSecurityGroupName] = true
			filterNames = append(filterNames, *r.SourceSecurityGroupName)
		}
	}

	// Find all the security groups and then parse the group name to get the Id of the security group.
	var securityGroup *ec2.SecurityGroup
	sourceSecurityGroups := make(map[string]*ec2.SecurityGroup)
	err = svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("group-name"),
				Values: aws.StringSlice(filterNames),
			},
		},
	}, func(res *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
		for _, s := range res.SecurityGroups {
			if *s.GroupName == securityGroupName {
				securityGroup = s
			} else if includeGroupNames[*s.GroupName] {
				sourceSecurityGroups[*s.GroupName] = s
			}
		}
		return !lastPage
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidGroup.NotFound" {
			return nil, errors.Wrapf(err, "Failed to find security group '%s'", securityGroupName)
		}
	}

	// Create all the linked security groups that don't exist.
	for gn, _ := range includeGroupNames {
		if _, ok := sourceSecurityGroups[gn]; ok {
			continue
		}
		return nil, errors.Errorf("Failed to find source security group '%s' as ingress for security group '%s'", gn, securityGroupName)
	}

	if securityGroup == nil {

		// If no security group was found, create one.
		createRes, err := svc.CreateSecurityGroup(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create security group '%s'", securityGroupName)
		}
		result = &AwsEc2SecurityGroupResult{
			GroupId:   *createRes.GroupId,
			GroupName: *input.GroupName,
			VpcId:     input.VpcId,
			InputHash: inputHash,
		}

		log.Printf("\t\tCreated: %s", securityGroupName)

		err = infra.Ec2TagResource(*createRes.GroupId, "", targetSg.Tags...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to tag security group '%s'.", securityGroupName)
		}
	} else {
		log.Printf("\t\tFound: %s", securityGroupName)

		result = &AwsEc2SecurityGroupResult{
			GroupId:   *securityGroup.GroupId,
			GroupName: *securityGroup.GroupName,
			VpcId:     input.VpcId,
			InputHash: inputHash,
		}
	}

	// Add all the default ingress to the security group.
	for _, ingressInput := range targetSg.IngressRules {
		ingressInput.GroupId = aws.String(result.GroupId)

		// Replace the placeholder to allow ingress to reference themselves.
		if ingressInput.SourceSecurityGroupName != nil && *ingressInput.SourceSecurityGroupName == AwsSecurityGroupSourceGroupSelf {
			ingressInput.SourceSecurityGroupName = aws.String(result.GroupName)
		}

		_, err = svc.AuthorizeSecurityGroupIngress(ingressInput)
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidPermission.Duplicate" {
				return nil, errors.Wrapf(err, "Failed to add ingress for security group '%s'", securityGroupName)
			}
		}
	}

	infra.AwsEc2SecurityGroup[targetSg.GroupName] = result

	log.Printf("\t%s\tSecurity Group configured\n", Success)

	return result, nil
}

// GetAwsElasticCacheCluster returns *AwsElasticCacheClusterResult by cache cluster ID.
func (infra *Infrastructure) GetAwsElasticCacheCluster(cacheClusterId string) (*AwsElasticCacheClusterResult, error) {
	var (
		result *AwsElasticCacheClusterResult
		ok     bool
	)
	if infra.AwsElasticCacheCluster != nil {
		result, ok = infra.AwsElasticCacheCluster[cacheClusterId]
	}
	if !ok {
		return nil, errors.Errorf("No cache cluster configured for '%s'", cacheClusterId)
	}
	return result, nil
}

// setupAwsElasticCacheCluster ensures the AWS Elastic cache cluster exists else creates it.
func (infra *Infrastructure) setupAwsElasticCacheCluster(log *log.Logger, targetCluster *AwsElasticCacheCluster, securityGroup *AwsEc2SecurityGroupResult) (*AwsElasticCacheClusterResult, error) {

	log.Println("\tElastic Cache - Get or Create Cache Cluster")

	input, err := targetCluster.Input(securityGroup)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input, targetCluster.ParameterNameValues)

	if infra.AwsElasticCacheCluster == nil {
		infra.AwsElasticCacheCluster = make(map[string]*AwsElasticCacheClusterResult)
	}

	result, ok := infra.AwsElasticCacheCluster[targetCluster.CacheClusterId]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.CacheClusterId)
		return result, nil
	}

	svc := elasticache.New(infra.awsCredentials.Session())

	cacheClusterId := targetCluster.CacheClusterId

	// Find Elastic Cache cluster given Id.
	var cacheCluster *elasticache.CacheCluster
	descRes, err := svc.DescribeCacheClusters(&elasticache.DescribeCacheClustersInput{
		CacheClusterId:    aws.String(cacheClusterId),
		ShowCacheNodeInfo: aws.Bool(true),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elasticache.ErrCodeCacheClusterNotFoundFault {
			return nil, errors.Wrapf(err, "Failed to describe cache cluster '%s'", cacheClusterId)
		}
	} else if len(descRes.CacheClusters) > 0 {
		cacheCluster = descRes.CacheClusters[0]
	}

	if cacheCluster == nil {
		// If no repository was found, create one.
		createRes, err := svc.CreateCacheCluster(input)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create cluster '%s'", cacheClusterId)
		}
		cacheCluster = createRes.CacheCluster

		log.Printf("\t\tCreated: %s", *cacheCluster.CacheClusterId)
	} else {
		log.Printf("\t\tFound: %s", *cacheCluster.CacheClusterId)
	}

	// The status of the cluster.
	log.Printf("\t\t\tStatus: %s", *cacheCluster.CacheClusterStatus)

	// If the cache cluster is not active because it was recently created, wait for it to become active.
	if *cacheCluster.CacheClusterStatus != "available" {
		log.Printf("\t\tWait for cluster to become available.")
		err = svc.WaitUntilCacheClusterAvailable(&elasticache.DescribeCacheClustersInput{
			CacheClusterId: aws.String(cacheClusterId),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to wait for cache cluster '%s' to enter available state", cacheClusterId)
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
	if len(targetCluster.ParameterNameValues) > 0 {

		customCacheParameterGroupName := fmt.Sprintf("%s-%s%s",
			strings.ToLower(infra.ProjectNameCamel()),
			*cacheCluster.Engine,
			*cacheCluster.EngineVersion)

		customCacheParameterGroupName = strings.Replace(customCacheParameterGroupName, ".", "-", -1)

		// Check to see if the custom cache parameter group has already been created.
		var createCustomParamGroup bool
		_, err = svc.DescribeCacheParameterGroups(&elasticache.DescribeCacheParameterGroupsInput{
			CacheParameterGroupName: aws.String(customCacheParameterGroupName),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == elasticache.ErrCodeCacheParameterGroupNotFoundFault {
				createCustomParamGroup = true
			} else {
				return nil, errors.Wrapf(err, "Failed to describe cache parameter group '%s'", cacheClusterId)
			}
		}

		// If the cache cluster is using the default parameter group, create a new custom group.
		if createCustomParamGroup && strings.HasPrefix(*cacheCluster.CacheParameterGroup.CacheParameterGroupName, "default") {
			// Lookup the group family from the current cache parameter group.
			descRes, err := svc.DescribeCacheParameterGroups(&elasticache.DescribeCacheParameterGroupsInput{
				CacheParameterGroupName: cacheCluster.CacheParameterGroup.CacheParameterGroupName,
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elasticache.ErrCodeCacheParameterGroupNotFoundFault {
					return nil, errors.Wrapf(err, "Failed to describe cache parameter group '%s'", cacheClusterId)
				}
			}

			log.Printf("\t\tCreated custom Cache Parameter Group : %s", customCacheParameterGroupName)
			_, err = svc.CreateCacheParameterGroup(&elasticache.CreateCacheParameterGroupInput{
				CacheParameterGroupFamily: descRes.CacheParameterGroups[0].CacheParameterGroupFamily,
				CacheParameterGroupName:   aws.String(customCacheParameterGroupName),
				Description:               aws.String(fmt.Sprintf("Customized default parameter group for %s %s", *cacheCluster.Engine, *cacheCluster.EngineVersion)),
			})
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to cache parameter group '%s'", customCacheParameterGroupName)
			}

			log.Printf("\t\tSet Cache Parameter Group : %s", customCacheParameterGroupName)
			updateRes, err := svc.ModifyCacheCluster(&elasticache.ModifyCacheClusterInput{
				CacheClusterId:          cacheCluster.CacheClusterId,
				CacheParameterGroupName: aws.String(customCacheParameterGroupName),
			})
			if err != nil {
				return nil, errors.Wrapf(err, "Failed modify cache parameter group '%s' for cache cluster '%s'", customCacheParameterGroupName, *cacheCluster.CacheClusterId)
			}
			cacheCluster = updateRes.CacheCluster
		}

		// Only modify the cache parameter group if the cache cluster is custom one created to allow other groups to
		// be set on the cache cluster but not modified.
		if *cacheCluster.CacheParameterGroup.CacheParameterGroupName == customCacheParameterGroupName {
			log.Printf("\t\tUpdating Cache Parameter Group : %s", customCacheParameterGroupName)

			input, err := targetCluster.CacheParameterGroupInput(customCacheParameterGroupName)
			if err != nil {
				return nil, err
			}
			_, err = svc.ModifyCacheParameterGroup(input)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to modify cache parameter group '%s'", *cacheCluster.CacheParameterGroup.CacheParameterGroupName)
			}

			for _, p := range targetCluster.ParameterNameValues {
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
				return nil, errors.Wrapf(err, "Failed to describe cache cluster '%s'", cacheClusterId)
			}
		} else if len(descRes.CacheClusters) > 0 {
			cacheCluster = descRes.CacheClusters[0]
		}
	}

	result = &AwsElasticCacheClusterResult{
		CacheClusterId: *cacheCluster.CacheClusterId,
		InputHash:      inputHash,
	}

	if cacheCluster.ConfigurationEndpoint != nil && cacheCluster.ConfigurationEndpoint.Address != nil {
		result.ConfigurationEndpoint = &AwsElasticCacheClusterEndpoint{
			Address: *cacheCluster.ConfigurationEndpoint.Address,
			Port:    *cacheCluster.ConfigurationEndpoint.Port,
		}
	}

	for _, cn := range cacheCluster.CacheNodes {
		result.CacheNodes = append(result.CacheNodes, &AwsElasticCacheNode{
			CacheNodeId:              *cn.CacheNodeId,
			CustomerAvailabilityZone: *cn.CustomerAvailabilityZone,
			CreatedAt:                *cn.CacheNodeCreateTime,
			Endpoint: AwsElasticCacheClusterEndpoint{
				Address: *cn.Endpoint.Address,
				Port:    *cn.Endpoint.Port,
			},
			SourceCacheNodeId: cn.SourceCacheNodeId,
		})
	}

	infra.AwsElasticCacheCluster[targetCluster.CacheClusterId] = result

	log.Printf("\t%s\tElastic Cache cluster configured\n", Success)

	return result, nil
}

func (infra *Infrastructure) GetDBConnInfo(name string) (*DBConnInfo, error) {

	// Secret ID used to store the DB username and password across deploys.
	dbSecretId := infra.SecretID(filepath.Join("rds", name))

	var dbInfo *DBConnInfo
	sm := secretsmanager.New(infra.awsCredentials.Session())
	res, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(dbSecretId),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
			return nil, errors.Wrapf(err, "Failed to get value for secret id %s", dbSecretId)
		}
	} else {
		if len(res.SecretBinary) > 0 {
			err = json.Unmarshal(res.SecretBinary, &dbInfo)
		} else {
			err = json.Unmarshal([]byte(*res.SecretString), &dbInfo)
		}

		if err != nil {
			return nil, errors.Wrap(err, "Failed to json decode db credentials")
		}
	}

	return dbInfo, nil
}

func (infra *Infrastructure) SaveDbConnInfo(log *log.Logger, name string, dBConnInfo *DBConnInfo) error {

	// Secret ID used to store the DB username and password across deploys.
	dbSecretId := infra.SecretID(filepath.Join("rds", name))

	// Json encode the db details to be stored as secret text.
	dat, err := json.Marshal(dBConnInfo)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal db credentials")
	}

	// Create the new entry in AWS Secret Manager with the database password.
	sm := secretsmanager.New(infra.awsCredentials.Session())

	_, err = sm.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(dbSecretId),
		SecretBinary: dat,
	})
	if err != nil {
		aerr, ok := err.(awserr.Error)

		if ok && aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException {
			log.Printf("\tCreating new entry in AWS Secret Manager using secret ID %s\n", dbSecretId)

			_, err = sm.CreateSecret(&secretsmanager.CreateSecretInput{
				Name:         aws.String(dbSecretId),
				SecretBinary: dat,
			})
			if err != nil {
				return errors.Wrap(err, "Failed to create new secret with db credentials")
			}

		} else {
			return errors.Wrap(err, "Failed to update new secret with db credentials")
		}
	}

	return nil
}

// GetAwsRdsDBCluster returns *AwsRdsDBClusterResult by database cluster ID.
func (infra *Infrastructure) GetAwsRdsDBCluster(dBClusterIdentifier string) (*AwsRdsDBClusterResult, error) {
	var (
		result *AwsRdsDBClusterResult
		ok     bool
	)
	if infra.AwsRdsDBCluster != nil {
		result, ok = infra.AwsRdsDBCluster[dBClusterIdentifier]
	}
	if !ok {
		return nil, errors.Errorf("No cluster configured for '%s'", dBClusterIdentifier)
	}
	return result, nil
}

// setupAwsRdsDbCluster ensures the AWS RDS database cluster exists else creates it.
func (infra *Infrastructure) setupAwsRdsDbCluster(log *log.Logger, targetCluster *AwsRdsDBCluster, securityGroup *AwsEc2SecurityGroupResult) (*AwsRdsDBClusterResult, error) {
	log.Println("\tRDS - Get or Create Database Cluster")

	input, err := targetCluster.Input(securityGroup)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsRdsDBCluster == nil {
		infra.AwsRdsDBCluster = make(map[string]*AwsRdsDBClusterResult)
	}

	result, ok := infra.AwsRdsDBCluster[targetCluster.DBClusterIdentifier]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.DBClusterArn)
		return result, nil
	}

	dBClusterIdentifier := targetCluster.DBClusterIdentifier

	connInfo, err := infra.GetDBConnInfo(dBClusterIdentifier)
	if err != nil {
		return nil, err
	}

	svc := rds.New(infra.awsCredentials.Session())

	// Try to find a RDS database cluster using cluster identifier.
	var dbCluster *rds.DBCluster
	descRes, err := svc.DescribeDBClusters(&rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(dBClusterIdentifier),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBClusterNotFoundFault {
			return nil, errors.Wrapf(err, "Failed to describe database cluster '%s'", dBClusterIdentifier)
		}
	} else if len(descRes.DBClusters) > 0 {
		dbCluster = descRes.DBClusters[0]
	}

	var created bool
	if dbCluster == nil {
		if connInfo != nil && connInfo.Pass != "" {
			input.MasterUsername = aws.String(connInfo.User)
			input.MasterUserPassword = aws.String(connInfo.Pass)
		}

		// The the password to a random value, it can be manually overwritten with the PreCreate method.
		if input.MasterUserPassword == nil || *input.MasterUserPassword == "" {
			input.MasterUserPassword = aws.String(uuid.NewRandom().String())
		}

		// Store the secret first in the event that create fails.
		if connInfo == nil {
			// Only set the password right now,
			// all other configuration details will be set after the database instance is created.
			connInfo = &DBConnInfo{
				User: *input.MasterUsername,
				Pass: *input.MasterUserPassword,
			}

			err = infra.SaveDbConnInfo(log, dBClusterIdentifier, connInfo)
			if err != nil {
				return nil, err
			}

			log.Printf("\t\tStored Secret\n")
		}

		// If no cluster was found, create one.
		createRes, err := svc.CreateDBCluster(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create cluster '%s'", dBClusterIdentifier)
		}
		dbCluster = createRes.DBCluster
		created = true

		log.Printf("\t\tCreated: %s", *dbCluster.DBClusterArn)
	} else {
		log.Printf("\t\tFound: %s", *dbCluster.DBClusterArn)

		// Store the secret first in the event that create fails.
		if connInfo == nil {
			// Only set the password right now,
			// all other configuration details will be set after the database instance is created.
			connInfo = &DBConnInfo{
				User: *input.MasterUsername,
				Pass: *input.MasterUserPassword,
			}
		}
	}

	// The status of the cluster.
	log.Printf("\t\t\tStatus: %s", *dbCluster.Status)

	// If the instance is not active because it was recently created, wait for it to become active.
	if *dbCluster.Status != "available" {
		retryFunc := func() (bool, error) {
			// Try to find a RDS database cluster using cluster identifier.
			descRes, err := svc.DescribeDBClusters(&rds.DescribeDBClustersInput{
				DBClusterIdentifier: aws.String(dBClusterIdentifier),
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBClusterNotFoundFault {
					return false, errors.Wrapf(err, "Failed to describe database cluster '%s'", dBClusterIdentifier)
				}
			} else if len(descRes.DBClusters) > 0 {
				dbCluster = descRes.DBClusters[0]
			}

			log.Printf("\t\t\tStatus: %s.", *dbCluster.Status)

			if *dbCluster.Status == "available" {
				return true, nil
			}

			return false, nil
		}
		err = retry.Retry(context.Background(), nil, retryFunc)
		if err != nil {
			return nil, err
		}
	}

	// Update the secret with the DB cluster details. This happens after DB create to help address when the
	// DB cluster was successfully created, but the secret failed to save. The DB details host should be empty or
	// match the current cluster endpoint.
	curHost := fmt.Sprintf("%s:%d", *dbCluster.Endpoint, *dbCluster.Port)
	if curHost != connInfo.Host {

		// Copy the cluster details to the DB struct.
		connInfo.Host = curHost
		connInfo.Driver = *dbCluster.Engine
		connInfo.DisableTLS = false

		if dbCluster.DatabaseName != nil {
			connInfo.Database = *dbCluster.DatabaseName
		} else {
			connInfo.Database = *input.DatabaseName
		}

		switch connInfo.Driver {
		case "aurora-postgresql":
			connInfo.Driver = "postgres"
		case "aurora", "aurora-mysql":
			connInfo.Driver = "mysql"
		}

		err = infra.SaveDbConnInfo(log, dBClusterIdentifier, connInfo)
		if err != nil {
			return nil, err
		}

		log.Printf("\t\tUpdate Secret\n")
	}

	// Execute the post AwsRdsDBCluster method if defined.
	if created && targetCluster.AfterCreate != nil {
		// Ensure the newly created database is seeded.
		log.Printf("\t\tOpen database connection")

		db, err := openDbConn(log, connInfo)
		if err != nil {
			return nil, err
		}
		defer db.Close()

		err = targetCluster.AfterCreate(dbCluster, connInfo, db)
		if err != nil {
			return nil, err
		}
	}

	result = &AwsRdsDBClusterResult{
		DBClusterArn:        *dbCluster.DBClusterArn,
		DBClusterIdentifier: *dbCluster.DBClusterIdentifier,
		Endpoint:            *dbCluster.Endpoint,
		Port:                *dbCluster.Port,
		Engine:              *dbCluster.Engine,
		EngineMode:          *dbCluster.EngineMode,
		EngineVersion:       *dbCluster.EngineVersion,
		MasterUsername:      *dbCluster.MasterUsername,
		CreatedAt:           *dbCluster.ClusterCreateTime,
		DBConnInfo:          connInfo,
		InputHash:           inputHash,
	}

	if dbCluster.DatabaseName != nil {
		result.DatabaseName = *dbCluster.DatabaseName
	} else {
		result.DatabaseName = connInfo.Database
	}

	infra.AwsRdsDBCluster[targetCluster.DBClusterIdentifier] = result

	log.Printf("\t%s\tDB Cluster available\n", Success)

	return result, nil
}

// GetAwsRdsDBInstance returns *AwsRdsDBInstanceResult by database instance identifier.
func (infra *Infrastructure) GetAwsRdsDBInstance(dBInstanceIdentifier string) (*AwsRdsDBInstanceResult, error) {
	var (
		result *AwsRdsDBInstanceResult
		ok     bool
	)
	if infra.AwsRdsDBInstance != nil {
		result, ok = infra.AwsRdsDBInstance[dBInstanceIdentifier]
	}
	if !ok {
		return nil, errors.Errorf("No instance configured for '%s'", dBInstanceIdentifier)
	}
	return result, nil
}

// setupAwsRdsDbInstance ensures the AWS RDS database instance exists else creates it.
func (infra *Infrastructure) setupAwsRdsDbInstance(log *log.Logger, targetInstance *AwsRdsDBInstance, securityGroup *AwsEc2SecurityGroupResult) (*AwsRdsDBInstanceResult, error) {
	log.Println("\tRDS - Get or Create Database Instance")

	input, err := targetInstance.Input(securityGroup)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsRdsDBInstance == nil {
		infra.AwsRdsDBInstance = make(map[string]*AwsRdsDBInstanceResult)
	}

	result, ok := infra.AwsRdsDBInstance[targetInstance.DBInstanceIdentifier]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.DBInstanceArn)
		return result, nil
	}

	dBInstanceIdentifier := targetInstance.DBInstanceIdentifier

	if targetInstance.DBClusterIdentifier != nil && *targetInstance.DBClusterIdentifier == dBInstanceIdentifier {
		dBInstanceIdentifier += "db"
	}

	connInfo, err := infra.GetDBConnInfo(dBInstanceIdentifier)
	if err != nil {
		return nil, err
	}

	if (connInfo == nil || connInfo.Host == "") && targetInstance.DBClusterIdentifier != nil && *targetInstance.DBClusterIdentifier != "" {
		connInfo, err = infra.GetDBConnInfo(*targetInstance.DBClusterIdentifier)
		if err != nil {
			return nil, err
		}
	}

	// Init a new RDS client.
	svc := rds.New(infra.awsCredentials.Session())

	// Try to find an existing DB instance with the same identifier.
	var dbInstance *rds.DBInstance
	descRes, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(dBInstanceIdentifier),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != rds.ErrCodeDBInstanceNotFoundFault {
			return nil, errors.Wrapf(err, "Failed to describe database instance '%s'", dBInstanceIdentifier)
		}
	} else if len(descRes.DBInstances) > 0 {
		dbInstance = descRes.DBInstances[0]
	}

	// No DB instance was found, so create a new one.
	var created bool
	if dbInstance == nil {
		//if targetInstance.AwsRdsDBCluster != nil {
		//	cfg.AwsRdsDBInstance.DBClusterIdentifier = aws.String(cfg.AwsRdsDBCluster.DBClusterIdentifier)
		//}

		if targetInstance.DBClusterIdentifier != nil && *targetInstance.DBClusterIdentifier != "" {
			// These properties are set on the db cluster.
			input.MasterUsername = nil
			input.MasterUserPassword = nil
			input.DBName = nil
			input.BackupRetentionPeriod = nil
			input.Port = nil
			input.VpcSecurityGroupIds = nil
			input.DBSubnetGroupName = nil
			input.AllocatedStorage = nil
		} else {
			if connInfo != nil && connInfo.Pass != "" {
				input.MasterUsername = aws.String(connInfo.User)
				input.MasterUserPassword = aws.String(connInfo.Pass)
			}

			// The the password to a random value, it can be manually overwritten with the PreCreate method.
			if input.MasterUserPassword == nil || *input.MasterUserPassword == "" {
				input.MasterUserPassword = aws.String(uuid.NewRandom().String())
			}
		}

		// Only store the db password for the instance when no cluster is defined.
		// Store the secret first in the event that create fails.
		if connInfo == nil || (input.MasterUserPassword != nil && connInfo.Pass != *input.MasterUserPassword) {
			connInfo = &DBConnInfo{
				User: *input.MasterUsername,
				Pass: *input.MasterUserPassword,
			}
		}

		err = infra.SaveDbConnInfo(log, dBInstanceIdentifier, connInfo)
		if err != nil {
			return nil, err
		}
		log.Printf("\t\tStored Secret\n")

		// If no instance was found, create one.
		createRes, err := svc.CreateDBInstance(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create instance '%s'", dBInstanceIdentifier)
		}
		dbInstance = createRes.DBInstance
		created = true

		log.Printf("\t\tCreated: %s", *dbInstance.DBInstanceArn)
	} else {
		log.Printf("\t\tFound: %s", *dbInstance.DBInstanceArn)
	}

	// The status of the instance.
	log.Printf("\t\t\tStatus: %s", *dbInstance.DBInstanceStatus)

	// If the instance is not active because it was recently created, wait for it to become active.
	if *dbInstance.DBInstanceStatus != "available" {
		log.Printf("\t\tWait for instance to become available.")
		err = svc.WaitUntilDBInstanceAvailable(&rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: dbInstance.DBInstanceIdentifier,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to wait for database instance '%s' to enter available state", dBInstanceIdentifier)
		}

		// Try to find an existing DB instance with the same identifier.
		descRes, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(dBInstanceIdentifier),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to describe database instance '%s'", dBInstanceIdentifier)
		} else if len(descRes.DBInstances) > 0 {
			dbInstance = descRes.DBInstances[0]
		}
	}

	// Update the secret with the DB instance details. This happens after DB create to help address when the
	// DB instance was successfully created, but the secret failed to save. The DB details host should be empty or
	// match the current instance endpoint.
	curHost := fmt.Sprintf("%s:%d", *dbInstance.Endpoint.Address, *dbInstance.Endpoint.Port)
	if curHost != connInfo.Host {

		// Copy the instance details to the DB struct.
		connInfo.Host = curHost
		connInfo.Database = *dbInstance.DBName
		connInfo.Driver = *dbInstance.Engine
		connInfo.DisableTLS = false

		switch connInfo.Driver {
		case "aurora-postgresql":
			connInfo.Driver = "postgres"
		case "aurora", "aurora-mysql":
			connInfo.Driver = "mysql"
		}

		err = infra.SaveDbConnInfo(log, dBInstanceIdentifier, connInfo)
		if err != nil {
			return nil, err
		}
		log.Printf("\t\tUpdate Secret\n")
	}

	// Execute the post created method if defined.
	if created && targetInstance.AfterCreate != nil {
		// Ensure the newly created database is seeded.
		log.Printf("\t\tOpen database connection")

		db, err := openDbConn(log, connInfo)
		if err != nil {
			return nil, err
		}
		defer db.Close()

		err = targetInstance.AfterCreate(dbInstance, connInfo, db)
		if err != nil {
			return nil, err
		}
	}

	result = &AwsRdsDBInstanceResult{
		DBClusterIdentifier:  dbInstance.DBClusterIdentifier,
		DBInstanceArn:        *dbInstance.DBInstanceArn,
		DBInstanceClass:      *dbInstance.DBInstanceClass,
		DBInstanceIdentifier: *dbInstance.DBInstanceIdentifier,
		DatabaseName:         *dbInstance.DBName,
		Endpoint:             *dbInstance.Endpoint.Address,
		Port:                 *dbInstance.Endpoint.Port,
		Engine:               *dbInstance.Engine,
		EngineVersion:        *dbInstance.EngineVersion,
		MasterUsername:       *dbInstance.MasterUsername,
		CreatedAt:            *dbInstance.InstanceCreateTime,
		DBConnInfo:           connInfo,
		InputHash:            inputHash,
	}

	infra.AwsRdsDBInstance[targetInstance.DBInstanceIdentifier] = result

	log.Printf("\t%s\tDB Instance available\n", Success)

	return result, nil
}

// GetAwsEcsCluster returns *AwsEcsClusterResult by cluster name.
func (infra *Infrastructure) GetAwsEcsCluster(clusterName string) (*AwsEcsClusterResult, error) {
	var (
		result *AwsEcsClusterResult
		ok     bool
	)
	if infra.AwsEcsCluster != nil {
		result, ok = infra.AwsEcsCluster[clusterName]
	}
	if !ok {
		return nil, errors.Errorf("No cluster configured for '%s'", clusterName)
	}
	return result, nil
}

// setupAwsEcsCluster ensures the AWS ECS cluster exists else creates it.
func (infra *Infrastructure) setupAwsEcsCluster(log *log.Logger, target *AwsEcsCluster) (*AwsEcsClusterResult, error) {

	log.Println("\tECS - Get or create cluster")

	input, err := target.Input()
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsEcsCluster == nil {
		infra.AwsEcsCluster = make(map[string]*AwsEcsClusterResult)
	}

	result, ok := infra.AwsEcsCluster[target.ClusterName]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.ClusterName)
		return result, nil
	}

	svc := ecs.New(infra.AwsSession())

	clusterName := target.ClusterName

	var ecsCluster *ecs.Cluster
	descRes, err := svc.DescribeClusters(&ecs.DescribeClustersInput{
		Clusters: []*string{aws.String(clusterName)},
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != ecs.ErrCodeClusterNotFoundException {
			return nil, errors.Wrapf(err, "Failed to describe cluster '%s'", clusterName)
		}
	} else if len(descRes.Clusters) > 0 {
		ecsCluster = descRes.Clusters[0]
	}

	if ecsCluster == nil || *ecsCluster.Status == "INACTIVE" {
		// If no cluster was found, create one.
		createRes, err := svc.CreateCluster(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create cluster '%s'", clusterName)
		}
		ecsCluster = createRes.Cluster

		log.Printf("\t\tCreated: %s.", *ecsCluster.ClusterArn)
	} else {
		log.Printf("\t\tFound: %s.", *ecsCluster.ClusterArn)

		// The number of services that are running on the cluster in an ACTIVE state.
		// You can view these services with ListServices.
		log.Printf("\t\t\tActiveServicesCount: %d.", *ecsCluster.ActiveServicesCount)
		// The number of tasks in the cluster that are in the PENDING state.
		log.Printf("\t\t\tPendingTasksCount: %d.", *ecsCluster.PendingTasksCount)
		// The number of container instances registered into the cluster. This includes
		// container instances in both ACTIVE and DRAINING status.
		log.Printf("\t\t\tRegisteredContainerInstancesCount: %d.", *ecsCluster.RegisteredContainerInstancesCount)
		// The number of tasks in the cluster that are in the RUNNING state.
		log.Printf("\t\t\tRunningTasksCount: %d.", *ecsCluster.RunningTasksCount)
	}

	// The status of the cluster. The valid values are ACTIVE or INACTIVE. ACTIVE
	// indicates that you can register container instances with the cluster and
	// the associated instances can accept tasks.
	log.Printf("\t\t\tStatus: %s.", *ecsCluster.Status)

	log.Printf("\t%s\tECS Cluster setup.\n", Success)

	result = &AwsEcsClusterResult{
		ClusterArn:  *ecsCluster.ClusterArn,
		ClusterName: *ecsCluster.ClusterName,
		InputHash:   inputHash,
	}
	infra.AwsEcsCluster[target.ClusterName] = result

	log.Printf("\t%s\tECS Cluster available\n", Success)

	return result, nil
}

// setupAwsEcsService ensures the AWS ECS cluster exists else creates it.
func (infra *Infrastructure) setupAwsEcsService(log *log.Logger, cluster *AwsEcsClusterResult, targetService *AwsEcsService, taskDef *AwsEcsTaskDefinitionResult, vpc *AwsEc2VpcResult, securityGroup *AwsEc2SecurityGroupResult, sdService *AwsSdServiceResult, elb *AwsElbLoadBalancerResult) (*AwsEcsServiceResult, error) {

	log.Println("\tECS - Get or create service")

	var ecsELBs []*ecs.LoadBalancer
	if elb != nil {
		for _, tg := range elb.TargetGroups {
			ecsELBs = append(ecsELBs, &ecs.LoadBalancer{
				// The name of the container (as it appears in a container definition) to associate
				// with the load balancer.
				ContainerName: aws.String(targetService.ServiceName),
				// The port on the container to associate with the load balancer. This port
				// must correspond to a containerPort in the service's task definition. Your
				// container instances must allow ingress traffic on the hostPort of the port
				// mapping.
				ContainerPort: aws.Int64(tg.Port),
				// The full Amazon Resource Name (ARN) of the Elastic Load Balancing target
				// group or groups associated with a service or task set.
				TargetGroupArn: aws.String(tg.TargetGroupArn),
			})
		}
	}

	input, err := targetService.CreateInput(cluster, taskDef, vpc, securityGroup, ecsELBs, sdService)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsEcsCluster == nil {
		infra.AwsEcsCluster = make(map[string]*AwsEcsClusterResult)
	}

	result, err := cluster.GetService(targetService.ServiceName)
	if err == nil && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.ServiceName)
		return result, nil
	}

	svc := ecs.New(infra.AwsSession())

	ecsServiceName := targetService.ServiceName

	var ecsService *ecs.Service
	{

		// Try to find AWS ECS Service by name. This does not error on not found, but results are used to determine if
		// the full creation process of a service needs to be executed.
		{
			log.Printf("\t\tList %s services\n", cluster.ClusterName)

			// Find service by ECS cluster and service name.
			res, err := svc.DescribeServices(&ecs.DescribeServicesInput{
				Cluster:  aws.String(cluster.ClusterArn),
				Services: []*string{aws.String(ecsServiceName)},
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != ecs.ErrCodeServiceNotFoundException {
					return nil, errors.Wrapf(err, "Failed to describe service '%s'", ecsServiceName)
				}
			} else if len(res.Services) > 0 {
				ecsService = res.Services[0]

				log.Printf("\t\tFound: %s.", *ecsService.ServiceArn)

				// The desired number of instantiations of the task definition to keep running
				// on the service. This value is specified when the service is created with
				// CreateService, and it can be modified with UpdateService.
				log.Printf("\t\t\tDesiredCount: %d.", *ecsService.DesiredCount)
				// The number of tasks in the cluster that are in the PENDING state.
				log.Printf("\t\t\tPendingCount: %d.", *ecsService.PendingCount)
				// The number of tasks in the cluster that are in the RUNNING state.
				log.Printf("\t\t\tRunningCount: %d.", *ecsService.RunningCount)

				// The status of the service. The valid values are ACTIVE, DRAINING, or INACTIVE.
				log.Printf("\t\t\tStatus: %s.", *ecsService.Status)

				log.Printf("\t%s\tUsing ECS Service '%s'.\n", Success, ecsServiceName)
			} else {
				log.Printf("\t%s\tExisting ECS Service not found.\n", Success)
			}
		}

		// Check to see if the service should be re-created instead of updated.
		if ecsService != nil {
			var (
				recreateService bool
				forceDelete     bool
			)

			if targetService.ForceRecreate {
				// Flag was included to force recreate.
				recreateService = true
				forceDelete = true
			} else if len(ecsELBs) > 0 && (ecsService.LoadBalancers == nil || len(ecsService.LoadBalancers) == 0) {
				// Service was created without ELB and now ELB is enabled.
				recreateService = true
			} else if len(ecsELBs) == 0 && (ecsService.LoadBalancers != nil && len(ecsService.LoadBalancers) > 0) {
				// Service was created with ELB and now ELB is disabled.
				recreateService = true
			} else if sdService != nil && (ecsService.ServiceRegistries == nil || len(ecsService.ServiceRegistries) == 0) {
				// Service was created without Service Discovery and now Service Discovery is enabled.
				recreateService = true
			} else if (sdService == nil) && (ecsService.ServiceRegistries != nil && len(ecsService.ServiceRegistries) > 0) {
				// Service was created with Service Discovery and now Service Discovery is disabled.
				recreateService = true
			}

			// If determined from above that service needs to be recreated.
			if recreateService {

				// Needs to delete any associated services on ECS first before it can be recreated.
				log.Println("\t\tDelete existing Service")

				// The service cannot be stopped while it is scaled above 0.
				if ecsService.DesiredCount != nil && *ecsService.DesiredCount > 0 {
					log.Println("\t\t\tScaling service down to zero.")
					_, err := svc.UpdateService(&ecs.UpdateServiceInput{
						Cluster:      ecsService.ClusterArn,
						Service:      ecsService.ServiceArn,
						DesiredCount: aws.Int64(int64(0)),
					})
					if err != nil {
						return nil, errors.Wrapf(err, "Failed to update service '%s'", *ecsService.ServiceName)
					}

					// It may take some time for the service to scale down, so need to wait.
					log.Println("\t\t\tWait for the service to scale down.")
					err = svc.WaitUntilServicesStable(&ecs.DescribeServicesInput{
						Cluster:  ecsService.ClusterArn,
						Services: aws.StringSlice([]string{*ecsService.ServiceArn}),
					})
					if err != nil {
						return nil, errors.Wrapf(err, "Failed to wait for service '%s' to enter stable state", *ecsService.ServiceName)
					}
				}

				// Once task count is 0 for the service, then can delete it.
				log.Println("\t\t\tDeleting Service.")
				res, err := svc.DeleteService(&ecs.DeleteServiceInput{
					Cluster: ecsService.ClusterArn,
					Service: ecsService.ServiceArn,

					// If true, allows you to delete a service even if it has not been scaled down
					// to zero tasks. It is only necessary to use this if the service is using the
					// REPLICA scheduling strategy.
					Force: aws.Bool(forceDelete),
				})
				if err != nil {
					// If you get the error 'The service cannot be stopped while it is scaled above 0.' then it's
					// likely there is an autoscaling policy setup on the service. Disable autoscaling from the AWS
					// Web Console and try running the deploy for the service again.
					return nil, errors.Wrapf(err, "Failed to delete service '%s'", *ecsService.ServiceName)
				}
				ecsService = res.Service

				log.Println("\t\t\tWait for the service to be deleted.")
				err = svc.WaitUntilServicesInactive(&ecs.DescribeServicesInput{
					Cluster:  ecsService.ClusterArn,
					Services: aws.StringSlice([]string{*ecsService.ServiceArn}),
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to wait for service '%s' to enter stable state", *ecsService.ServiceName)
				}

				// Manually mark the ECS has inactive since WaitUntilServicesInactive was executed.
				ecsService.Status = aws.String("INACTIVE")
			}
		}
	}

	// Step 9: If the service exists on ECS, update the service, else create a new service.
	if ecsService != nil && *ecsService.Status != "INACTIVE" {
		log.Println("\t\tUpdate Service")

		input, err := targetService.UpdateInput(cluster, taskDef, *ecsService.DesiredCount)
		if err != nil {
			return nil, err
		}

		updateRes, err := svc.UpdateService(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to update service '%s'", ecsServiceName)
		}
		ecsService = updateRes.Service

		log.Printf("\t%s\tUpdated ECS Service '%s'.\n", Success, ecsServiceName)
	} else {

		// If not service exists on ECS, then create it.
		log.Println("\t\tCreate Service")

		createRes, err := svc.CreateService(input)

		// If tags aren't enabled for the account, try the request again without them.
		// https://aws.amazon.com/blogs/compute/migrating-your-amazon-ecs-deployment-to-the-new-arn-and-resource-id-format-2/
		if err != nil && strings.Contains(err.Error(), "ARN and resource ID format must be enabled") {
			input.Tags = nil
			createRes, err = svc.CreateService(input)
		}

		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create service '%s'", ecsServiceName)
		}
		ecsService = createRes.Service
	}

	result = &AwsEcsServiceResult{
		ServiceArn:     *ecsService.ServiceArn,
		ServiceName:    *ecsService.ServiceName,
		ClusterArn:     *ecsService.ClusterArn,
		DesiredCount:   *ecsService.DesiredCount,
		LaunchType:     *ecsService.LaunchType,
		TaskDefinition: taskDef,
		InputHash:      inputHash,
	}

	if cluster.Services == nil {
		cluster.Services = make(map[string]*AwsEcsServiceResult)
	}
	cluster.Services[ecsServiceName] = result

	return result, nil
}

// GetRoute53ZoneById returns *AwsRoute53ZoneResult by zone id.
func (infra *Infrastructure) GetRoute53ZoneById(zoneId string) (*AwsRoute53ZoneResult, error) {
	var (
		result *AwsRoute53ZoneResult
		ok     bool
	)
	if infra.AwsRoute53Zone != nil {
		result, ok = infra.AwsRoute53Zone[zoneId]
	}
	if !ok {
		return nil, errors.Errorf("No zone configured for '%s'", zoneId)
	}
	return result, nil
}

// GetRoute53ZoneByDomain returns *AwsRoute53ZoneResult by domain name.
func (infra *Infrastructure) GetRoute53ZoneByDomain(domainName string) (*AwsRoute53ZoneResult, error) {
	var result *AwsRoute53ZoneResult

	var userZoneId string
	if infra.AwsRoute53MapZone != nil {
		var err error
		userZoneId, err = infra.AwsRoute53MapZone(domainName)
		if err != nil {
			return nil, errors.WithMessagef(err, "Failed to map domain '%s' to zone ID", domainName)
		}
	}

	if infra.AwsRoute53Zone != nil {
		for _, z := range infra.AwsRoute53Zone {
			if userZoneId != "" {
				if z.ZoneId == userZoneId {
					result = z
				}
			} else {
				for _, dn := range z.AssocDomains {
					if  dn == domainName {
						result = z
						break
					}
				}
			}

			if result != nil {
				break
			}
		}
	}

	if result == nil {
		return nil, errors.Errorf("No zone configured for domain '%s'", domainName)
	}

	return result, nil
}

// setupAwsRoute53Zones finds all the associated Route 53 zones.
func (infra *Infrastructure) setupAwsRoute53Zones(log *log.Logger, domains []string, vpc *AwsEc2VpcResult) (map[string]*AwsRoute53ZoneResult, error) {

	if infra.AwsRoute53Zone == nil {
		infra.AwsRoute53Zone = make(map[string]*AwsRoute53ZoneResult)
	}

	result := make(map[string]*AwsRoute53ZoneResult)

	if len(domains) == 0 {
		return result, nil
	}

	log.Println("\tRoute 53 - Get or create hosted zones.")

	// Route 53 zone lookup when hostname is set. Supports both top level domains or sub domains.
	// Loop through all the defined domain names and find the associated zone even when they are a sub domain.
	var missingDomains []string
	for _, dn := range domains {
		log.Printf("\t\t\tFind zone for domain '%s'", dn)

		// Loop over each one of hosted zones and try to find match.
		var zoneId string
		if infra.AwsRoute53MapZone != nil {
			var err error
			zoneId, err = infra.AwsRoute53MapZone(dn)
			if err != nil {
				return nil, errors.WithMessagef(err, "Failed to map domain '%s' to zone ID", dn)
			}
		}

		if zoneId == "" {
			for _, z := range infra.AwsRoute53Zone {
				for _, ac := range z.AssocDomains {
					if ac == dn {
						zoneId = z.ZoneId
						result[zoneId] = z
						break
					}
				}

				if zoneId != "" {
					break
				}
			}
		}

		if zoneId != "" {
			log.Printf("\t\t\t\tFound hosted zone '%s'", zoneId)
		} else {
			missingDomains = append(missingDomains, dn)
		}
	}

	if len(missingDomains) == 0 {
		return result, nil
	}

	svc := route53.New(infra.AwsSession())

	log.Println("\t\tList all hosted zones.")
	var zones []*route53.HostedZone
	err := svc.ListHostedZonesPages(&route53.ListHostedZonesInput{},
		func(res *route53.ListHostedZonesOutput, lastPage bool) bool {
			for _, z := range res.HostedZones {
				zones = append(zones, z)
			}
			return !lastPage
		})
	if err != nil {
		return nil, errors.Wrap(err, "Failed list route 53 hosted zones")
	}

	for _, dn := range missingDomains {

		// Get the top level domain from url.
		zoneName := domainutil.Domain(dn)
		var subdomain string
		if zoneName == "" {
			// Handle domain names that have weird TDL: ie .tech
			zoneName = dn
			log.Printf("\t\t\t\tNon-standard Level Domain: '%s'", zoneName)
		} else {
			log.Printf("\t\t\t\tTop Level Domain: '%s'", zoneName)

			// Check if url has subdomain.
			if domainutil.HasSubdomain(dn) {
				subdomain = domainutil.Subdomain(dn)
				log.Printf("\t\t\t\tsubdomain: '%s'", subdomain)
			}
		}

		// Start at the top level domain and try to find a hosted zone. Search until a match is found or there are
		// no more domain levels to search for.
		var zone *route53.HostedZone
		for {
			log.Printf("\t\t\t\tChecking zone '%s' for associated hosted zone.", zoneName)

			// Loop over each one of hosted zones and try to find match.
			for _, z := range zones {
				zn := strings.TrimRight(*z.Name, ".")

				log.Printf("\t\t\t\t\tChecking if '%s' matches '%s'", zn, zoneName)
				if zn == zoneName {
					zone = z
					break
				}
			}

			if zone != nil || zoneName == dn {
				// Found a matching zone or have to search all possibilities!
				break
			}

			// If we have not found a hosted zone, append the next level from the domain to the zone.
			pts := strings.Split(subdomain, ".")
			subs := []string{}
			for idx, sn := range pts {
				if idx == len(pts)-1 {
					zoneName = sn + "." + zoneName
				} else {
					subs = append(subs, sn)
				}
			}
			subdomain = strings.Join(subs, ".")
		}

		var aName string
		if zone == nil {

			// Get the top level domain from url again.
			zoneName := domainutil.Domain(dn)
			if zoneName == "" {
				// Handle domain names that have weird TDL: ie .tech
				zoneName = dn
			}

			log.Printf("\t\t\t\tNo hosted zone found for '%s', create '%s'.", dn, zoneName)
			hzReq := &route53.CreateHostedZoneInput{
				Name: aws.String(zoneName),
				HostedZoneConfig: &route53.HostedZoneConfig{
					Comment: aws.String(fmt.Sprintf("Public hosted zone created by saas-starter-kit.")),
				},

				// A unique string that identifies the request and that allows failed CreateHostedZone
				// requests to be retried without the risk of executing the operation twice.
				// You must use a unique CallerReference string every time you submit a CreateHostedZone
				// request. CallerReference can be any unique string, for example, a date/time
				// stamp.
				//
				// CallerReference is a required field
				CallerReference: aws.String(fmt.Sprintf("devops-deploy-%s-%d", zoneName, time.Now().Unix())),
			}
			if infra.awsCredentials.IsGov() {
				hzReq.HostedZoneConfig.PrivateZone = aws.Bool(true)
				hzReq.VPC = &route53.VPC{
					VPCId: &vpc.VpcId,
					VPCRegion: &infra.awsCredentials.Region,
				}
			}

			createRes, err := svc.CreateHostedZone(hzReq)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to create route 53 hosted zone '%s' for domain '%s'", zoneName, dn)
			}
			zone = createRes.HostedZone

			log.Printf("\t\t\t\tCreated hosted zone '%s'", *zone.Id)

			// The fully qualified A record name.
			aName = dn
		} else {
			log.Printf("\t\t\t\tFound hosted zone '%s'", *zone.Id)

			// The fully qualified A record name.
			if subdomain != "" {
				aName = subdomain + "." + zoneName
			} else {
				aName = zoneName
			}
		}

		// Add the A record to be maintained for the zone.
		if _, ok := infra.AwsRoute53Zone[*zone.Id]; !ok {
			infra.AwsRoute53Zone[*zone.Id] = &AwsRoute53ZoneResult{
				ZoneId:       *zone.Id,
				Name:         *zone.Name,
				Entries:      []string{},
				AssocDomains: []string{},
			}
		}

		infra.AwsRoute53Zone[*zone.Id].Entries = append(infra.AwsRoute53Zone[*zone.Id].Entries, aName)
		infra.AwsRoute53Zone[*zone.Id].AssocDomains = append(infra.AwsRoute53Zone[*zone.Id].AssocDomains, dn)

		result[*zone.Id] = infra.AwsRoute53Zone[*zone.Id]

		log.Printf("\t%s\tZone '%s' found with A record name '%s'.\n", Success, *zone.Id, aName)
	}

	log.Printf("\t%s\tZones available\n", Success)

	return result, nil
}

// GetAwsSdPrivateDnsNamespace returns *AwsSdPrivateDnsNamespaceResult by cluster name.
func (infra *Infrastructure) GetAwsSdPrivateDnsNamespace(namespace string) (*AwsSdPrivateDnsNamespaceResult, error) {
	var (
		result *AwsSdPrivateDnsNamespaceResult
		ok     bool
	)
	if infra.AwsSdPrivateDnsNamespace != nil {
		result, ok = infra.AwsSdPrivateDnsNamespace[namespace]
	}
	if !ok {
		return nil, errors.Errorf("No namespace configured for '%s'", namespace)
	}
	return result, nil
}

// GetService returns *AwsSdServiceResult by service name.
func (res *AwsSdPrivateDnsNamespaceResult) GetService(serviceName string) (*AwsSdServiceResult, error) {
	var (
		result *AwsSdServiceResult
		ok     bool
	)
	if res.Services != nil {
		result, ok = res.Services[serviceName]
	}
	if !ok {
		return nil, errors.Errorf("No service configured for '%s'", serviceName)
	}
	return result, nil
}

// setupAwsSdPrivateDnsNamespace ensures the AWS Service Discovery namespace exists else creates it.
func (infra *Infrastructure) setupAwsSdPrivateDnsNamespace(log *log.Logger, target *AwsSdPrivateDnsNamespace, vpc *AwsEc2VpcResult) (*AwsSdPrivateDnsNamespaceResult, error) {

	log.Println("\tService Discovery - Get or create namespace")

	input, err := target.Input(vpc)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsSdPrivateDnsNamespace == nil {
		infra.AwsSdPrivateDnsNamespace = make(map[string]*AwsSdPrivateDnsNamespaceResult)
	}

	result, ok := infra.AwsSdPrivateDnsNamespace[target.Name]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", target.Name)
		return result, nil
	}

	svc := servicediscovery.New(infra.AwsSession())

	namespaceName := target.Name

	log.Println("\t\tList all the private namespaces and try to find an existing entry.")

	listNamespaces := func() (*servicediscovery.NamespaceSummary, error) {
		var found *servicediscovery.NamespaceSummary
		err := svc.ListNamespacesPages(&servicediscovery.ListNamespacesInput{
			Filters: []*servicediscovery.NamespaceFilter{
				&servicediscovery.NamespaceFilter{
					Name:      aws.String("TYPE"),
					Condition: aws.String("EQ"),
					Values:    aws.StringSlice([]string{"DNS_PRIVATE"}),
				},
			},
		}, func(res *servicediscovery.ListNamespacesOutput, lastPage bool) bool {
			for _, n := range res.Namespaces {
				if *n.Name == namespaceName {
					found = n
					return false
				}
			}
			return !lastPage
		})
		if err != nil {
			return nil, errors.Wrap(err, "Failed to list namespaces")
		}

		return found, nil
	}

	sdNamespace, err := listNamespaces()
	if err != nil {
		return nil, err
	}

	if sdNamespace == nil {
		log.Println("\t\tCreate private namespace.")

		// If no namespace was found, create one.
		createRes, err := svc.CreatePrivateDnsNamespace(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create namespace '%s'", namespaceName)
		}
		operationId := createRes.OperationId

		log.Println("\t\tWait for create operation to finish.")
		retryFunc := func() (bool, error) {
			opRes, err := svc.GetOperation(&servicediscovery.GetOperationInput{
				OperationId: operationId,
			})
			if err != nil {
				return true, err
			}

			log.Printf("\t\t\tStatus: %s.", *opRes.Operation.Status)

			// The status of the operation. Values include the following:
			//    * SUBMITTED: This is the initial state immediately after you submit a
			//    request.
			//    * PENDING: AWS Cloud Map is performing the operation.
			//    * SUCCESS: The operation succeeded.
			//    * FAIL: The operation failed. For the failure reason, see ErrorMessage.
			if *opRes.Operation.Status == "SUCCESS" {
				return true, nil
			} else if *opRes.Operation.Status == "FAIL" {
				err = errors.Errorf("Operation failed")
				err = awserr.New(*opRes.Operation.ErrorCode, *opRes.Operation.ErrorMessage, err)
				return true, err
			}

			return false, nil
		}
		err = retry.Retry(context.Background(), nil, retryFunc)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to get operation for namespace '%s'", namespaceName)
		}

		// Now that the create operation is complete, try to find the namespace again.
		sdNamespace, err = listNamespaces()
		if err != nil {
			return nil, err
		}

		log.Printf("\t\tCreated: %s.", *sdNamespace.Arn)
	} else {
		log.Printf("\t\tFound: %s.", *sdNamespace.Arn)

		// The number of services that are associated with the namespace.
		if sdNamespace.ServiceCount != nil {
			log.Printf("\t\t\tServiceCount: %d.", *sdNamespace.ServiceCount)
		}
	}

	var curServices map[string]*AwsSdServiceResult
	if result != nil {
		curServices = result.Services
	}

	result = &AwsSdPrivateDnsNamespaceResult{
		Id:        *sdNamespace.Id,
		Name:      *sdNamespace.Name,
		Arn:       *sdNamespace.Arn,
		Type:      *sdNamespace.Type,
		InputHash: inputHash,
		Services:  curServices,
	}
	infra.AwsSdPrivateDnsNamespace[result.Name] = result

	log.Printf("\t%s\tService Discovery Namespace available\n", Success)

	return result, nil
}

// setupAwsSdService ensures the AWS Service Discovery service exists for a namespace else creates it.
func (infra *Infrastructure) setupAwsSdService(log *log.Logger, sdNamespace *AwsSdPrivateDnsNamespaceResult, target *AwsSdService) (*AwsSdServiceResult, error) {

	log.Printf("\tService Discovery - Get or create service %s\n", target.Name)

	input, err := target.Input(sdNamespace)
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	result, err := sdNamespace.GetService(target.Name)
	if err == nil && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", target.Name)
		return result, nil
	}

	svc := servicediscovery.New(infra.AwsSession())

	// Try to find an existing entry for the current service.
	var sdService *servicediscovery.ServiceSummary
	err = svc.ListServicesPages(&servicediscovery.ListServicesInput{
		Filters: []*servicediscovery.ServiceFilter{
			&servicediscovery.ServiceFilter{
				Name:      aws.String("NAMESPACE_ID"),
				Condition: aws.String("EQ"),
				Values:    aws.StringSlice([]string{sdNamespace.Id}),
			},
		},
	}, func(res *servicediscovery.ListServicesOutput, lastPage bool) bool {
		for _, n := range res.Services {
			if *n.Name == target.Name {
				sdService = n
				return false
			}
		}
		return !lastPage
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to list services for namespace '%s'", sdNamespace.Id)
	}

	if sdService == nil {

		// If no namespace was found, create one.
		createRes, err := svc.CreateService(input)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create service '%s'", sdService.Name)
		}
		result = &AwsSdServiceResult{
			Id:          *createRes.Service.Id,
			Name:        *createRes.Service.Name,
			Arn:         *createRes.Service.Arn,
			NamespaceId: sdNamespace.Id,
			InputHash:   inputHash,
		}

		log.Printf("\t\tCreated: %s.", result.Arn)
	} else {

		result = &AwsSdServiceResult{
			Id:          *sdService.Id,
			Name:        *sdService.Name,
			Arn:         *sdService.Arn,
			NamespaceId: sdNamespace.Id,
			InputHash:   inputHash,
		}

		log.Printf("\t\tFound: %s.", result.Arn)
	}

	if sdNamespace.Services == nil {
		sdNamespace.Services = make(map[string]*AwsSdServiceResult)
	}
	sdNamespace.Services[result.Name] = result

	log.Printf("\t%s\tService Discovery Service setup\n", Success)

	return result, nil
}

// GetAwsCloudWatchLogGroup returns *AwsCloudWatchLogGroupResult by name.
func (infra *Infrastructure) GetAwsCloudWatchLogGroup(logGroupName string) (*AwsCloudWatchLogGroupResult, error) {
	var (
		result *AwsCloudWatchLogGroupResult
		ok     bool
	)
	if infra.AwsCloudWatchLogGroup != nil {
		result, ok = infra.AwsCloudWatchLogGroup[logGroupName]
	}
	if !ok {
		return nil, errors.Errorf("No log group configured for '%s'", logGroupName)
	}
	return result, nil
}

// setupAwsCloudWatchLogGroup ensures the AWS Cloudwatch log group exists else creates it.
func (infra *Infrastructure) setupAwsCloudWatchLogGroup(log *log.Logger, target *AwsCloudWatchLogGroup) (*AwsCloudWatchLogGroupResult, error) {

	log.Println("\tCloudWatch - Get or create log group")

	input, err := target.Input()
	if err != nil {
		return nil, err
	}
	inputHash := getInputHash(input)

	if infra.AwsCloudWatchLogGroup == nil {
		infra.AwsCloudWatchLogGroup = make(map[string]*AwsCloudWatchLogGroupResult)
	}

	result, ok := infra.AwsCloudWatchLogGroup[target.LogGroupName]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.LogGroupName)
		return result, nil
	}

	svc := cloudwatchlogs.New(infra.AwsSession())

	logGroupName := target.LogGroupName

	// If no log group was found, create one.
	_, err = svc.CreateLogGroup(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != cloudwatchlogs.ErrCodeResourceAlreadyExistsException {
			return nil, errors.Wrapf(err, "Failed to create log group '%s'", logGroupName)
		}

		log.Printf("\t\tFound: %s", logGroupName)
	} else {
		log.Printf("\t\tCreated: %s", logGroupName)
	}

	result = &AwsCloudWatchLogGroupResult{
		LogGroupName: logGroupName,
		InputHash:    inputHash,
	}
	infra.AwsCloudWatchLogGroup[target.LogGroupName] = result

	log.Printf("\t%s\tLog Group available\n", Success)

	return result, nil
}

// GetAwsAcmCertificate returns *AwsAcmCertificateResult by domain name.
func (infra *Infrastructure) GetAwsAcmCertificate(domainName string) (*AwsAcmCertificateResult, error) {
	var (
		result *AwsAcmCertificateResult
		ok     bool
	)
	if infra.AwsAcmCertificate != nil {
		result, ok = infra.AwsAcmCertificate[domainName]
	}
	if !ok {
		return nil, errors.Errorf("No certificate configured for '%s'", domainName)
	}
	return result, nil
}

// setupAwsAcmCertificate ensures the AWS ACM certificate exists else creates it.
func (infra *Infrastructure) setupAwsAcmCertificate(log *log.Logger, domainName string, alternativeNames []string) (*AwsAcmCertificateResult, error) {

	log.Println("\tACM - Get or create certificate")

	input := &acm.RequestCertificateInput{
		// Fully qualified domain name (FQDN), such as www.example.com, that you want
		// to secure with an ACM certificate. Use an asterisk (*) to create a wildcard
		// certificate that protects several sites in the same domain. For example,
		// *.example.com protects www.example.com, site.example.com, and images.example.com.
		//
		// The first domain name you enter cannot exceed 63 octets, including periods.
		// Each subsequent Subject Alternative Name (SAN), however, can be up to 253
		// octets in length.
		//
		// DomainName is a required field
		DomainName: aws.String(domainName),

		// Currently, you can use this parameter to specify whether to add the certificate
		// to a certificate transparency log. Certificate transparency makes it possible
		// to detect SSL/TLS certificates that have been mistakenly or maliciously issued.
		// Certificates that have not been logged typically produce an error message
		// in a browser. For more information, see Opting Out of Certificate Transparency
		// Logging (https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html#best-practices-transparency).
		Options: &acm.CertificateOptions{
			CertificateTransparencyLoggingPreference: aws.String("DISABLED"),
		},

		// The method you want to use if you are requesting a public certificate to
		// validate that you own or control domain. You can validate with DNS (https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html)
		// or validate with email (https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html).
		// We recommend that you use DNS validation.
		ValidationMethod: aws.String("DNS"),
	}

	if len(alternativeNames) > 0 {
		// Additional FQDNs to be included in the Subject Alternative Name extension
		// of the ACM certificate. For example, add the name www.example.net to a certificate
		// for which the DomainName field is www.example.com if users can reach your
		// site by using either name. The maximum number of domain names that you can
		// add to an ACM certificate is 100. However, the initial limit is 10 domain
		// names. If you need more than 10 names, you must request a limit increase.
		// For more information, see Limits (https://docs.aws.amazon.com/acm/latest/userguide/acm-limits.html).
		input.SubjectAlternativeNames = aws.StringSlice(alternativeNames)
	}

	inputHash := getInputHash(input)

	if infra.AwsAcmCertificate == nil {
		infra.AwsAcmCertificate = make(map[string]*AwsAcmCertificateResult)
	}

	result, ok := infra.AwsAcmCertificate[domainName]
	if ok && result != nil && result.InputHash == inputHash && result.Status != "PENDING_VALIDATION" && !infra.skipCache {
		log.Printf("\t\tExists: %s", domainName)
		return result, nil
	}

	svc := acm.New(infra.AwsSession())

	var certificateArn string
	err := svc.ListCertificatesPages(&acm.ListCertificatesInput{},
		func(res *acm.ListCertificatesOutput, lastPage bool) bool {
			for _, cert := range res.CertificateSummaryList {
				if *cert.DomainName == domainName {
					certificateArn = *cert.CertificateArn
					return false
				}
			}
			return !lastPage
		})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to list certificates for '%s'", domainName)
	}

	if certificateArn == "" {
		// Customer chosen string that can be used to distinguish between calls to RequestCertificate.
		// Idempotency tokens time out after one hour. Therefore, if you call RequestCertificate
		// multiple times with the same idempotency token within one hour, ACM recognizes
		// that you are requesting only one certificate and will issue only one. If
		// you change the idempotency token for each call, ACM recognizes that you are
		// requesting multiple certificates.
		// Create hash of all the domain names to be used to mark unique requests.
		idempotencyToken := domainName + "|" + strings.Join(alternativeNames, "|")
		idempotencyToken = fmt.Sprintf("%x", md5.Sum([]byte(idempotencyToken)))

		input.IdempotencyToken = aws.String(idempotencyToken)

		// If no certicate was found, create one.
		createRes, err := svc.RequestCertificate(input)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create certificate '%s'", domainName)
		}
		certificateArn = *createRes.CertificateArn

		log.Printf("\t\tCreated certificate '%s'", domainName)
	} else {
		log.Printf("\t\tFound certificate '%s'", domainName)
	}

	descRes, err := svc.DescribeCertificate(&acm.DescribeCertificateInput{
		CertificateArn: aws.String(certificateArn),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to describe certificate '%s'", certificateArn)
	}
	cert := descRes.Certificate

	log.Printf("\t\t\tStatus: %s", *cert.Status)

	if *cert.Status == "PENDING_VALIDATION" {
		svc := route53.New(infra.AwsSession())

		log.Println("\t\t\tList all hosted zones.")

		var zoneValOpts = map[string][]*acm.DomainValidation{}
		for _, opt := range cert.DomainValidationOptions {

			zone, err := infra.GetRoute53ZoneByDomain(*opt.DomainName)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to find zone ID for '%s'", *opt.DomainName)
			}

			if _, ok := zoneValOpts[zone.ZoneId]; !ok {
				zoneValOpts[zone.ZoneId] = []*acm.DomainValidation{}
			}
			zoneValOpts[zone.ZoneId] = append(zoneValOpts[zone.ZoneId], opt)
		}

		for zoneId, opts := range zoneValOpts {
			for _, opt := range opts {
				if *opt.ValidationStatus == "SUCCESS" {
					continue
				}

				input := &route53.ChangeResourceRecordSetsInput{
					ChangeBatch: &route53.ChangeBatch{
						Changes: []*route53.Change{
							&route53.Change{
								Action: aws.String("UPSERT"),
								ResourceRecordSet: &route53.ResourceRecordSet{
									Name: opt.ResourceRecord.Name,
									ResourceRecords: []*route53.ResourceRecord{
										&route53.ResourceRecord{Value: opt.ResourceRecord.Value},
									},
									Type: opt.ResourceRecord.Type,
									TTL:  aws.Int64(60),
								},
							},
						},
					},
					HostedZoneId: aws.String(zoneId),
				}

				log.Printf("\t\t\tAdded verification record for '%s'.\n", *opt.ResourceRecord.Name)
				_, err := svc.ChangeResourceRecordSets(input)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to update A records for zone '%s'", zoneId)
				}
			}
		}
	}

	result = &AwsAcmCertificateResult{
		CertificateArn: certificateArn,
		DomainName:     domainName,
		Status:         *cert.Status,
		InputHash:      inputHash,
	}
	infra.AwsAcmCertificate[domainName] = result

	log.Printf("\t%s\tCertificate available\n", Success)

	return result, nil
}

// GetAwsElbLoadBalancer returns *AwsElbLoadBalancerResult by load balancer name.
func (infra *Infrastructure) GetAwsElbLoadBalancer(loadBalancerName string) (*AwsElbLoadBalancerResult, error) {
	var (
		result *AwsElbLoadBalancerResult
		ok     bool
	)
	if infra.AwsElbLoadBalancer != nil {
		result, ok = infra.AwsElbLoadBalancer[loadBalancerName]
	}
	if !ok {
		return nil, errors.Errorf("No load balancer configured for '%s'", loadBalancerName)
	}
	return result, nil
}

// setupAwsElbLoadBalancer ensures the AWS ELB load balancer exists else creates it.
func (infra *Infrastructure) setupAwsElbLoadBalancer(log *log.Logger, definedElb *AwsElbLoadBalancer, vpc *AwsEc2VpcResult, securityGroup *AwsEc2SecurityGroupResult, zones map[string]*AwsRoute53ZoneResult, targetService *ProjectService) (*AwsElbLoadBalancerResult, error) {

	log.Println("\tELB - Get or create load balancer")

	// Append default listeners for port 80 and 443 if not are defined.
	if len(definedElb.Listeners) == 0 {
		listenerPorts := map[string]int64{
			"HTTP": 80,
		}

		if targetService.EnableHTTPS {
			listenerPorts["HTTPS"] = 443
		}

		for listenerProtocol, listenerPort := range listenerPorts {
			listenerInput := &AwsElbListener{
				// The port on which the load balancer is listening.
				Port: listenerPort,

				// The protocol for connections from clients to the load balancer. For Application
				// Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load
				// Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP.
				Protocol: listenerProtocol,
			}

			if listenerProtocol == "HTTPS" {
				// If HTTPS enabled on ELB, then need to find ARN certificates first.
				certificate, err := infra.setupAwsAcmCertificate(log, targetService.ServiceHostPrimary, targetService.ServiceHostNames)
				if err != nil {
					return nil, err
				}

				listenerInput.Certificates = append(listenerInput.Certificates, &AwsElbCertificate{
					CertificateArn: certificate.CertificateArn,
				})
			}

			// Dynamically attach the LoadBalancer target groups to the listener.
			listenerInput.PreCreate = func(elb *AwsElbLoadBalancerResult, input *elbv2.CreateListenerInput) error {
				// The actions for the default rule. The rule must include one forward action
				// or one or more fixed-response actions.
				//
				// If the action type is forward, you specify a target group. The protocol of
				// the target group must be HTTP or HTTPS for an Application Load Balancer.
				// The protocol of the target group must be TCP, TLS, UDP, or TCP_UDP for a
				// Network Load Balancer.
				input.DefaultActions = []*elbv2.Action{}

				for _, tg := range elb.TargetGroups {
					input.DefaultActions = append(input.DefaultActions, &elbv2.Action{
						// The type of action. Each rule must include exactly one of the following types
						// of actions: forward, fixed-response, or redirect.
						Type: aws.String("forward"),

						// The Amazon Resource Name (ARN) of the target group. Specify only when Type is forward.
						TargetGroupArn: aws.String(tg.TargetGroupArn),
					})
				}

				return nil
			}

			targetService.AwsElbLoadBalancer.Listeners = append(targetService.AwsElbLoadBalancer.Listeners, listenerInput)
		}
	}

	elbInput, err := definedElb.Input(vpc, securityGroup)
	if err != nil {
		return nil, err
	}

	var inputHash string
	{
		var targetGroupInputs []*elbv2.CreateTargetGroupInput
		for _, tg := range definedElb.TargetGroups {
			groupInput, err := tg.Input(vpc)
			if err != nil {
				return nil, err
			}
			targetGroupInputs = append(targetGroupInputs, groupInput)
		}

		var listenerInputs []*elbv2.CreateListenerInput
		for _, tg := range definedElb.Listeners {
			groupInput, err := tg.Input(nil)
			if err != nil {
				return nil, err
			}
			listenerInputs = append(listenerInputs, groupInput)
		}

		inputHash = getInputHash(elbInput, targetGroupInputs, listenerInputs)
	}

	if infra.AwsElbLoadBalancer == nil {
		infra.AwsElbLoadBalancer = make(map[string]*AwsElbLoadBalancerResult)
	}

	result, ok := infra.AwsElbLoadBalancer[definedElb.Name]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", definedElb.Name)
		return result, nil
	}

	svc := elbv2.New(infra.AwsSession())

	loadBalancerName := definedElb.Name

	// Try to find load balancer given a name.
	var elb *elbv2.LoadBalancer
	err = svc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{
		Names: []*string{aws.String(loadBalancerName)},
	}, func(res *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
		// Loop through the results to find the match ELB.
		for _, lb := range res.LoadBalancers {
			if *lb.LoadBalancerName == loadBalancerName {
				elb = lb
				return false
			}
		}
		return !lastPage
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elbv2.ErrCodeLoadBalancerNotFoundException {
			return nil, errors.Wrapf(err, "Failed to describe load balancer '%s'", loadBalancerName)
		}
	}

	var listeners []*elbv2.Listener
	if elb == nil {

		// If no repository was found, create one.
		createRes, err := svc.CreateLoadBalancer(elbInput)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create load balancer '%s'", loadBalancerName)
		}
		elb = createRes.LoadBalancers[0]

		log.Printf("\t\tCreated: %s.", *elb.LoadBalancerArn)
	} else {
		log.Printf("\t\tFound: %s.", *elb.LoadBalancerArn)

		// Search for existing listeners associated with the load balancer.
		res, err := svc.DescribeListeners(&elbv2.DescribeListenersInput{
			// The Amazon Resource Name (ARN) of the load balancer.
			LoadBalancerArn: aws.String(*elb.LoadBalancerArn),
			// There are two target groups, return both associated listeners if they exist.
			PageSize: aws.Int64(2),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to find listeners for load balancer '%s'", loadBalancerName)
		}
		listeners = res.Listeners
	}

	// The state code. The initial state of the load balancer is provisioning. After
	// the load balancer is fully set up and ready to route traffic, its state is
	// active. If the load balancer could not be set up, its state is failed.
	log.Printf("\t\t\tState: %s.", *elb.State.Code)

	var (
		curListeners    []*AwsElbListenerResult
		curTargetGroups []*AwsElbTargetGroupResult
	)
	if result != nil {
		curListeners = result.Listeners
		curTargetGroups = result.TargetGroups
	}

	result = &AwsElbLoadBalancerResult{
		DNSName:               *elb.DNSName,
		CanonicalHostedZoneId: *elb.CanonicalHostedZoneId,
		IpAddressType:         *elb.IpAddressType,
		LoadBalancerArn:       *elb.LoadBalancerArn,
		LoadBalancerName:      *elb.LoadBalancerName,
		Scheme:                *elb.Scheme,
		InputHash:             inputHash,
	}

	log.Println("\t\tConfigure Target Groups")
	for _, tg := range definedElb.TargetGroups {

		groupInput, err := tg.Input(vpc)
		if err != nil {
			return nil, err
		}
		inputHash := getInputHash(groupInput, definedElb.EcsTaskDeregistrationDelay)

		var groupResult *AwsElbTargetGroupResult
		for _, cg := range curTargetGroups {
			if cg.TargetGroupName == tg.Name && cg.InputHash == inputHash && !infra.skipCache {
				groupResult = cg
				break
			}
		}

		if groupResult != nil {
			log.Printf("\t\t\tTarget Group %s exists: %s", groupResult.TargetGroupName, groupResult.TargetGroupArn)
		} else {
			targetGroupName := tg.Name

			var targetGroup *elbv2.TargetGroup
			err = svc.DescribeTargetGroupsPages(&elbv2.DescribeTargetGroupsInput{
				LoadBalancerArn: aws.String(*elb.LoadBalancerArn),
			}, func(res *elbv2.DescribeTargetGroupsOutput, lastPage bool) bool {
				for _, tg := range res.TargetGroups {
					if *tg.TargetGroupName == targetGroupName {
						targetGroup = tg
						return false
					}
				}
				return !lastPage
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elbv2.ErrCodeTargetGroupNotFoundException {
					return nil, errors.Wrapf(err, "Failed to describe target group '%s'", targetGroupName)
				}
			}

			if targetGroup == nil {
				// If no target group was found, create one.
				createRes, err := svc.CreateTargetGroup(groupInput)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to create target group '%s'", targetGroupName)
				}
				targetGroup = createRes.TargetGroups[0]

				log.Printf("\t\t\tTarget Group %s created: %s", *targetGroup.TargetGroupName, *targetGroup.TargetGroupArn)
			} else {
				log.Printf("\t\t\tTarget Group %s found: %s", *targetGroup.TargetGroupName, *targetGroup.TargetGroupArn)
			}

			if definedElb.EcsTaskDeregistrationDelay > 0 {
				// If no target group was found, create one.
				_, err = svc.ModifyTargetGroupAttributes(&elbv2.ModifyTargetGroupAttributesInput{
					TargetGroupArn: targetGroup.TargetGroupArn,
					Attributes: []*elbv2.TargetGroupAttribute{
						&elbv2.TargetGroupAttribute{
							// The name of the attribute.
							Key: aws.String("deregistration_delay.timeout_seconds"),

							// The value of the attribute.
							Value: aws.String(strconv.Itoa(definedElb.EcsTaskDeregistrationDelay)),
						},
					},
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to modify target group '%s' attributes", targetGroupName)
				}

				log.Printf("\t\t\t\tSet sttributes.")
			}

			groupResult = &AwsElbTargetGroupResult{
				HealthCheckEnabled:         *targetGroup.HealthCheckEnabled,
				HealthCheckIntervalSeconds: *targetGroup.HealthCheckIntervalSeconds,
				HealthCheckPath:            *targetGroup.HealthCheckPath,
				HealthCheckPort:            *targetGroup.HealthCheckPort,
				HealthCheckProtocol:        *targetGroup.HealthCheckProtocol,
				HealthCheckTimeoutSeconds:  *targetGroup.HealthCheckTimeoutSeconds,
				HealthyThresholdCount:      *targetGroup.HealthyThresholdCount,
				Port:                       *targetGroup.Port,
				Protocol:                   *targetGroup.Protocol,
				TargetGroupArn:             *targetGroup.TargetGroupArn,
				TargetGroupName:            *targetGroup.TargetGroupName,
				TargetType:                 *targetGroup.TargetType,
				UnhealthyThresholdCount:    *targetGroup.UnhealthyThresholdCount,
				VpcId:                      *targetGroup.VpcId,
				InputHash:                  inputHash,
			}
			for _, arn := range targetGroup.LoadBalancerArns {
				groupResult.LoadBalancerArns = append(groupResult.LoadBalancerArns, *arn)
			}

			if targetGroup.Matcher != nil && targetGroup.Matcher.HttpCode != nil {
				groupResult.Matcher = *targetGroup.Matcher.HttpCode
			}
		}

		result.TargetGroups = append(result.TargetGroups, groupResult)
	}

	// TODO: Loop through the current target groups for any that have been renamed or removed and delete them.

	log.Println("\t\tConfigure Listeners")
	for _, l := range definedElb.Listeners {

		listenerInput, err := l.Input(result)
		if err != nil {
			return nil, err
		}
		inputHash = getInputHash(listenerInput)

		var listenerResult *AwsElbListenerResult
		for _, cl := range curListeners {
			if cl.Protocol == l.Protocol && cl.Port == l.Port && cl.InputHash == inputHash && !infra.skipCache {
				listenerResult = cl
				break
			}
		}

		if listenerResult != nil {
			log.Printf("\t\t\tListener %s %d exists: %s", listenerResult.Protocol, listenerResult.Port, listenerResult.ListenerArn)
		} else {

			var listener *elbv2.Listener
			for _, cl := range listeners {
				if *cl.Protocol == l.Protocol && *cl.Port == l.Port {
					listener = cl
					break
				}
			}

			if listener == nil {
				// If no listener was found, create one.
				createRes, err := svc.CreateListener(listenerInput)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to create listener for %s %d", l.Protocol, l.Port)
				}
				listener = createRes.Listeners[0]

				log.Printf("\t\t\tListener for %s %d created: %s", l.Protocol, l.Port, *listener.ListenerArn)
			} else {
				log.Printf("\t\t\tListener for %s %d found: %s", l.Protocol, l.Port, *listener.ListenerArn)
			}

			listenerResult = &AwsElbListenerResult{
				ListenerArn:     *listener.ListenerArn,
				LoadBalancerArn: *listener.LoadBalancerArn,
				Port:            *listener.Port,
				Protocol:        *listener.Protocol,
			}

			for _, a := range listener.DefaultActions {
				la := &AwsElbAction{
					TargetGroupArn: *a.TargetGroupArn,
					Type:           *a.Type,
				}

				if a.RedirectConfig != nil {
					la.RedirectConfig = &AwsElbRedirectActionConfig{
						Host:       *a.RedirectConfig.Host,
						Path:       *a.RedirectConfig.Path,
						Port:       *a.RedirectConfig.Port,
						Protocol:   *a.RedirectConfig.Protocol,
						Query:      *a.RedirectConfig.Query,
						StatusCode: *a.RedirectConfig.StatusCode,
					}
				}

				listenerResult.DefaultActions = append(listenerResult.DefaultActions, la)
			}

			for _, c := range listener.Certificates {
				var certIsDefault bool
				if c.IsDefault != nil {
					certIsDefault = *c.IsDefault
				}
				listenerResult.Certificates = append(listenerResult.Certificates, &AwsElbCertificate{
					CertificateArn: *c.CertificateArn,
					IsDefault:      certIsDefault,
				})
			}
		}

		result.Listeners = append(result.Listeners, listenerResult)
	}

	// TODO: Loop through the current listeners for any that have been renamed or removed and delete them.

	infra.AwsElbLoadBalancer[loadBalancerName] = result

	// If there are zones defined, then register the ELB.
	if zones != nil {

		log.Println("\t\tRegister DNS entry in Route 53")

		log.Printf("\t\t\tDNSName: '%s'\n", *elb.DNSName)

		svc := route53.New(infra.AwsSession())

		for _, zone := range zones {
			log.Printf("\t\t\tUpdate zone '%s'\n", zone.Name)
			
			input := &route53.ChangeResourceRecordSetsInput{
				ChangeBatch: &route53.ChangeBatch{
					Changes: []*route53.Change{},
				},
				HostedZoneId: aws.String(zone.ZoneId),
			}

			// Add all the A record names with the same set of public IPs.
			for _, aName := range zone.Entries {
				log.Printf("\t\t\t\tAdd A record for '%s'.\n", aName)

				rs := &route53.ResourceRecordSet{
					Name: aws.String(aName),
				}

				if infra.awsCredentials.IsGov() {
					rs.Type = aws.String("CNAME")
					rs.ResourceRecords = []*route53.ResourceRecord{
						&route53.ResourceRecord{
							Value:	elb.DNSName,
						},
					}
					rs.TTL = aws.Int64(120)
				} else {
					rs.Type = aws.String("A")
					rs.AliasTarget = &route53.AliasTarget{
						HostedZoneId:         elb.CanonicalHostedZoneId,
						DNSName:              elb.DNSName,
						EvaluateTargetHealth: aws.Bool(true),
					}
				}

				input.ChangeBatch.Changes = append(input.ChangeBatch.Changes, &route53.Change{
					Action: aws.String("UPSERT"),
					ResourceRecordSet: rs,
				})
			}

			_, err := svc.ChangeResourceRecordSets(input)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to update A records for zone '%s'", zone.ZoneId)
			}
		}
	}

	log.Printf("\t%s\tLoad Balancer available\n", Success)

	return result, nil
}

// GetAwsCloudwatchEventRule returns *AwsElbLoadBalancerResult by rule name.
func (infra *Infrastructure) GetAwsCloudwatchEventRule(ruleName string) (*AwsCloudwatchEventRuleResult, error) {
	var (
		result *AwsCloudwatchEventRuleResult
		ok     bool
	)
	if infra.AwsCloudwatchEventRule != nil {
		result, ok = infra.AwsCloudwatchEventRule[ruleName]
	}

	if !ok {
		return nil, errors.Errorf("No rule configured for '%s'", ruleName)
	}
	return result, nil
}

// setupAwsCloudwatchEventRule ensures the AWS Cloudwatch Event rule exists else creates it.
func (infra *Infrastructure) setupAwsCloudwatchEventRule(log *log.Logger, definedRule *AwsCloudwatchEventRule) (*AwsCloudwatchEventRuleResult, error) {

	ruleName := definedRule.Name

	log.Printf("\tCloudwatch Event - Get or create rule '%s'\n", ruleName)

	input, err := definedRule.Input(nil)
	if err != nil {
		return nil, err
	}

	var targets []*cloudwatchevents.Target
	for _, t := range definedRule.Targets {
		ti, err := t.Target(nil, nil)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ti)
	}

	inputHash := getInputHash(input, targets)

	if infra.AwsCloudwatchEventRule == nil {
		infra.AwsCloudwatchEventRule = make(map[string]*AwsCloudwatchEventRuleResult)
	}

	result, ok := infra.AwsCloudwatchEventRule[definedRule.Name]
	if ok && result != nil && result.InputHash == inputHash && !infra.skipCache {
		log.Printf("\t\tExists: %s", result.Name)
		return result, nil
	}

	svc := cloudwatchevents.New(infra.AwsSession())

	var rule *cloudwatchevents.Rule
	res, err := svc.ListRules(&cloudwatchevents.ListRulesInput{
		EventBusName: definedRule.EventBusName,
		NamePrefix:   aws.String(ruleName),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to list rules for '%s'", ruleName)
	} else if res != nil && len(res.Rules) > 0 {
		for _, r := range res.Rules {
			if *r.Name == ruleName {
				rule = r
			} else if result != nil && result.Arn == *r.Arn {
				rule = r
			}

			if rule != nil {
				log.Printf("\t\tFound rule %s", *rule.Arn)
				log.Printf("\t\t\tState: ", *rule.State)
				break
			}
		}
	}

	// If a role has been defined, then ensure its setup and set the roleARN for the rule.
	if definedRule.IamRole != nil {
		role, err := infra.GetAwsIamRole(definedRule.IamRole.RoleName)
		if err != nil || role == nil {
			curLogPrefix := log.Prefix()

			log.SetPrefix(curLogPrefix + "\t\t")

			role, err = infra.setupAwsIamRole(log, definedRule.IamRole)
			if err != nil {
				return nil, err
			}

			log.SetPrefix(curLogPrefix)
		}

		definedRule.RoleArn = aws.String(role.Arn)
	}

	// Get an updated input that applies any changes based on the existing rule.
	input, err = definedRule.Input(rule)
	if err != nil {
		return nil, err
	}

	// Creates or updates the specified rule. Rules are enabled by default or based on value of the state.
	// If you're updating an existing rule, the rule is replaced with what you specify in this PutRule command.
	// If you omit arguments in PutRule, the old values for those arguments aren't kept. Instead, they're replaced with null values.
	putRes, err := svc.PutRule(input)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to put rule '%s'", ruleName)
	}
	if rule != nil {
		log.Printf("\t\tUpdated rule %s", *rule.Arn)
	} else {
		log.Printf("\t\tCreated rule %s", *putRes.RuleArn)
	}

	// Update the result keeping any existing targets already defined.
	{
		var curRuleTargets map[string]*AwsCloudwatchEventTargetResult
		if result != nil {
			curRuleTargets = result.Targets
		}

		result = &AwsCloudwatchEventRuleResult{
			Name:         ruleName,
			EventBusName: definedRule.EventBusName,
			Arn:          *putRes.RuleArn,
			InputHash:    inputHash,
			Targets:      curRuleTargets,
		}
	}

	log.Printf("\t\tConfigure %d targets", len(definedRule.Targets))

	targetRes, err := svc.ListTargetsByRule(&cloudwatchevents.ListTargetsByRuleInput{
		Rule:         aws.String(ruleName),
		EventBusName: definedRule.EventBusName,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to list targets for '%s'", ruleName)
	}

	curTargets := make(map[string]*cloudwatchevents.Target)
	for _, t := range targetRes.Targets {
		curTargets[*t.Id] = t
	}

	targetsInput := &cloudwatchevents.PutTargetsInput{
		EventBusName: definedRule.EventBusName,
		Rule:         aws.String(ruleName),
	}

	for _, rt := range definedRule.Targets {

		// If a role has been defined, then ensure its setup and set the roleARN for the target.
		if rt.IamRole != nil {
			role, err := infra.GetAwsIamRole(rt.IamRole.RoleName)
			if err != nil || role == nil {
				curLogPrefix := log.Prefix()

				log.SetPrefix(curLogPrefix + "\t\t\t")

				role, err = infra.setupAwsIamRole(log, rt.IamRole)
				if err != nil {
					return nil, err
				}

				log.SetPrefix(curLogPrefix)
			}

			rt.RoleArn = aws.String(role.Arn)
		}

		target, err := rt.Target(nil, nil)
		if err != nil {
			return nil, err
		}
		inputHash := getInputHash(target)

		crt, err := result.GetTarget(rt.Id)
		if err == nil && crt != nil && crt.InputHash == inputHash && !infra.skipCache {
			log.Printf("\t\t\tExists: %s", target.Id)
		} else {
			ct, ok := curTargets[rt.Id]
			if ok {
				log.Printf("\t\t\tUpdate: %s", target.Id)
			} else {
				log.Printf("\t\t\tAdd: %s", target.Id)
			}

			// Get an updated target that applies any changes based on the existing target.
			target, err = rt.Target(result, ct)
			if err != nil {
				return nil, err
			}

			crt = &AwsCloudwatchEventTargetResult{
				Arn:       rt.Arn,
				Id:        rt.Id,
				InputHash: inputHash,
			}

			targetsInput.Targets = append(targetsInput.Targets, target)
		}

		result.Targets[rt.Id] = crt
	}

	infra.AwsCloudwatchEventRule[ruleName] = result

	log.Printf("\t%s\tCertificate available\n", Success)

	return result, nil
}

// GetAwsAppAutoscalingPolicy returns *AwsAppAutoscalingPolicyResult by policy name.
func (infra *Infrastructure) GetAwsAppAutoscalingPolicy(policyName string) (*AwsAppAutoscalingPolicyResult, error) {
	var (
		result *AwsAppAutoscalingPolicyResult
		ok     bool
	)
	if infra.AwsAppAutoscalingPolicy != nil {
		result, ok = infra.AwsAppAutoscalingPolicy[policyName]
	}

	if !ok {
		return nil, errors.Errorf("No policy configured for '%s'", policyName)
	}
	return result, nil
}

// getInputHash computes an MD5 for an input struct.
func getInputHash(input interface{}, vals ...interface{}) string {
	if input == nil {
		return ""
	}
	vals = append(vals, input)

	var hashes []string
	for _, v := range vals {
		dat, _ := json.Marshal(v)
		hashes = append(hashes, fmt.Sprintf("%x", md5.Sum(dat)))
	}

	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(hashes, "|"))))
}

/*


ctx.AwsElbLoadBalancer.AutoScalingGroup = &devdeploy.AwsAutoScalingGroup {
				// The name of the scaling policy.
				PolicyName: ctx.AwsEcsService.ServiceName,

				// The maximum size of the group.
				MaxSize: desiredCount * 2,

				// The minimum size of the group.
				MinSize: 1,

				// The number of Amazon EC2 instances that the Auto Scaling group attempts to
				// maintain. This number must be greater than or equal to the minimum size of
				// the group and less than or equal to the maximum size of the group. If you
				// do not specify a desired capacity, the default is the minimum size of the
				// group.
				DesiredCapacity: aws.Int64(desiredCount),

				// The amount of time, in seconds, that Amazon EC2 Auto Scaling waits before
				// checking the health status of an EC2 instance that has come into service.
				// During this time, any health check failures for the instance are ignored.
				// The default value is 0.
				HealthCheckGracePeriod: aws.Int64(300),

				// The key-value pairs to use for the tags.
				Tags: []devdeploy.Tag{
					{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
					{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
				},

				Policies: []*devdeploy.AwsAutoScalingPolicy{
					&devdeploy.AwsAutoScalingPolicy{
						PutScalingPolicyInput: &autoscaling.PutScalingPolicyInput{
							// The name of the policy.
							PolicyName: aws.String(fmt.Sprintf("%s-cpu", ctx.AwsElbLoadBalancer.Name)),

							// The policy type. The valid values are SimpleScaling, StepScaling, and TargetTrackingScaling.
							// If the policy type is null, the value is treated as SimpleScaling.
							PolicyType: aws.String("TargetTrackingScaling"),

							// Specifies whether the ScalingAdjustment parameter is an absolute number or
							// a percentage of the current capacity. The valid values are ChangeInCapacity,
							// ExactCapacity, and PercentChangeInCapacity.
							//
							// Valid only if the policy type is StepScaling or SimpleScaling. For more information,
							// see Scaling Adjustment Types (https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment)
							// in the Amazon EC2 Auto Scaling User Guide.
							AdjustmentType: aws.String("ChangeInCapacity"),

							// The amount of time, in seconds, after a scaling activity completes before
							// any further dynamic scaling activities can start. If this parameter is not
							// specified, the default cooldown period for the group applies.
							//
							// Valid only if the policy type is SimpleScaling. For more information, see
							// Scaling Cooldowns (https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html)
							// in the Amazon EC2 Auto Scaling User Guide.
							Cooldown: aws.Int64(300),

							// The estimated time, in seconds, until a newly launched instance can contribute
							// to the CloudWatch metrics. The default is to use the value specified for
							// the default cooldown period for the group.
							//
							// Valid only if the policy type is StepScaling or TargetTrackingScaling.
							EstimatedInstanceWarmup: aws.Int64(60),

							// The amount by which a simple scaling policy scales the Auto Scaling group
							// in response to an alarm breach. The adjustment is based on the value that
							// you specified in the AdjustmentType parameter (either an absolute number
							// or a percentage). A positive value adds to the current capacity and a negative
							// value subtracts from the current capacity. For exact capacity, you must specify
							// a positive value.
							//
							// Conditional: If you specify SimpleScaling for the policy type, you must specify
							// this parameter. (Not used with any other policy type.)
							ScalingAdjustment: aws.Int64(1),


							// A target tracking scaling policy. Includes support for predefined or customized
							// metrics.
							//
							// For more information, see TargetTrackingConfiguration (https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_TargetTrackingConfiguration.html)
							// in the Amazon EC2 Auto Scaling API Reference.
							//
							// Conditional: If you specify TargetTrackingScaling for the policy type, you
							// must specify this parameter. (Not used with any other policy type.)
							TargetTrackingConfiguration: &autoscaling.TargetTrackingConfiguration{
								// A predefined metric. You must specify either a predefined metric or a customized
								// metric.
								PredefinedMetricSpecification: &autoscaling.PredefinedMetricSpecification{
									// The metric type. The following predefined metrics are available:
									//
									//    * ASGAverageCPUUtilization - Average CPU utilization of the Auto Scaling
									//    group.
									//
									//    * ASGAverageNetworkIn - Average number of bytes received on all network
									//    interfaces by the Auto Scaling group.
									//
									//    * ASGAverageNetworkOut - Average number of bytes sent out on all network
									//    interfaces by the Auto Scaling group.
									//
									//    * ALBRequestCountPerTarget - Number of requests completed per target in
									//    an Application Load Balancer target group.
									//
									PredefinedMetricType: aws.String("ASGAverageCPUUtilization"),

									// Identifies the resource associated with the metric type.
									//
									// For predefined metric types ASGAverageCPUUtilization, ASGAverageNetworkIn, and
									// ASGAverageNetworkOut, the parameter must not be specified as the resource
									// associated with the metric type is the Auto Scaling group.
									//
									// For predefined metric type ALBRequestCountPerTarget, the parameter must be
									// specified in format:
									// 		app/load-balancer-name/load-balancer-id/targetgroup/target-group-name/target-group-id
									// where app/load-balancer-name/load-balancer-id is the final portion of the
									// load balancer ARN, and targetgroup/target-group-name/target-group-id is the
									// final portion of the target group ARN. The target group must be attached
									// to the Auto Scaling group.
									ResourceLabel: nil,
								},

								// The target value for the metric.
								//
								// TargetValue is a required field
								TargetValue: aws.Float64(60),

								// Indicates whether scaling in by the target tracking scaling policy is disabled.
								// If scaling in is disabled, the target tracking scaling policy doesn't remove
								// instances from the Auto Scaling group. Otherwise, the target tracking scaling
								// policy can remove instances from the Auto Scaling group. The default is false.
								DisableScaleIn: aws.Bool(false),
							},
						},
					},
				},
			}

// AwsEc2AutoscalingGroup defines the details needed to create an autoscaling group.
type AwsEc2AutoscalingGroup struct {
	// The name of the Auto Scaling group. This name must be unique per Region per account.
	GroupName string

	// The name of the launch configuration.
	LaunchConfigurationName string

	// The maximum size of the group.
	MaxSize int64

	// The minimum size of the group.
	MinSize int64

	// The number of Amazon EC2 instances that the Auto Scaling group attempts to
	// maintain. This number must be greater than or equal to the minimum size of
	// the group and less than or equal to the maximum size of the group. If you
	// do not specify a desired capacity, the default is the minimum size of the
	// group.
	DesiredCapacity *int64

	// The amount of time, in seconds, that Amazon EC2 Auto Scaling waits before
	// checking the health status of an EC2 instance that has come into service.
	// During this time, any health check failures for the instance are ignored.
	// The default value is 0.
	//
	// For more information, see Health Check Grace Period (https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html#health-check-grace-period)
	// in the Amazon EC2 Auto Scaling User Guide.
	//
	// Conditional: This parameter is required if you are adding an ELB health check.
	HealthCheckGracePeriod *int64

	// The key-value pairs to use for the tags.
	Tags []Tag

	// Optional list of polices to be associated with the group.
	Policies []*AwsEc2AutoscalingPolicy

	// Optional to provide additional details to the create input.
	PreCreate func(input *autoscaling.CreateAutoScalingGroupInput) error `json:"-"`
}

// AwsEc2AutoscalingGroupResult defines information about an autoscaling group.
type AwsEc2AutoscalingGroupResult struct {
	// The name of the Auto Scaling group. This name must be unique per Region per account.
	GroupName string

	// The name of the launch configuration.
	LaunchConfigurationName string

	// The maximum size of the group.
	MaxSize int64

	// The minimum size of the group.
	MinSize int64

	// The number of Amazon EC2 instances that the Auto Scaling group attempts to
	// maintain. This number must be greater than or equal to the minimum size of
	// the group and less than or equal to the maximum size of the group. If you
	// do not specify a desired capacity, the default is the minimum size of the
	// group.
	DesiredCapacity *int64

	// The Amazon Resource Name (ARN) of the group.
	GroupARN string

	// Optional list of polices that are associated with the group.
	Policies map[string]*AwsEc2AutoscalingPolicyResult

	// The md5 hash of the input used to create the Group.
	InputHash string
}

// Input returns the AWS input for autoscaling.CreateAutoScalingGroup.
func (m *AwsEc2AutoscalingGroup) Input(elb *AwsElbLoadBalancerResult, vpc *AwsEc2VpcResult) (*autoscaling.CreateAutoScalingGroupInput, error) {

	input := &autoscaling.CreateAutoScalingGroupInput{
		AutoScalingGroupName:          aws.String(m.GroupName),
		LaunchConfigurationName: aws.String(m.LaunchConfigurationName),
		MaxSize: aws.Int64(m.MaxSize),
		MinSize:        aws.Int64(m.MinSize),
		DesiredCapacity:          m.DesiredCapacity,
		HealthCheckGracePeriod:          m.HealthCheckGracePeriod,
		HealthCheckType:          aws.String("ELB"),
	}

	if vpc != nil {
		input.VPCZoneIdentifier = aws.String(strings.Join(vpc.SubnetIds, ", "))
	}

	if elb != nil {
		for _, tg := range elb.TargetGroups {
			input.TargetGroupARNs = append(input.TargetGroupARNs, aws.String(tg.TargetGroupArn))
		}
	}

	for _, t := range m.Tags {
		input.Tags = append(input.Tags, &autoscaling.Tag{
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

// GetPolicy returns *AwsCloudwatchEventTargetResult by id.
func (res *AwsEc2AutoscalingGroupResult) GetPolicy(policyName string) (*AwsEc2AutoscalingPolicyResult, error) {
	var (
		result *AwsEc2AutoscalingPolicyResult
		ok bool
	)
	if res.Policies != nil {
		result, ok = res.Policies[policyName]
	}
	if !ok {
		return nil, errors.Errorf("No policy configured for '%s'", policyName)
	}
	return result, nil
}

// AwsEc2AutoscalingPolicy defines the details needed to create an autoscaling policy.
type AwsEc2AutoscalingPolicy struct {
	*autoscaling.PutScalingPolicyInput

	// Optional to provide additional details to the create input.
	PreCreate func(group *AwsEc2AutoscalingGroupResult, input *autoscaling.PutScalingPolicyInput) error `json:"-"`
}

// AwsEc2AutoscalingPolicyResult defines information about an autoscaling policy.
type AwsEc2AutoscalingPolicyResult struct {
	// The name of the policy.
	PolicyName string

	// The policy type.
	PolicyType string

	// The Amazon Resource Name (ARN) of the policy.
	PolicyARN string

	// The md5 hash of the input used to create the Group.
	InputHash string
}

// Input returns the AWS input for autoscaling.PutScalingPolicy.
func (m *AwsEc2AutoscalingPolicy) Input(group *AwsEc2AutoscalingGroupResult) (*autoscaling.PutScalingPolicyInput, error) {

	input := m.PutScalingPolicyInput
	if input == nil {
		input = &autoscaling.PutScalingPolicyInput{}
	}

	input.AutoScalingGroupName =aws.String(group.GroupName)

	if m.PreCreate != nil {
		if group == nil {
			group = &AwsEc2AutoscalingGroupResult{}
		}
		if err := m.PreCreate(group, input); err != nil {
			return input, err
		}
	}

	return input, nil
}



if definedElb.AutoScalingGroup != nil {
		groupInput, err := definedElb.AutoScalingGroup.Input(result)
		if err != nil {
			return nil, err
		}
		inputHash := getInputHash(groupInput)

		groupName := definedElb.AutoScalingGroup.GroupName

		as := autoscaling.New(infra.AwsSession())

		if curAutoscalingGroup != nil  && curAutoscalingGroup.InputHash == inputHash && !infra.skipCache {
			log.Printf("\t\t\tAutoscaling group %s exists: %s", curAutoscalingGroup.GroupName, curAutoscalingGroup.GroupARN)
		} else {

			groupRes, err := as.DescribeAutoScalingGroups(&autoscaling.DescribeAutoScalingGroupsInput{
				AutoScalingGroupNames: aws.StringSlice([]string{groupName}),
			})
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to describe group '%s'", groupName)
			}

			var scalingGroup *autoscaling.Group
			for _, g := range groupRes.AutoScalingGroups {
				if *g.AutoScalingGroupName == groupName || (curAutoscalingGroup != nil && curAutoscalingGroup.GroupARN == *g.AutoScalingGroupARN) {
					scalingGroup = g
					break
				}
			}

			var groupArn string
			if scalingGroup == nil {
				// If no target group was found, create one.
				createRes, err := as.CreateAutoScalingGroup(groupInput)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to create group '%s'", groupName)
				}
				groupArn = createRes.String()

				log.Printf("\t\t\tAutoscaling Group %s created: %s", groupName, groupArn)
			} else {
				groupArn = *scalingGroup.AutoScalingGroupARN

				log.Printf("\t\t\tAutoscaling Group %s found: %s", groupName, groupArn)
			}

			var curPolicies map[string]*AwsEc2AutoscalingPolicyResult
			if curAutoscalingGroup != nil && curAutoscalingGroup.Policies != nil  {
				curPolicies = curAutoscalingGroup.Policies
			} else {
				curPolicies = make(map[string]*AwsEc2AutoscalingPolicyResult)
			}

			curAutoscalingGroup = &AwsEc2AutoscalingGroupResult{
				GroupName : groupName,
				MaxSize : definedElb.AutoScalingGroup.MaxSize,
				MinSize: definedElb.AutoScalingGroup.MinSize,
				DesiredCapacity: definedElb.AutoScalingGroup.DesiredCapacity,
				GroupARN: groupArn,
				InputHash: inputHash,
				Policies: curPolicies,
			}
		}

		for _, definedPolicy := range definedElb.AutoScalingGroup.Policies {
			policyInput, err := definedPolicy.Input(curAutoscalingGroup)
			if err != nil {
				return nil, err
			}
			inputHash := getInputHash(policyInput)

			var policyName string
			if definedPolicy.PolicyName != nil {
				policyName = *definedPolicy.PolicyName
			}

			curPolicy, err := curAutoscalingGroup.GetPolicy(policyName)
			if err == nil && curPolicy != nil  && curPolicy.InputHash == inputHash && !infra.skipCache {
				log.Printf("\t\t\t\tPolicy %s exists: %s", policyName, curPolicy.PolicyARN)
			} else {
				policyRes, err := as.DescribePolicies(&autoscaling.DescribePoliciesInput{
					AutoScalingGroupName: aws.String(groupName),
					PolicyNames: aws.StringSlice([]string{policyName}),
				})
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to describe policy '%s'", policyName)
				}

				var scalingPolicy *autoscaling.ScalingPolicy
				for _, p := range policyRes.ScalingPolicies {
					if *p.PolicyName	 == policyName || (curPolicy != nil && curPolicy.PolicyARN == *p.PolicyARN) {
						scalingPolicy =p
						break
					}
				}

				var policyArn string
				var policyType string
				if scalingPolicy == nil {
					// If no target group was found, create one.
					createRes, err := as.PutScalingPolicy(policyInput)
					if err != nil {
						return nil, errors.Wrapf(err, "Failed to create policy '%s'", policyName)
					}
					policyArn = createRes.String()

					if definedPolicy.PolicyType != nil {
						policyType = *definedPolicy.PolicyType
					}

					// If the policy type is null, the value is treated as SimpleScaling.
					if policyType == "" {
						policyType = "SimpleScaling"
					}

					log.Printf("\t\t\t\tAutoscaling policy %s created: %s", policyName, policyArn)
				} else {
					policyArn = *scalingPolicy.PolicyARN
					policyType = *scalingPolicy.PolicyType

					log.Printf("\t\t\t\tAutoscaling policy %s found: %s", policyName, policyArn)
				}

				curPolicy = &AwsEc2AutoscalingPolicyResult{
					PolicyName : policyName,
					PolicyType : policyType,
					PolicyARN: policyArn,
					InputHash: inputHash,
				}
			}

			curAutoscalingGroup.Policies[curPolicy.PolicyName] = curPolicy
		}

		result.Ec2AutoScalingGroup = curAutoscalingGroup
	}
*/
