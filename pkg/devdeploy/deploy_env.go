package devdeploy

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"gopkg.in/go-playground/validator.v9"
)


// ProjectNameCamel takes a project name and returns the camel cased version.
func (devEnv *DeploymentEnv) ProjectNameCamel() string {
	s := strings.Replace(devEnv.ProjectName, "_", " ", -1)
	s = strings.Replace(s, "-", " ", -1)
	s = strcase.ToCamel(s)
	return s
}



// SetupDeploymentEnv ensures all the resources for the project are setup before deploying a single ECS service or
// Lambda function.
func SetupDeploymentEnv(devEnv *DeploymentEnv) error {

	errs := validator.New().Struct(devEnv)
	if errs != nil {
		return  errs
	}



	for _, s3Bucket := range devEnv.AwsS3Buckets {

		if s3Bucket.CloudFront != nil {
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

			s3Bucket.CloudFront.DistributionConfig.DefaultCacheBehavior.TargetOriginId =  aws.String(domainId)
			s3Bucket.CloudFront.DistributionConfig.DefaultCacheBehavior.AllowedMethods = allowedMethods
			s3Bucket.CloudFront.DistributionConfig.Origins = origins
		}

	}

}



func LoadModuleDetails(workDir string) (ModuleDetails, error) {
	var (
		resp ModuleDetails
		err error
	)

	resp.GoModFile, err = findProjectGoModFile()
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
		return "", errors.WithMessagef(err, "failed to load go.mod for project using project root %s")
	} else if !ok {
		return "", errors.Errorf("failed to locate project go.mod in project root %s", projectRoot)
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
func getTargetEnv(targetEnv, envName string) string {
	k := fmt.Sprintf("%s_%s", strings.ToUpper(targetEnv), envName)

	if v := os.Getenv(k); v != "" {
		// Set the non prefixed env var with the prefixed value.
		os.Setenv(envName, v)
		return v
	}

	return os.Getenv(envName)
}
