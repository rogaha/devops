package devdeploy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
)

const (
	AwsRegistryMaximumImages = 900 // Max is actually 1000 but make sure there is always room.
	AwsTagNameProject        = "Project"
	AwsTagNameEnv            = "env"
	AwsTagNameName           = "Name"
)

// Session returns a new AWS Session used to access AWS services.
func (creds AwsCredentials) Session() *session.Session {

	if creds.UseRole {
		// Get an AWS session from an implicit source if no explicit
		// configuration is provided. This is useful for taking advantage of
		// EC2/ECS instance roles.
		sess := session.Must(session.NewSession())
		if creds.Region != "" {
			sess.Config.WithRegion(creds.Region)
		}

		return sess
	}

	return session.Must(session.NewSession(
		&aws.Config{
			Region:      aws.String(creds.Region),
			Credentials: credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey, ""),
		}))
}

// IsGov returns whether the region is a part of the govcloud.
func (creds AwsCredentials) IsGov() bool {
	return strings.Contains(creds.Region, "-gov-")
}

// GetAwsCredentials loads the AWS Access Keys from env variables unless a role is used.
func GetAwsCredentialsFromEnv(targetEnv string) (AwsCredentials, error) {
	var creds AwsCredentials

	creds.Region = strings.TrimSpace(GetTargetEnv(targetEnv, "AWS_DEFAULT_REGION"))

	if v := GetTargetEnv(targetEnv, "AWS_USE_ROLE"); v != "" {
		creds.UseRole, _ = strconv.ParseBool(v)

		sess, err := session.NewSession()
		if err != nil {
			return creds, errors.Wrap(err, "Failed to load AWS credentials from instance")
		}

		if sess.Config != nil && sess.Config.Region != nil && *sess.Config.Region != "" {
			creds.Region = *sess.Config.Region
		} else {
			sm := ec2metadata.New(sess)
			creds.Region, err = sm.Region()
			if err != nil {
				return creds, errors.Wrap(err, "Failed to get region from AWS session")
			}
		}

		return creds, nil
	}

	creds.AccessKeyID = strings.TrimSpace(GetTargetEnv(targetEnv, "AWS_ACCESS_KEY_ID"))
	creds.SecretAccessKey = strings.TrimSpace(GetTargetEnv(targetEnv, "AWS_SECRET_ACCESS_KEY"))

	errs := validator.New().Struct(creds)
	if errs != nil {
		return creds, errs
	}

	//os.Setenv("AWS_DEFAULT_REGION", creds.Region)

	return creds, nil
}

// SyncPublicS3Files copies the local files from the static directory to s3 with public-read enabled.
func SyncPublicS3Files(awsSession *session.Session, staticS3Bucket, staticS3Prefix, staticDir string, metadatas ...Metadata) error {
	uploader := s3manager.NewUploader(awsSession)

	// Set the default cache-control, users can override this value with a Metadata arg.
	metadata := map[string]*string{
		"Cache-Control": aws.String("max-age=604800"),
	}
	for _, kv := range metadatas {
		metadata[kv.Key] = aws.String(kv.Value)
	}

	di, err := NewDirectoryIterator(staticS3Bucket, staticS3Prefix, staticDir, "public-read", metadata)
	if err != nil {
		return err
	}

	err = uploader.UploadWithIterator(aws.BackgroundContext(), di)
	if err != nil {
		return err
	}

	return nil
}

// EcrPurgeImages ensures pipeline does not generate images for max of 10000 and prevent manual deletion of images.
func EcrPurgeImages(awsCredentials AwsCredentials, ecrRepositoryName string, maxImages int) ([]*ecr.ImageIdentifier, error) {
	if maxImages == 0 || maxImages > AwsRegistryMaximumImages {
		maxImages = AwsRegistryMaximumImages
	}

	svc := ecr.New(awsCredentials.Session())

	// Describe all the image IDs to determine oldest.
	var (
		ts       []int
		tsImgIds = map[int][]*ecr.ImageIdentifier{}
	)
	err := svc.DescribeImagesPages(&ecr.DescribeImagesInput{
		RepositoryName: aws.String(ecrRepositoryName),
	}, func(res *ecr.DescribeImagesOutput, lastPage bool) bool {
		for _, img := range res.ImageDetails {

			imgTs := int(img.ImagePushedAt.Unix())

			if _, ok := tsImgIds[imgTs]; !ok {
				tsImgIds[imgTs] = []*ecr.ImageIdentifier{}
				ts = append(ts, imgTs)
			}

			if img.ImageTags != nil {
				tsImgIds[imgTs] = append(tsImgIds[imgTs], &ecr.ImageIdentifier{
					ImageTag: img.ImageTags[0],
				})
			} else if img.ImageDigest != nil {
				tsImgIds[imgTs] = append(tsImgIds[imgTs], &ecr.ImageIdentifier{
					ImageDigest: img.ImageDigest,
				})
			}
		}

		return !lastPage
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to describe images for repository '%s'", ecrRepositoryName)
	}

	// Sort the image timestamps in reverse order.
	sort.Sort(sort.Reverse(sort.IntSlice(ts)))

	// Loop over all the timestamps, skip the newest images until count exceeds limit.
	var imgCnt int
	var delIds []*ecr.ImageIdentifier
	for _, imgTs := range ts {
		for _, imgId := range tsImgIds[imgTs] {
			imgCnt = imgCnt + 1

			if imgCnt <= maxImages {
				continue
			}
			delIds = append(delIds, imgId)
		}
	}

	// If there are image IDs to delete, delete them.
	if len(delIds) > 0 {
		//log.Printf("\t\tECR has %d images for repository '%s' which exceeds limit of %d", imgCnt, creds.EcrRepositoryName, creds.EcrRepositoryMaxImages)
		//for _, imgId := range delIds {
		//	log.Printf("\t\t\tDelete %s", *imgId.ImageTag)
		//}

		_, err = svc.BatchDeleteImage(&ecr.BatchDeleteImageInput{
			ImageIds:       delIds,
			RepositoryName: aws.String(ecrRepositoryName),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to delete %d images for repository '%s'", len(delIds), ecrRepositoryName)
		}
	}

	return delIds, nil
}

// EcsReadTaskDefinition reads a task definition file and json decodes it.
func EcsReadTaskDefinition(serviceDir, targetEnv string) ([]byte, error) {
	checkPaths := []string{
		filepath.Join(serviceDir, fmt.Sprintf("ecs-task-definition-%s.json", targetEnv)),
		filepath.Join(serviceDir, "ecs-task-definition.json"),
	}

	var defFile string
	for _, tf := range checkPaths {
		ok, _ := exists(tf)
		if ok {
			defFile = tf
			break
		}
	}

	if defFile == "" {
		return nil, errors.Errorf("failed to locate task definition - checked %s", strings.Join(checkPaths, ", "))
	}

	dat, err := ioutil.ReadFile(defFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file %s", defFile)
	}

	return dat, nil
}

// LambdaReadFuncDefinition reads a task definition file and json decodes it.
func LambdaReadFuncDefinition(serviceDir, targetEnv string) ([]byte, error) {
	checkPaths := []string{
		filepath.Join(serviceDir, fmt.Sprintf("lambda-func-definition-%s.json", targetEnv)),
		filepath.Join(serviceDir, "lambda-func-definition.json"),
	}

	var defFile string
	for _, tf := range checkPaths {
		ok, _ := exists(tf)
		if ok {
			defFile = tf
			break
		}
	}

	if defFile == "" {
		return nil, errors.Errorf("failed to locate task definition - checked %s", strings.Join(checkPaths, ", "))
	}

	dat, err := ioutil.ReadFile(defFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file %s", defFile)
	}

	return dat, nil
}

// LambdaS3KeyFromReleaseImage generates an S3 key from a release image.
func LambdaS3KeyFromReleaseImage(releaseImage string) string {
	it := filepath.Base(releaseImage)
	it = strings.Replace(it, ":", "/", -1)
	return filepath.Join("src/aws/lambda/", it+".zip")
}

// ParseTaskDefinitionInput json decodes an ecs task definition.
func ParseTaskDefinitionInput(dat []byte) (*ecs.RegisterTaskDefinitionInput, error) {
	dat = convertKeys(dat)

	var taskDef *ecs.RegisterTaskDefinitionInput
	if err := json.Unmarshal(dat, &taskDef); err != nil {
		return nil, errors.Wrapf(err, "failed to json decode task definition - %s", string(dat))
	}

	return taskDef, nil
}

// convertKeys fixes json keys to they can be unmarshaled into aws types. No AWS structs have json tags.
func convertKeys(j json.RawMessage) json.RawMessage {
	m := make(map[string]json.RawMessage)
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		// Not a JSON object
		return j
	}

	for k, v := range m {
		fixed := fixKey(k)
		delete(m, k)
		m[fixed] = convertKeys(v)
	}

	b, err := json.Marshal(m)
	if err != nil {
		return j
	}

	return json.RawMessage(b)
}

func fixKey(key string) string {
	return strings.ToTitle(key)
}
