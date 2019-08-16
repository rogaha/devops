package devdeploy

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"strconv"
	"strings"
	"gopkg.in/go-playground/validator.v9"
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

	return session.New(
		&aws.Config{
			Region:      aws.String(creds.Region),
			Credentials: credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey, ""),
		})
}



// GetAwsCredentials loads the AWS Access Keys from env variables unless a role is used.
func GetAwsCredentialsFromEnv(targetEnv string) (AwsCredentials, error) {
	var creds AwsCredentials

	creds.Region = strings.TrimSpace(getTargetEnv(targetEnv, "AWS_REGION"))

	if v := getTargetEnv(targetEnv, "AWS_USE_ROLE"); v != "" {
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

	creds.AccessKeyID = strings.TrimSpace(getTargetEnv(targetEnv, "AWS_ACCESS_KEY_ID"))
	creds.SecretAccessKey = strings.TrimSpace(getTargetEnv(targetEnv, "AWS_SECRET_ACCESS_KEY"))

	errs := validator.New().Struct(creds)
	if errs != nil {
		return creds, errs
	}

	//os.Setenv("AWS_DEFAULT_REGION", creds.Region)

	return creds, nil
}

