package devdeploy

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
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