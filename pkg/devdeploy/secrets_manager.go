package devdeploy

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
)

var ErrSecreteNotFound = errors.New("secret not found")

// SecretManagerGetString loads a key from AWS Secrets Manager.
// when UnrecognizedClientException its likely the AWS IAM permissions are not correct.
func SecretManagerGetString(awsSession *session.Session, secretID string) (string, error) {

	svc := secretsmanager.New(awsSession)

	// Load the secret by ID from Secrets Manager.
	res, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && (aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException || aerr.Code() == secretsmanager.ErrCodeInvalidRequestException) {
			return "", errors.Wrapf(ErrSecreteNotFound, "Failed to get value for secret id %s", secretID)
		}
		return "", errors.Wrapf(err, "Failed to get value for secret id %s", secretID)
	}

	return *res.SecretString, nil
}

// SecretManagerGetString loads a key from AWS Secrets Manager.
// when UnrecognizedClientException its likely the AWS IAM permissions are not correct.
func SecretManagerGetBinary(awsSession *session.Session, secretID string) ([]byte, error) {

	svc := secretsmanager.New(awsSession)

	// Load the secret by ID from Secrets Manager.
	res, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && (aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException || aerr.Code() == secretsmanager.ErrCodeInvalidRequestException) {
			return nil, errors.Wrapf(ErrSecreteNotFound, "Failed to get value for secret id %s", secretID)
		}
		return nil, errors.Wrapf(err, "Failed to get value for secret id %s", secretID)
	}

	return res.SecretBinary, nil
}

// SecretManagerPutBinary saves binary a value to AWS Secrets Manager.
func SecretManagerPutBinary(awsSession *session.Session, secretID string, value []byte) error {
	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretID),
		SecretBinary: value,
	}
	return secretManagerPutValue(awsSession, input)
}

// SecretManagerPutString saves a string value to AWS Secrets Manager.
func SecretManagerPutString(awsSession *session.Session, secretID, value string) error {
	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretID),
		SecretString: aws.String(value),
	}
	return secretManagerPutValue(awsSession, input)
}

// If the secret ID does not exist, it will create it.
// If the secret ID was deleted, it will restore it and then update the value.
func secretManagerPutValue(awsSession *session.Session, input *secretsmanager.CreateSecretInput) error {

	svc := secretsmanager.New(awsSession)

	// Create the new entry in AWS Secret Manager for the file.
	_, err := svc.CreateSecret(input)
	if err != nil {
		aerr, ok := err.(awserr.Error)

		if ok && aerr.Code() == secretsmanager.ErrCodeInvalidRequestException {
			// InvalidRequestException: You can't create this secret because a secret with this
			// 							 name is already scheduled for deletion.

			// Restore secret after it was already previously deleted.
			_, err = svc.RestoreSecret(&secretsmanager.RestoreSecretInput{
				SecretId: input.Name,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to restore secret %s", *input.Name)
			}

		} else if !ok || aerr.Code() != secretsmanager.ErrCodeResourceExistsException {
			return errors.Wrapf(err, "failed to create secret %s", *input.Name)
		}

		// If where was a resource exists error for create, then need to update the secret instead.
		_, err = svc.UpdateSecret(&secretsmanager.UpdateSecretInput{
			SecretId:     input.Name,
			SecretString: input.SecretString,
			SecretBinary: input.SecretBinary,
		})
		if err != nil {
			return errors.Wrapf(err, "failed to update secret %s", *input.Name)
		}
	}

	return nil
}
