package devdeploy

import (
	"bytes"
	"context"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"
)

// S3AutocertCache implements the autocert.Cache interface for AWS S3 that is used by Manager
// to store and retrieve previously obtained certificates and other account data as opaque blobs.
type S3AutocertCache struct {
	awsSession     *session.Session
	log            *log.Logger
	s3Bucket       string
	s3Prefix       string
	cache          autocert.Cache
	migrationCache autocert.Cache
}

// NewS3AutocertCache provides the functionality to keep config files sync'd between running tasks and across deployments.
func NewS3AutocertCache(log *log.Logger, awsSession *session.Session, s3Bucket, s3Prefix string, cache autocert.Cache) (*S3AutocertCache, error) {
	return &S3AutocertCache{
		awsSession: awsSession,
		log:        log,
		s3Bucket:   s3Bucket,
		s3Prefix:   s3Prefix,
		cache:      cache,
	}, nil
}

// EnableMigrationCache allows for entries to be migrated over from an existing cache option.
func (c *S3AutocertCache) EnableMigrationCache(cache autocert.Cache) {
	c.migrationCache = cache
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (c *S3AutocertCache) Get(ctx context.Context, key string) ([]byte, error) {

	// Check short term cache.
	if c.cache != nil {
		v, err := c.cache.Get(ctx, key)
		if err != nil && err != autocert.ErrCacheMiss {
			return nil, errors.WithStack(err)
		} else if len(v) > 0 {
			return v, nil
		}
	}

	// If a migration cache has been set, check to see if it exists there first.
	if c.migrationCache != nil {
		v, err := c.migrationCache.Get(ctx, key)
		if err != nil && err != autocert.ErrCacheMiss {
			return nil, errors.WithStack(err)
		} else if len(v) > 0 {
			// When a value exist, persist it to the current s3 cache.
			err = c.Put(ctx, key, v)
			if err != nil {
				return nil, err
			}

			return v, nil
		}
	}

	s3Key := filepath.Join(c.s3Prefix, key)

	res, err := s3.New(c.awsSession).GetObject(&s3.GetObjectInput{
		Bucket: aws.String(c.s3Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == s3.ErrCodeNoSuchKey {
			return nil, autocert.ErrCacheMiss
		}
		return nil, errors.Wrapf(err, "autocert failed to get key s3://%s/%s", c.s3Bucket, s3Key)
	}
	defer res.Body.Close()

	dat, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return dat, nil
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (c *S3AutocertCache) Put(ctx context.Context, key string, data []byte) error {
	s3Key := filepath.Join(c.s3Prefix, key)

	_, err := s3.New(c.awsSession).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(c.s3Bucket),
		Key:                  aws.String(s3Key),
		Body:                 bytes.NewReader(data),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return errors.Wrapf(err, "autocert failed to update key s3://%s/%s", c.s3Bucket, s3Key)
	}

	log.Printf("Autocert : AWS S3 : Key s3://%s/%s updated.", c.s3Bucket, s3Key)

	if c.cache != nil {
		err = c.cache.Put(ctx, key, data)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (c *S3AutocertCache) Delete(ctx context.Context, key string) error {

	// If a migration cache has been set, check to see if it exists and delete there first.
	if c.migrationCache != nil {
		err := c.migrationCache.Delete(ctx, key)
		if err != nil && err != autocert.ErrCacheMiss {
			return errors.WithStack(err)
		}
	}

	s3Key := filepath.Join(c.s3Prefix, key)

	_, err := s3.New(c.awsSession).DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(c.s3Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		return errors.Wrapf(err, "autocert failed to delete key s3://%s/%s", c.s3Bucket, s3Key)
	}

	log.Printf("Autocert : AWS S3 : Key s3://%s/%s deleted.", c.s3Bucket, s3Key)

	if c.cache != nil {
		err = c.cache.Delete(ctx, key)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
