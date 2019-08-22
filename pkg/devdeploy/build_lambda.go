package devdeploy

import (
	"log"
	"path/filepath"

	"gopkg.in/go-playground/validator.v9"
)

// BuildLambda defines the details needed to build a function using docker.
type BuildLambda struct {
	// Required flags.
	FuncName     string `validate:"required" example:"web-api"`
	Dockerfile   string `validate:"required" example:"./cmd/web-api/Dockerfile"`
	BuildDir     string `validate:"required"`
	ReleaseTag   string `validate:"required"`
	CodeS3Key    string `validate:"required"`
	CodeS3Bucket string `validate:"required"`

	// Optional flags.
	DockerBuildContext string `validate:"omitempty" example:"."`
	TargetLayer        string `validate:"omitempty" example:"lambda"`
	NoCache            bool   `validate:"omitempty" example:"false"`
	NoPush             bool   `validate:"omitempty" example:"false"`
	BuildArgs          map[string]string
}

// BuildLambdaForTargetEnv builds a lambda function using the defined Dockerfile and pushes the zip to AWS S3.
func BuildLambdaForTargetEnv(log *log.Logger, cfg *Config, targetFunc *BuildLambda) error {

	log.Printf("Build service %s for environment %s\n", targetFunc.FuncName, cfg.Env)

	if targetFunc.BuildDir == "" {
		targetFunc.BuildDir = cfg.ProjectRoot
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetFunc)
	if errs != nil {
		return errs
	}

	err := SetupBuildEnv(log, cfg)
	if err != nil {
		return err
	}

	// Ensure the bucket used to store the lambda function exists.
	s3Buckets := []*AwsS3Bucket{cfg.AwsS3BucketPublic, cfg.AwsS3BucketPrivate}
	for _, s3Bucket := range s3Buckets {
		if s3Bucket != nil && s3Bucket.BucketName == targetFunc.CodeS3Bucket {
			err = SetupS3Buckets(log, cfg, s3Bucket)
			if err != nil {
				return err
			}
		}
	}

	req := &BuildDockerRequest{
		Env:         cfg.Env,
		ProjectName: cfg.ProjectName,
		ServiceName: targetFunc.FuncName,

		ReleaseImage: filepath.Join(cfg.ProjectName, targetFunc.FuncName) + ":" + targetFunc.ReleaseTag,

		IsLambda:       true,
		LambdaS3Key:    targetFunc.CodeS3Key,
		LambdaS3Bucket: targetFunc.CodeS3Bucket,

		BuildDir:           targetFunc.BuildDir,
		Dockerfile:         targetFunc.Dockerfile,
		DockerBuildContext: targetFunc.DockerBuildContext,
		TargetLayer:        targetFunc.TargetLayer,

		AwsCredentials: cfg.AwsCredentials,

		NoCache: targetFunc.NoCache,
		NoPush:  targetFunc.NoPush,

		BuildArgs: targetFunc.BuildArgs,
	}

	return BuildDocker(log, req)
}
