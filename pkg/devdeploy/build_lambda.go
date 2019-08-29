package devdeploy

import (
	"log"
	"path/filepath"

	"gopkg.in/go-playground/validator.v9"
)

// BuildLambdaForTargetEnv builds a lambda function using the defined Dockerfile and pushes the zip to AWS S3.
func BuildLambdaForTargetEnv(log *log.Logger, cfg *Config, targetFunc *ProjectFunction, noCache, noPush bool) error {

	log.Printf("Build lambda %s for environment %s\n", targetFunc.Name, cfg.Env)

	if targetFunc.DockerBuildDir == "" {
		targetFunc.DockerBuildDir = cfg.ProjectRoot
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetFunc)
	if errs != nil {
		return errs
	}

	req := &BuildDockerRequest{
		Env:         cfg.Env,
		ProjectName: cfg.ProjectName,
		Name:        targetFunc.Name,

		ReleaseImage: filepath.Join(cfg.ProjectName, targetFunc.Name) + ":" + targetFunc.ReleaseTag,

		IsLambda:       true,
		LambdaS3Key:    targetFunc.CodeS3Key,
		LambdaS3Bucket: targetFunc.CodeS3Bucket,

		BuildDir:           targetFunc.DockerBuildDir,
		Dockerfile:         targetFunc.Dockerfile,
		DockerBuildContext: targetFunc.DockerBuildContext,
		BaseImageTags:      targetFunc.BaseImageTags,
		TargetLayer:        targetFunc.DockerBuildTargetLayer,

		AwsCredentials: cfg.AwsCredentials,

		NoCache: noCache,
		NoPush:  noPush,

		BuildArgs: targetFunc.DockerBuildArgs,
	}

	return BuildDocker(log, req)
}
