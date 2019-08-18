package config

import (
	"log"
	"path/filepath"

	"encoding/json"
	"geeks-accelerator/oss/devops/pkg/devdeploy"
	"github.com/pkg/errors"
)

// Function define the name of a function.
type Function = string

var (
	Function_AwsLambdaGoFunc       = "aws-lambda-go-func"
	Function_AwsLambdaPythonDdlogs = "aws-lambda-python-ddlogs"
)

// ErrInvalidFunction occurs when no config can be determined for a function.
var ErrInvalidFunction = errors.New("Invalid function")

// FunctionContext defines the flags for deploying a function.
type FunctionContext struct {
	// Required flags.
	Name string `validate:"required" example:"aws-lambda-go-func"`

	// Optional flags.
	FunctionDir        string `validate:"omitempty"`
	BuildDir           string `validate:"omitempty"`
	DockerBuildContext string `validate:"omitempty" example:"."`
	Dockerfile         string `validate:"required" example:"./cmd/web-api/Dockerfile"`
	ReleaseTag         string `validate:"required"`
	EnableVPC          bool   `validate:"omitempty" example:"false"`
}

// NewFunctionContext returns the FunctionContext.
func NewFunctionContext(funcName string, cfg *devdeploy.Config) (*FunctionContext, error) {

	ctx := &FunctionContext{
		Name: funcName,

		FunctionDir: filepath.Join(cfg.ProjectRoot, "examples", funcName),

		DockerBuildContext: ".",

		// Set the release tag for the image to use include env + service name + commit hash/tag.
		ReleaseTag: devdeploy.GitLabCiReleaseTag(cfg.Env, funcName),
	}

	switch funcName {
	case Function_AwsLambdaGoFunc:
		// No additional settings for function.
	case Function_AwsLambdaPythonDdlogs:
		// Change the build directory to the function directory instead of project root.
		ctx.BuildDir = ctx.FunctionDir
	default:
		return nil, errors.Wrapf(ErrInvalidFunction,
			"No function context defined for function '%s'",
			funcName)
	}

	// Set the docker file if no custom one has been defined for the service.
	if ctx.Dockerfile == "" {
		ctx.Dockerfile = filepath.Join(ctx.BuildDir, "Dockerfile")
	}

	return ctx, nil
}

// BuildFunction handles defining all the information needed to deploy a service to AWS ECS.
func (ctx *FunctionContext) Build(log *log.Logger, noCache, noPush bool) (*devdeploy.BuildLambda, error) {

	log.Printf("Define build for function '%s'.", ctx.Name)
	log.Printf("\tUsing release tag %s.", ctx.ReleaseTag)

	srv := &devdeploy.BuildLambda{
		FuncName:           ctx.Name,
		ReleaseTag:         ctx.ReleaseTag,
		BuildDir:           ctx.BuildDir,
		Dockerfile:         ctx.Dockerfile,
		DockerBuildContext: ctx.DockerBuildContext,
		NoCache:            noCache,
		NoPush:             noPush,
	}

	return srv, nil
}

// S3Location returns the s3 bucket and key used to upload the code to.
func (ctx *FunctionContext) S3Location(cfg *devdeploy.Config) (string, string) {
	s3Bucket := cfg.AwsS3BucketPrivate.BucketName
	s3Key := filepath.Join("src", "aws", "lambda", cfg.Env, ctx.Name, ctx.ReleaseTag+".zip")

	return s3Bucket, s3Key
}

// BuildServiceForTargetEnv executes the build commands for a target service.
func BuildFunctionForTargetEnv(log *log.Logger, awsCredentials devdeploy.AwsCredentials, targetEnv Env, functionName, releaseTag string, dryRun, noCache, noPush bool) error {

	cfgCtx, err := NewConfigContext(targetEnv, awsCredentials)
	if err != nil {
		return err
	}

	cfg, err := cfgCtx.Config(log)
	if err != nil {
		return err
	}

	funcCtx, err := NewFunctionContext(functionName, cfg)
	if err != nil {
		return err
	}

	// Override the release tag if set.
	if releaseTag != "" {
		funcCtx.ReleaseTag = releaseTag
	}

	buildSrv, err := funcCtx.Build(log, noCache, noPush)
	if err != nil {
		return err
	}

	// Set the s3 bucket and s3 for uploading the zip file.
	buildSrv.LambdaS3Bucket, buildSrv.LambdaS3Key = funcCtx.S3Location(cfg)

	// funcPath is used to copy the service specific code in the Dockerfile.
	funcPath, err := filepath.Rel(cfg.ProjectRoot, funcCtx.FunctionDir)
	if err != nil {
		return err
	}

	// commitRef is used by main.go:build constant.
	commitRef := getCommitRef()
	if commitRef == "" {
		commitRef = funcCtx.ReleaseTag
	}

	buildSrv.BuildArgs = map[string]string{
		"func_path":  funcPath,
		"commit_ref": commitRef,
	}

	if dryRun {
		cfgJSON, err := json.MarshalIndent(cfg, "", "    ")
		if err != nil {
			log.Fatalf("BuildFunctionForTargetEnv : Marshalling config to JSON : %+v", err)
		}
		log.Printf("BuildFunctionForTargetEnv : config : %v\n", string(cfgJSON))

		return nil
	}

	return devdeploy.BuildLambdaForTargetEnv(log, cfg, buildSrv)
}
