package config

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"

	"geeks-accelerator/oss/devops/pkg/devdeploy"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
)

// Service define the name of a service.
type Service = string

var (
	Service_AwsEcsGoWebApi = "aws-ecs-go-web-api"

	// Duplicate of aws-ecs-go-web-api service but with an ELB enabled.
	Service_AwsEcsGoWebApiElb = "aws-ecs-go-web-api-elb"
)

// ErrInvalidService occurs when no config can be determined for a service.
var ErrInvalidService = errors.New("Invalid service")

// ServiceContext defines the flags for deploying a service.
type ServiceContext struct {
	// Required flags.
	Name string `validate:"required" example:"web-api"`

	// Optional flags.
	EnableHTTPS         bool     `validate:"omitempty" example:"false"`
	EnableElb           bool     `validate:"omitempty" example:"false"`
	ServiceHostPrimary  string   `validate:"omitempty" example:"example-project.com"`
	ServiceHostNames    []string `validate:"omitempty" example:"subdomain.example-project.com"`
	DesiredCount        int      `validate:"omitempty" example:"2"`
	ServiceDir          string   `validate:"omitempty"`
	BuildDir            string   `validate:"omitempty"`
	DockerBuildContext  string   `validate:"omitempty" example:"."`
	Dockerfile          string   `validate:"required" example:"./cmd/web-api/Dockerfile"`
	ReleaseTag          string   `validate:"required"`
	StaticFilesS3Enable bool     `validate:"omitempty" example:"false"`
}

// NewServiceContext returns the ServiceContext for a service that is configured for the target deployment env.
func NewServiceContext(serviceName string, cfg *devdeploy.Config) (*ServiceContext, error) {

	ctx := &ServiceContext{
		Name:               serviceName,
		DesiredCount:       1,
		DockerBuildContext: ".",
		ServiceDir:         filepath.Join(cfg.ProjectRoot, "examples", serviceName),

		// Set the release tag for the image to use include env + service name + commit hash/tag.
		ReleaseTag: devdeploy.GitLabCiReleaseTag(cfg.Env, serviceName),
	}

	// Enable settings for the stage and prod envs.
	if cfg.Env == Env_Stage || cfg.Env == Env_Prod {
		ctx.EnableHTTPS = true
		ctx.StaticFilesS3Enable = true
	} else {
		// Only a single deployment env ATM, so default to true.
		ctx.EnableHTTPS = true
		ctx.StaticFilesS3Enable = true
	}

	switch serviceName {
	case Service_AwsEcsGoWebApi:
		ctx.ServiceHostPrimary = fmt.Sprintf("%s.devops.example.saasstartupkit.com", cfg.Env)

		ctx.ServiceHostNames = []string{
			fmt.Sprintf("api.%s.devops.example.saasstartupkit.com", cfg.Env),
		}

	// Duplicate service but with an ELB enabled using a different hostname.
	case Service_AwsEcsGoWebApiElb:
		ctx.EnableElb = true

		ctx.ServiceHostPrimary = fmt.Sprintf("elb.%s.devops.example.saasstartupkit.com", cfg.Env)
		ctx.ServiceDir = filepath.Join(cfg.ProjectRoot, "examples", Service_AwsEcsGoWebApi)

	default:
		return nil, errors.Wrapf(ErrInvalidService,
			"No service context defined for service '%s'",
			serviceName)
	}

	// Set the docker file if no custom one has been defined for the service.
	if ctx.Dockerfile == "" {
		ctx.Dockerfile = filepath.Join(ctx.ServiceDir, "Dockerfile")
	}

	return ctx, nil
}

// BuildService handles defining all the information needed to a service with docker and push to AWS ECR.
func (ctx *ServiceContext) Build(log *log.Logger, noCache, noPush bool) (*devdeploy.BuildService, error) {

	log.Printf("Define build for service '%s'.", ctx.Name)
	log.Printf("\tUsing release tag %s.", ctx.ReleaseTag)

	srv := &devdeploy.BuildService{
		ServiceName:        ctx.Name,
		ReleaseTag:         ctx.ReleaseTag,
		BuildDir:           ctx.BuildDir,
		Dockerfile:         ctx.Dockerfile,
		DockerBuildContext: ctx.DockerBuildContext,
		NoCache:            noCache,
		NoPush:             noPush,
	}

	return srv, nil
}

// DeployService handles defining all the information needed to deploy a service to AWS ECS.
func (ctx *ServiceContext) Deploy(log *log.Logger, cfg *devdeploy.Config) (*devdeploy.DeployService, error) {

	log.Printf("Define deploy for service '%s'.", ctx.Name)
	log.Printf("\tUsing release tag %s.", ctx.ReleaseTag)

	// Start to define all the information for the service from the service context.
	srv := &devdeploy.DeployService{
		ServiceName:        ctx.Name,
		ReleaseTag:         ctx.ReleaseTag,
		EnableHTTPS:        ctx.EnableHTTPS,
		ServiceHostPrimary: ctx.ServiceHostPrimary,
		ServiceHostNames:   ctx.ServiceHostNames,
	}

	// When only service host names are set, choose the first item as the primary host.
	if srv.ServiceHostPrimary == "" && len(srv.ServiceHostNames) > 0 {
		srv.ServiceHostPrimary = srv.ServiceHostNames[0]
		log.Printf("\t\tSet Service Primary Host to '%s'.", srv.ServiceHostPrimary)
	}

	// The S3 prefix used to upload static files served to public.
	if ctx.StaticFilesS3Enable {
		srv.StaticFilesS3Prefix = filepath.Join(cfg.AwsS3BucketPublicKeyPrefix, srv.ReleaseTag, "static")
	}

	// Determine the Dockerfile for the service.
	if ctx.Dockerfile != "" {
		srv.Dockerfile = ctx.Dockerfile
		log.Printf("\t\tUsing docker file '%s'.", srv.Dockerfile)
	} else {
		var err error
		srv.Dockerfile, err = devdeploy.FindServiceDockerFile(cfg.ProjectRoot, srv.ServiceName)
		if err != nil {
			return nil, err
		}
		log.Printf("\t\tFound service docker file '%s'.", srv.Dockerfile)
	}

	// Set the service directory.
	if ctx.ServiceDir == "" {
		ctx.ServiceDir = filepath.Dir(srv.Dockerfile)
	}
	srv.StaticFilesDir = filepath.Join(ctx.ServiceDir, "static")

	// Define the ECS Cluster used to host the serverless fargate tasks.
	srv.AwsEcsCluster = &devdeploy.AwsEcsCluster{
		ClusterName: cfg.ProjectName + "-" + cfg.Env,
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
	}

	// Define the ECS task execution role. This role executes ECS actions such as pulling the image and storing the
	// application logs in cloudwatch.
	srv.AwsEcsExecutionRole = &devdeploy.AwsIamRole{
		RoleName:                 fmt.Sprintf("ecsExecutionRole%s%s", cfg.ProjectNameCamel(), strcase.ToCamel(cfg.Env)),
		Description:              fmt.Sprintf("Provides access to other AWS service resources that are required to run Amazon ECS tasks for %s. ", cfg.ProjectName),
		AssumeRolePolicyDocument: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ecs-tasks.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}",
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
		AttachRolePolicyArns: []string{"arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"},
	}
	log.Printf("\t\tSet ECS Execution Role Name to '%s'.", srv.AwsEcsExecutionRole)

	// Define the ECS task role. This role is used by the task itself for calling other AWS services.
	srv.AwsEcsTaskRole = &devdeploy.AwsIamRole{
		RoleName:                 fmt.Sprintf("ecsTaskRole%s%s", cfg.ProjectNameCamel(), strcase.ToCamel(cfg.Env)),
		Description:              fmt.Sprintf("Allows ECS tasks for %s to call AWS services on your behalf.", cfg.ProjectName),
		AssumeRolePolicyDocument: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ecs-tasks.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}",
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
	}
	log.Printf("\t\tSet ECS Task Role Name to '%s'.", srv.AwsEcsTaskRole)

	// AwsCloudWatchLogGroup defines the name of the cloudwatch log group that will be used to store logs for the ECS tasks.
	srv.AwsCloudWatchLogGroup = &devdeploy.AwsCloudWatchLogGroup{
		LogGroupName: fmt.Sprintf("logs/env_%s/aws/ecs/cluster_%s/service_%s", cfg.Env, srv.AwsEcsCluster.ClusterName, srv.ServiceName),
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
	}
	log.Printf("\t\tSet AWS Log Group Name to '%s'.", srv.AwsCloudWatchLogGroup.LogGroupName)

	// AwsSdPrivateDnsNamespace defines the service discovery group.
	srv.AwsSdPrivateDnsNamespace = &devdeploy.AwsSdPrivateDnsNamespace{
		Name:        srv.AwsEcsCluster.ClusterName,
		Description: fmt.Sprintf("Private DNS namespace used for services running on the ECS Cluster %s", srv.AwsEcsCluster.ClusterName),
		Service: &devdeploy.AwsSdService{
			Name:                        ctx.Name,
			Description:                 fmt.Sprintf("Service %s running on the ECS Cluster %s", ctx.Name, srv.AwsEcsCluster.ClusterName),
			DnsRecordTTL:                300,
			HealthCheckFailureThreshold: 3,
		},
	}
	log.Printf("\t\tSet AWS Service Discovery Namespace to '%s'.", srv.AwsSdPrivateDnsNamespace.Name)

	// If the service is requested to use an elastic load balancer then define.
	if ctx.EnableElb {
		// AwsElbLoadBalancer defines if the service should use an elastic load balancer.
		srv.AwsElbLoadBalancer = &devdeploy.AwsElbLoadBalancer{
			Name:          fmt.Sprintf("%s-%s-%s", cfg.Env, srv.AwsEcsCluster.ClusterName, srv.ServiceName),
			IpAddressType: "ipv4",
			Scheme:        "internet-facing",
			Type:          "application",
			Tags: []devdeploy.Tag{
				{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
				{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
			},
		}
		log.Printf("\t\tSet ELB Name to '%s'.", srv.AwsElbLoadBalancer.Name)

		// Define the target group for service to receive HTTP traffic from the load balancer.
		srv.AwsElbLoadBalancer.TargetGroup = &devdeploy.AwsElbTargetGroup{
			Name:                       fmt.Sprintf("%s-http", srv.ServiceName),
			Port:                       80,
			Protocol:                   "HTTP",
			TargetType:                 "ip",
			HealthCheckEnabled:         true,
			HealthCheckIntervalSeconds: 30,
			HealthCheckPath:            "/ping",
			HealthCheckProtocol:        "HTTP",
			HealthCheckTimeoutSeconds:  5,
			HealthyThresholdCount:      3,
			UnhealthyThresholdCount:    3,
			Matcher:                    "200",
		}
		log.Printf("\t\t\tSet ELB Target Group Name for %s to '%s'.",
			srv.AwsElbLoadBalancer.TargetGroup.Protocol,
			srv.AwsElbLoadBalancer.TargetGroup.Name)

		// Set ECS configs based on specified env.
		if cfg.Env == "prod" {
			srv.AwsElbLoadBalancer.EcsTaskDeregistrationDelay = 300
		} else {
			// Force staging to deploy immediately without waiting for connections to drain
			srv.AwsElbLoadBalancer.EcsTaskDeregistrationDelay = 0
		}
	}

	// AwsEcsService defines the details for the ecs service.
	srv.AwsEcsService = &devdeploy.AwsEcsService{
		ServiceName:                   ctx.Name,
		DesiredCount:                  int64(ctx.DesiredCount),
		EnableECSManagedTags:          false,
		HealthCheckGracePeriodSeconds: 60,
		LaunchType:                    "FARGATE",
	}

	// Ensure when deploying a new service there is always at-least one running.
	if srv.AwsEcsService.DesiredCount == 0 {
		srv.AwsEcsService.DesiredCount = 1
	}

	// Set ECS configs based on specified env.
	if cfg.Env == "prod" {
		srv.AwsEcsService.DeploymentMinimumHealthyPercent = 100
		srv.AwsEcsService.DeploymentMaximumPercent = 200
	} else {
		srv.AwsEcsService.DeploymentMinimumHealthyPercent = 100
		srv.AwsEcsService.DeploymentMaximumPercent = 200
	}

	// Read the defined json task definition for the service.
	dat, err := devdeploy.EcsReadTaskDefinition(ctx.ServiceDir, cfg.Env)
	if err != nil {
		return srv, err
	}

	// JSON decode the task definition.
	taskDef, err := devdeploy.ParseTaskDefinitionInput(dat)
	if err != nil {
		return srv, err
	}

	// AwsEcsTaskDefinition defines the details for registering a new ECS task definition.
	srv.AwsEcsTaskDefinition = &devdeploy.AwsEcsTaskDefinition{
		RegisterInput: taskDef,
		UpdatePlaceholders: func(placeholders map[string]string) error {

			// Try to find the Datadog API key, this value is optional.
			// If Datadog API key is not specified, then integration with Datadog for observability will not be active.
			{
				// Load Datadog API key which can be either stored in an environment variable or in AWS Secrets Manager.
				// 1. Check env vars for [DEV|STAGE|PROD]_DD_API_KEY and DD_API_KEY
				datadogApiKey := devdeploy.GetTargetEnv(cfg.Env, "DD_API_KEY")

				// 2. Check AWS Secrets Manager for datadog entry prefixed with target environment.
				if datadogApiKey == "" {
					prefixedSecretId := cfg.SecretID("datadog/api-key")
					var err error
					datadogApiKey, err = devdeploy.GetAwsSecretValue(cfg.AwsCredentials, prefixedSecretId)
					if err != nil {
						if aerr, ok := errors.Cause(err).(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
							return err
						}
					}
				}

				// 3. Check AWS Secrets Manager for Datadog entry.
				if datadogApiKey == "" {
					secretId := "DATADOG"
					var err error
					datadogApiKey, err = devdeploy.GetAwsSecretValue(cfg.AwsCredentials, secretId)
					if err != nil {
						if aerr, ok := errors.Cause(err).(awserr.Error); !ok || aerr.Code() != secretsmanager.ErrCodeResourceNotFoundException {
							return err
						}
					}
				}

				if datadogApiKey != "" {
					log.Println("DATADOG API Key set.")
				} else {
					log.Printf("DATADOG API Key NOT set.")
				}

				placeholders["{DATADOG_APIKEY}"] = datadogApiKey

				// When the datadog API key is empty, don't force the container to be essential have have the whole task fail.
				if datadogApiKey != "" {
					placeholders["{DATADOG_ESSENTIAL}"] = "true"
				} else {
					placeholders["{DATADOG_ESSENTIAL}"] = "false"
				}
			}

			return nil
		},
	}

	return srv, nil
}

// BuildServiceForTargetEnv executes the build commands for a target service.
func BuildServiceForTargetEnv(log *log.Logger, awsCredentials devdeploy.AwsCredentials, targetEnv Env, serviceName, releaseTag string, dryRun, noCache, noPush bool) error {

	cfgCtx, err := NewConfigContext(targetEnv, awsCredentials)
	if err != nil {
		return err
	}

	cfg, err := cfgCtx.Config(log)
	if err != nil {
		return err
	}

	srvCtx, err := NewServiceContext(serviceName, cfg)
	if err != nil {
		return err
	}

	// Override the release tag if set.
	if releaseTag != "" {
		srvCtx.ReleaseTag = releaseTag
	}

	buildSrv, err := srvCtx.Build(log, noCache, noPush)
	if err != nil {
		return err
	}

	// servicePath is used to copy the service specific code in the Dockerfile.
	servicePath, err := filepath.Rel(cfg.ProjectRoot, srvCtx.ServiceDir)
	if err != nil {
		return err
	}

	// commitRef is used by main.go:build constant.
	commitRef := getCommitRef()
	if commitRef == "" {
		commitRef = srvCtx.ReleaseTag
	}

	buildSrv.BuildArgs = map[string]string{
		"service_path": servicePath,
		"commit_ref":   commitRef,
	}

	if dryRun {
		cfgJSON, err := json.MarshalIndent(cfg, "", "    ")
		if err != nil {
			log.Fatalf("BuildServiceForTargetEnv : Marshalling config to JSON : %+v", err)
		}
		log.Printf("BuildServiceForTargetEnv : config : %v\n", string(cfgJSON))

		return nil
	}

	return devdeploy.BuildServiceForTargetEnv(log, cfg, buildSrv)
}
