package config

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy"
)

const (
	// EnableServiceElb will enable all services to be deployed with an ELB (Elastic Load Balancer).
	// This will only be applied to the prod env, but the logic can be changed in the code below.
	//
	// When enabled each service will require it's own ELB and therefore will add $20~ month per service when
	// this is enabled. The hostnames defined for the service will be updated in Route53 to resolve to the ELB.
	// If HTTPS is enabled, the ELB will be created with an AWS ACM certificate that will support SSL termination on
	// the ELB, all traffic will be sent to the container as HTTP.
	// This can be configured on a by service basis.
	//
	// When not enabled, tasks will be auto assigned a public IP. As ECS tasks for the service are launched/terminated,
	// the task will update the hostnames defined for the service in Route53 to either add/remove its public IP. This
	// option is good for services that only need one container running.
	EnableServiceElb = true

	// EnableServiceAutoscaling will enable all services to be deployed with an application scaling policy.
	EnableServiceAutoscaling = true
)

// Service define the name of a service.
type Service = string

var (
	ServiceGoWebApi = "aws-ecs-go-web-api"
)

// List of service names used by main.go for help and append the services to config.
var ServiceNames = []Service{
	ServiceGoWebApi,
}

// NewService returns the ProjectService for a service that is configured for the target deployment env.
func NewService(serviceName string, cfg *devdeploy.Config) (*devdeploy.ProjectService, error) {

	// =========================================================================
	// New project service.
	ctx := &devdeploy.ProjectService{
		Name:               serviceName,
		CodeDir:            filepath.Join(cfg.ProjectRoot, "examples", serviceName),
		DockerBuildDir:     cfg.ProjectRoot,
		DockerBuildContext: ".",

		// Set the release tag for the image to use include env + service name + commit hash/tag.
		ReleaseTag: devdeploy.GitLabCiReleaseTag(cfg.Env, serviceName),
	}

	// =========================================================================
	// Context settings based on target env.
	var enableElb bool
	var desiredCount int64
	if cfg.Env == EnvStage || cfg.Env == EnvProd {
		desiredCount = 1

		ctx.EnableHTTPS = true

		if cfg.Env == EnvProd && EnableServiceElb {
			enableElb = true
		}

		// Sync static files to S3 will be enabled when the S3 prefix is defined.
		ctx.StaticFilesS3Prefix = filepath.Join(cfg.AwsS3BucketPublicKeyPrefix, ctx.ReleaseTag, "static")
	} else {
		desiredCount = 1

		ctx.EnableHTTPS = false
	}

	// =========================================================================
	// Shared details that could be applied to all task definitions.

	// Define the ECS Cluster used to host the serverless fargate tasks.
	ctx.AwsEcsCluster = &devdeploy.AwsEcsCluster{
		ClusterName: cfg.ProjectName + "-" + cfg.Env,
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
	}

	// Define the ECS task execution role. This role executes ECS actions such as pulling the image and storing the
	// application logs in cloudwatch.
	ctx.AwsEcsExecutionRole = &devdeploy.AwsIamRole{
		RoleName:                 fmt.Sprintf("ecsExecutionRole%s%s", cfg.ProjectNameCamel(), strcase.ToCamel(cfg.Env)),
		Description:              fmt.Sprintf("Provides access to other AWS service resources that are required to run Amazon ECS tasks for %s. ", cfg.ProjectName),
		AssumeRolePolicyDocument: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ecs-tasks.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}",
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
		AttachRolePolicyArns: []string{"arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"},
	}
	log.Printf("\t\tSet ECS Execution Role Name to '%s'.", ctx.AwsEcsExecutionRole.RoleName)

	// Define the ECS task role. This role is used by the task itself for calling other AWS services.
	ctx.AwsEcsTaskRole = &devdeploy.AwsIamRole{
		RoleName:                 fmt.Sprintf("ecsTaskRole%s%s", cfg.ProjectNameCamel(), strcase.ToCamel(cfg.Env)),
		Description:              fmt.Sprintf("Allows ECS tasks for %s to call AWS services on your behalf.", cfg.ProjectName),
		AssumeRolePolicyDocument: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ecs-tasks.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}",
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
	}
	log.Printf("\t\tSet ECS Task Role Name to '%s'.", ctx.AwsEcsTaskRole.RoleName)

	// AwsCloudWatchLogGroup defines the name of the cloudwatch log group that will be used to store logs for the ECS tasks.
	ctx.AwsCloudWatchLogGroup = &devdeploy.AwsCloudWatchLogGroup{
		LogGroupName: fmt.Sprintf("logs/env_%s/aws/ecs/cluster_%s/service_%s", cfg.Env, ctx.AwsEcsCluster.ClusterName, ctx.Name),
		Tags: []devdeploy.Tag{
			{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
			{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
		},
	}
	log.Printf("\t\tSet AWS Log Group Name to '%s'.", ctx.AwsCloudWatchLogGroup.LogGroupName)

	// AwsSdPrivateDnsNamespace defines the service discovery group.
	ctx.AwsSdPrivateDnsNamespace = &devdeploy.AwsSdPrivateDnsNamespace{
		Name:        ctx.AwsEcsCluster.ClusterName,
		Description: fmt.Sprintf("Private DNS namespace used for services running on the ECS Cluster %s", ctx.AwsEcsCluster.ClusterName),
		Service: &devdeploy.AwsSdService{
			Name:                        ctx.Name,
			Description:                 fmt.Sprintf("Service %s running on the ECS Cluster %s", ctx.Name, ctx.AwsEcsCluster.ClusterName),
			DnsRecordTTL:                300,
			HealthCheckFailureThreshold: 3,
		},
	}
	log.Printf("\t\tSet AWS Service Discovery Namespace to '%s'.", ctx.AwsSdPrivateDnsNamespace.Name)

	// If the service is requested to use an elastic load balancer then define.
	if enableElb {
		// AwsElbLoadBalancer defines if the service should use an elastic load balancer.
		ctx.AwsElbLoadBalancer = &devdeploy.AwsElbLoadBalancer{
			Name:          fmt.Sprintf("%s-%s", cfg.Env, ctx.Name),
			IpAddressType: "ipv4",
			Scheme:        "internet-facing",
			Type:          "application",
			Tags: []devdeploy.Tag{
				{Key: devdeploy.AwsTagNameProject, Value: cfg.ProjectName},
				{Key: devdeploy.AwsTagNameEnv, Value: cfg.Env},
			},
		}
		log.Printf("\t\tSet ELB Name to '%s'.", ctx.AwsElbLoadBalancer.Name)

		// Define the target group for service to receive HTTP traffic from the load balancer.
		ctx.AwsElbLoadBalancer.TargetGroups = []*devdeploy.AwsElbTargetGroup{
			&devdeploy.AwsElbTargetGroup{
				Name:                       fmt.Sprintf("%s-http", ctx.Name),
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
			},
		}
		log.Printf("\t\t\tSet ELB Target Group Name for %s to '%s'.",
			ctx.AwsElbLoadBalancer.TargetGroups[0].Protocol,
			ctx.AwsElbLoadBalancer.TargetGroups[0].Name)

		// Set ECS configs based on specified env.
		if cfg.Env == "prod" {
			ctx.AwsElbLoadBalancer.EcsTaskDeregistrationDelay = 300
		} else {
			// Force staging to deploy immediately without waiting for connections to drain
			ctx.AwsElbLoadBalancer.EcsTaskDeregistrationDelay = 0
		}
	}

	// AwsEcsService defines the details for the ecs service.
	ctx.AwsEcsService = &devdeploy.AwsEcsService{
		ServiceName:                   ctx.Name,
		DesiredCount:                  desiredCount,
		EnableECSManagedTags:          false,
		HealthCheckGracePeriodSeconds: 60,
		LaunchType:                    "FARGATE",
	}

	// Set ECS configs based on specified env.
	if cfg.Env == "prod" {
		ctx.AwsEcsService.DeploymentMinimumHealthyPercent = 100
		ctx.AwsEcsService.DeploymentMaximumPercent = 200
	} else {
		ctx.AwsEcsService.DeploymentMinimumHealthyPercent = 100
		ctx.AwsEcsService.DeploymentMaximumPercent = 200
	}

	if EnableServiceAutoscaling {
		ctx.AwsAppAutoscalingPolicy = &devdeploy.AwsAppAutoscalingPolicy{
			// The name of the scaling policy.
			PolicyName: ctx.AwsEcsService.ServiceName,

			// The policy type. This parameter is required if you are creating a scaling
			// policy.
			//
			// The following policy types are supported:
			//
			// TargetTrackingScaling—Not supported for Amazon EMR or AppStream
			//
			// StepScaling—Not supported for Amazon DynamoDB
			//
			// For more information, see Step Scaling Policies for Application Auto Scaling
			// (https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-step-scaling-policies.html)
			// and Target Tracking Scaling Policies for Application Auto Scaling (https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html)
			// in the Application Auto Scaling User Guide.
			PolicyType: "TargetTrackingScaling",

			// The minimum value to scale to in response to a scale-in event. MinCapacity
			// is required to register a scalable target.
			MinCapacity: desiredCount,

			// The maximum value to scale to in response to a scale-out event. MaxCapacity
			// is required to register a scalable target.
			MaxCapacity: desiredCount * 2,

			// A target tracking scaling policy. Includes support for predefined or customized metrics.
			TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{

				// A predefined metric. You can specify either a predefined metric or a customized
				// metric.
				PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
					// The metric type. The following predefined metrics are available:
					//
					//    * ASGAverageCPUUtilization - Average CPU utilization of the Auto Scaling
					//    group.
					//
					//    * ASGAverageNetworkIn - Average number of bytes received on all network
					//    interfaces by the Auto Scaling group.
					//
					//    * ASGAverageNetworkOut - Average number of bytes sent out on all network
					//    interfaces by the Auto Scaling group.
					//
					//    * ALBRequestCountPerTarget - Number of requests completed per target in
					//    an Application Load Balancer target group. ResourceLabel will be auto populated.
					//
					PredefinedMetricType: aws.String("ECSServiceAverageCPUUtilization"),
				},

				// The target value for the metric. The range is 8.515920e-109 to 1.174271e+108
				// (Base 10) or 2e-360 to 2e360 (Base 2).
				TargetValue: aws.Float64(70.0),

				// The amount of time, in seconds, after a scale-in activity completes before
				// another scale in activity can start.
				//
				// The cooldown period is used to block subsequent scale-in requests until it
				// has expired. The intention is to scale in conservatively to protect your
				// application's availability. However, if another alarm triggers a scale-out
				// policy during the cooldown period after a scale-in, Application Auto Scaling
				// scales out your scalable target immediately.
				ScaleInCooldown: aws.Int64(300),

				// The amount of time, in seconds, after a scale-out activity completes before
				// another scale-out activity can start.
				//
				// While the cooldown period is in effect, the capacity that has been added
				// by the previous scale-out event that initiated the cooldown is calculated
				// as part of the desired capacity for the next scale out. The intention is
				// to continuously (but not excessively) scale out.
				ScaleOutCooldown: aws.Int64(300),

				// Indicates whether scale in by the target tracking scaling policy is disabled.
				// If the value is true, scale in is disabled and the target tracking scaling
				// policy won't remove capacity from the scalable resource. Otherwise, scale
				// in is enabled and the target tracking scaling policy can remove capacity
				// from the scalable resource. The default value is false.
				DisableScaleIn: aws.Bool(false),
			},
		}
	}

	// Define a base set of environment variables that can be assigned to individual container definitions.
	baseEnvVals := func() []*ecs.KeyValuePair {

		var ciJobURL string
		if id := os.Getenv("CI_JOB_ID"); id != "" {
			ciJobURL = strings.TrimRight(GitLabProjectBaseUrl, "/") + "/-/jobs/" + os.Getenv("CI_JOB_ID")
		}

		var ciPipelineURL string
		if id := os.Getenv("CI_PIPELINE_ID"); id != "" {
			ciPipelineURL = strings.TrimRight(GitLabProjectBaseUrl, "/") + "/pipelines/" + os.Getenv("CI_PIPELINE_ID")
		}

		return []*ecs.KeyValuePair{
			ecsKeyValuePair(devdeploy.ENV_KEY_ECS_CLUSTER, ctx.AwsEcsCluster.ClusterName),
			ecsKeyValuePair(devdeploy.ENV_KEY_ECS_SERVICE, ctx.AwsEcsService.ServiceName),
			ecsKeyValuePair("AWS_DEFAULT_REGION", cfg.AwsCredentials.Region),
			ecsKeyValuePair("AWS_USE_ROLE", "true"),
			ecsKeyValuePair("AWSLOGS_GROUP", ctx.AwsCloudWatchLogGroup.LogGroupName),
			ecsKeyValuePair("ECS_ENABLE_CONTAINER_METADATA", "true"),
			ecsKeyValuePair("CI_COMMIT_REF_NAME", os.Getenv("CI_COMMIT_REF_NAME")),
			ecsKeyValuePair("CI_COMMIT_SHORT_SHA", os.Getenv("CI_COMMIT_SHORT_SHA")),
			ecsKeyValuePair("CI_COMMIT_SHA", os.Getenv("CI_COMMIT_SHA")),
			ecsKeyValuePair("CI_COMMIT_TAG", os.Getenv("CI_COMMIT_TAG")),
			ecsKeyValuePair("CI_JOB_ID", os.Getenv("CI_JOB_ID")),
			ecsKeyValuePair("CI_PIPELINE_ID", os.Getenv("CI_PIPELINE_ID")),
			ecsKeyValuePair("CI_JOB_URL", ciJobURL),
			ecsKeyValuePair("CI_PIPELINE_URL", ciPipelineURL),
		}
	}

	// =========================================================================
	// Service dependant settings.
	switch serviceName {
	case ServiceGoWebApi:
		if cfg.Env == EnvProd {
			ctx.ServiceHostPrimary = "devops.example.saasstartupkit.com"

			ctx.ServiceHostNames = []string{
				fmt.Sprintf("api.%s.devops.example.saasstartupkit.com", cfg.Env),
			}
		} else {
			ctx.ServiceHostPrimary = fmt.Sprintf("api.%s.devops.example.saasstartupkit.com", cfg.Env)
		}

		// Defined a container definition for the specific service.
		container1 := &ecs.ContainerDefinition{
			Name:      aws.String(ctx.Name),
			Image:     aws.String(ctx.ReleaseImage),
			Essential: aws.Bool(true),
			LogConfiguration: &ecs.LogConfiguration{
				LogDriver: aws.String("awslogs"),
				Options: map[string]*string{
					"awslogs-group":         aws.String(ctx.AwsCloudWatchLogGroup.LogGroupName),
					"awslogs-region":        aws.String(cfg.AwsCredentials.Region),
					"awslogs-stream-prefix": aws.String("ecs"),
				},
			},
			PortMappings: []*ecs.PortMapping{
				&ecs.PortMapping{
					HostPort:      aws.Int64(80),
					Protocol:      aws.String("tcp"),
					ContainerPort: aws.Int64(80),
				},
			},
			Cpu:               aws.Int64(128),
			MemoryReservation: aws.Int64(128),
			Environment:       baseEnvVals(),
			HealthCheck: &ecs.HealthCheck{
				Retries: aws.Int64(3),
				Command: aws.StringSlice([]string{
					"CMD-SHELL",
					"curl -f http://localhost/ping || exit 1",
				}),
				Timeout:     aws.Int64(5),
				Interval:    aws.Int64(60),
				StartPeriod: aws.Int64(60),
			},
			Ulimits: []*ecs.Ulimit{
				&ecs.Ulimit{
					Name:      aws.String("nofile"),
					SoftLimit: aws.Int64(987654),
					HardLimit: aws.Int64(999999),
				},
			},
		}

		// If the service has HTTPS enabled with the use of an AWS Elastic Load Balancer, then need to enable
		// traffic for port 443 for SSL traffic to get terminated on the deployed tasks.
		if ctx.EnableHTTPS && !enableElb {
			container1.PortMappings = append(container1.PortMappings, &ecs.PortMapping{
				HostPort:      aws.Int64(443),
				Protocol:      aws.String("tcp"),
				ContainerPort: aws.Int64(443),
			})
		}

		// Append env vars for the service task.
		container1.Environment = append(container1.Environment,
			ecsKeyValuePair("SERVICE_NAME", ctx.Name),
			ecsKeyValuePair("PROJECT_NAME", cfg.ProjectName),

			// Use placeholders for these environment variables that will be replaced with devdeploy.DeployServiceToTargetEnv
			ecsKeyValuePair("WEB_API_SERVICE_HOST", "{HTTP_HOST}"),
			ecsKeyValuePair("WEB_API_SERVICE_HTTPS_HOST", "{HTTPS_HOST}"),
			ecsKeyValuePair("WEB_API_SERVICE_ENABLE_HTTPS", "{HTTPS_ENABLED}"),
			ecsKeyValuePair("WEB_API_SERVICE_BASE_URL", "{APP_BASE_URL}"),
			ecsKeyValuePair("WEB_API_SERVICE_HOST_NAMES", "{HOST_NAMES}"),
			ecsKeyValuePair("WEB_API_SERVICE_STATICFILES_S3_ENABLED", "{STATIC_FILES_S3_ENABLED}"),
			ecsKeyValuePair("WEB_API_SERVICE_STATICFILES_S3_PREFIX", "{STATIC_FILES_S3_PREFIX}"),
			ecsKeyValuePair("WEB_API_SERVICE_STATICFILES_CLOUDFRONT_ENABLED", "{STATIC_FILES_CLOUDFRONT_ENABLED}"),
			ecsKeyValuePair("WEB_API_REDIS_HOST", "{CACHE_HOST}"),
			ecsKeyValuePair("WEB_API_DB_HOST", "{DB_HOST}"),
			ecsKeyValuePair("WEB_API_DB_USERNAME", "{DB_USER}"),
			ecsKeyValuePair("WEB_API_DB_PASSWORD", "{DB_PASS}"),
			ecsKeyValuePair("WEB_API_DB_DATABASE", "{DB_DATABASE}"),
			ecsKeyValuePair("WEB_API_DB_DRIVER", "{DB_DRIVER}"),
			ecsKeyValuePair("WEB_API_DB_DISABLE_TLS", "{DB_DISABLE_TLS}"),
			ecsKeyValuePair("WEB_API_AWS_S3_BUCKET_PRIVATE", "{AWS_S3_BUCKET_PRIVATE}"),
			ecsKeyValuePair("WEB_API_AWS_S3_BUCKET_PUBLIC", "{AWS_S3_BUCKET_PUBLIC}"),
			ecsKeyValuePair(devdeploy.ENV_KEY_ROUTE53_UPDATE_TASK_IPS, "{ROUTE53_UPDATE_TASK_IPS}"),
			ecsKeyValuePair(devdeploy.ENV_KEY_ROUTE53_ZONES, "{ROUTE53_ZONES}"),
		)

		// Define the full task definition for the service.
		taskDef := &ecs.RegisterTaskDefinitionInput{
			Family:      aws.String(fmt.Sprintf("%s-%s-%s", cfg.Env, ctx.AwsEcsCluster.ClusterName, ctx.Name)),
			NetworkMode: aws.String("awsvpc"),
			ContainerDefinitions: []*ecs.ContainerDefinition{
				// Include the single container definition for the service. Additional definitions could be added
				// here like one for datadog.
				container1,
			},
			RequiresCompatibilities: aws.StringSlice([]string{"FARGATE"}),
		}

		ctx.AwsEcsTaskDefinition = &devdeploy.AwsEcsTaskDefinition{
			RegisterInput: taskDef,
			UpdatePlaceholders: func(placeholders map[string]string) error {

				// Try to find the Datadog API key, this value is optional.
				// If Datadog API key is not specified, then integration with Datadog for observability will not be active.
				{
					datadogApiKey, err := getDatadogApiKey(cfg)
					if err != nil {
						return err
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

	default:
		return nil, errors.Wrapf(devdeploy.ErrInvalidService,
			"No service context defined for service '%s'",
			serviceName)
	}

	// Set the docker file if no custom one has been defined for the service.
	if ctx.Dockerfile == "" {
		ctx.Dockerfile = filepath.Join(ctx.CodeDir, "Dockerfile")
	}

	if ctx.StaticFilesDir == "" {
		ctx.StaticFilesDir = filepath.Join(ctx.CodeDir, "static")
	}

	// When only service host names are set, choose the first item as the primary host.
	if ctx.ServiceHostPrimary == "" && len(ctx.ServiceHostNames) > 0 {
		ctx.ServiceHostPrimary = ctx.ServiceHostNames[0]
		log.Printf("\t\tSet Service Primary Host to '%s'.", ctx.ServiceHostPrimary)
	}

	return ctx, nil
}

// BuildServiceForTargetEnv executes the build commands for a target service.
func BuildServiceForTargetEnv(log *log.Logger, awsCredentials devdeploy.AwsCredentials, targetEnv Env, serviceName, releaseTag string, dryRun, noCache, noPush bool) error {

	cfg, err := NewConfig(log, targetEnv, awsCredentials)
	if err != nil {
		return err
	}

	targetSvc, err := NewService(serviceName, cfg)
	if err != nil {
		return err
	}

	// Override the release tag if set.
	if releaseTag != "" {
		targetSvc.ReleaseTag = releaseTag
	}

	// Append build args to be used for all services.
	if targetSvc.DockerBuildArgs == nil {
		targetSvc.DockerBuildArgs = make(map[string]string)
	}

	// servicePath is used to copy the service specific code in the Dockerfile.
	codePath, err := filepath.Rel(cfg.ProjectRoot, targetSvc.CodeDir)
	if err != nil {
		return err
	}
	targetSvc.DockerBuildArgs["code_path"] = codePath

	// commitRef is used by main.go:build constant.
	commitRef := getCommitRef()
	if commitRef == "" {
		commitRef = targetSvc.ReleaseTag
	}
	targetSvc.DockerBuildArgs["commit_ref"] = commitRef

	if dryRun {
		cfgJSON, err := json.MarshalIndent(cfg, "", "    ")
		if err != nil {
			log.Fatalf("BuildServiceForTargetEnv : Marshalling config to JSON : %+v", err)
		}
		log.Printf("BuildServiceForTargetEnv : config : %v\n", string(cfgJSON))

		detailsJSON, err := json.MarshalIndent(targetSvc, "", "    ")
		if err != nil {
			log.Fatalf("BuildServiceForTargetEnv : Marshalling details to JSON : %+v", err)
		}
		log.Printf("BuildServiceForTargetEnv : details : %v\n", string(detailsJSON))

		return nil
	}

	return devdeploy.BuildServiceForTargetEnv(log, cfg, targetSvc, noCache, noPush)
}

// DeployServiceForTargetEnv executes the build commands for a target service.
func DeployServiceForTargetEnv(log *log.Logger, awsCredentials devdeploy.AwsCredentials, targetEnv Env, serviceName, releaseTag string, dryRun bool) error {

	cfg, err := NewConfig(log, targetEnv, awsCredentials)
	if err != nil {
		return err
	}

	targetSvc, err := NewService(serviceName, cfg)
	if err != nil {
		return err
	}

	// Override the release tag if set.
	if releaseTag != "" {
		targetSvc.ReleaseTag = releaseTag
	}

	return devdeploy.DeployServiceToTargetEnv(log, cfg, targetSvc)
}

// ecsKeyValuePair returns an *ecs.KeyValuePair
func ecsKeyValuePair(name, value string) *ecs.KeyValuePair {
	return &ecs.KeyValuePair{
		Name:  aws.String(name),
		Value: aws.String(value),
	}
}
