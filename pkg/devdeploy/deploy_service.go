package devdeploy

import (
	"compress/gzip"
	"fmt"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
)

// DeployServiceToTargetEnv deploys a service to AWS ECS. The following steps will be executed for deployment:
// 1. Load the VPC for the project.
// 2. Load the security group.
// 3. AWS ECR repository
// 4. Find AWS Route 53 Zones for service hostnames.
// 5. Find service discovery for service.
// 6. Find Load Balancer if enabled.
// 7. Setup the AWS ECS Cluster for the service.
// 8. Register AWS ECS task definition.
// 9. Sync static files to AWS S3.
// 10. Check for an existing AWS ECS service and if it needs to be created, recreated, or updated.
// 11. Wait for AWS ECS service to enter a stable state.
func DeployServiceToTargetEnv(log *log.Logger, cfg *Config, targetService *ProjectService) error {

	log.Printf("Deploy service %s to environment %s\n", targetService.Name, cfg.Env)

	if targetService.BuildOnly {
		log.Printf("\t%s\tBuild only, nothing to deploy\n", Success)
		return nil
	}

	infra, err := NewInfrastructure(cfg)
	if err != nil {
		return err
	}

	startTime := time.Now()

	syncS3Chan := make(chan error, 1)

	go func() {
		// When static files are enabled to be to stored on S3, we need to upload all of them.
		syncS3Chan <- func() error {
			if targetService.StaticFilesDir != "" && targetService.StaticFilesS3Prefix != "" {
				log.Println("\tUpload static files to public S3 bucket")

				staticDir := targetService.StaticFilesDir

				if _, err := os.Stat(staticDir); err != nil {
					if !os.IsNotExist(err) {
						return errors.Wrapf(err, "Static directory '%s' does not exist.", staticDir)

					}
				} else {
					err := SyncPublicS3Files(infra.AwsSession(),
						cfg.AwsS3BucketPublic.BucketName,
						targetService.StaticFilesS3Prefix,
						staticDir)
					if err != nil {
						return errors.Wrapf(err, "Failed to sync static files from %s to s3://%s/%s",
							staticDir,
							cfg.AwsS3BucketPublic.BucketName,
							targetService.StaticFilesS3Prefix)
					}

					log.Printf("\t%s\tFiles uploaded to s3://%s/%s.\n", Success,
						cfg.AwsS3BucketPublic.BucketName,
						targetService.StaticFilesS3Prefix)
				}
			}
			return nil
		}()
	}()

	// Step 1: Find the vpc.
	var vpc *AwsEc2VpcResult
	{
		if cfg.AwsEc2Vpc.IsDefault {
			vpc, err = infra.GetAwsEc2DefaultVpc()
		} else if cfg.AwsEc2Vpc.VpcId != "" {
			vpc, err = infra.GetAwsEc2Vpc(cfg.AwsEc2Vpc.VpcId)
		} else {
			vpc, err = infra.GetAwsEc2Vpc(cfg.AwsEc2Vpc.CidrBlock)
		}
		if err != nil {
			return err
		}
	}

	// Step 2: Load the EC2 security group.
	securityGroup, err := infra.GetAwsEc2SecurityGroup(cfg.AwsEc2SecurityGroup.GroupName)
	if err != nil {
		return err
	}

	// Step 3: Find the AWS ECR repository.
	{
		log.Println("\tECR - Get repository")

		repo, err := infra.GetAwsEcrRepository(cfg.AwsEcrRepository.RepositoryName)
		if err != nil {
			return err
		}
		targetService.ReleaseImage = repo.RepositoryUri + ":" + targetService.ReleaseTag

		log.Printf("\t%s\tRelease image set to %s\n", Success, targetService.ReleaseImage)
	}

	// Step 4: Route 53 zone lookup when hostname is set. Supports both top level domains or sub domains.
	zones := make(map[string][]string)
	{
		lookupDomains := []string{}
		if targetService.ServiceHostPrimary != "" {
			lookupDomains = append(lookupDomains, targetService.ServiceHostPrimary)
		}
		for _, dn := range targetService.ServiceHostNames {
			if dn != targetService.ServiceHostPrimary {
				lookupDomains = append(lookupDomains, dn)
			}
		}

		for _, dn := range lookupDomains {
			zone, err := infra.GetRoute53ZoneByDomain(dn)
			if err != nil {
				return err
			}

			if _, ok := zones[zone.ZoneId]; !ok {
				zones[zone.ZoneId] = []string{}
			}

			for idx, adn := range zone.AssocDomains {
				if adn == dn {
					zones[zone.ZoneId] = append(zones[zone.ZoneId], zone.Entries[idx])
					break
				}
			}
		}
	}

	// Step 5: Find service discovery service.
	var sdService *AwsSdServiceResult
	if targetService.AwsSdPrivateDnsNamespace != nil && !cfg.AwsCredentials.IsGov() {
		sdNamespace, err := infra.GetAwsSdPrivateDnsNamespace(targetService.AwsSdPrivateDnsNamespace.Name)
		if err != nil {
			return err
		}

		// Ensure the service exists in the namespace.
		if targetService.AwsSdPrivateDnsNamespace.Service != nil {
			sdService, err = sdNamespace.GetService(targetService.AwsSdPrivateDnsNamespace.Service.Name)
			if err != nil {
				return err
			}
		}
	}

	// Step 6: Find an Elastic Load Balancer if enabled.
	var elb *AwsElbLoadBalancerResult
	if targetService.AwsElbLoadBalancer != nil {
		elb, err = infra.GetAwsElbLoadBalancer(targetService.AwsElbLoadBalancer.Name)
		if err != nil {
			return err
		}
	}

	// Step 7: Try to find AWS ECS Cluster by name or create new one.
	ecsCluster, err := infra.GetAwsEcsCluster(targetService.AwsEcsCluster.ClusterName)
	if err != nil {
		return err
	}

	// The execution role is the IAM role that executes ECS actions such as pulling the image and storing the
	// application logs in cloudwatch.
	var executionRoleArn string
	if targetService.AwsEcsExecutionRole != nil {
		role, err := infra.GetAwsIamRole(targetService.AwsEcsExecutionRole.RoleName)
		if err != nil {
			return err
		}

		// Update the task definition with the execution role ARN.
		log.Printf("\tAppend ExecutionRoleArn to task definition input for role %s.", role.RoleName)
		executionRoleArn = role.Arn
	}

	// The task role is the IAM role used by the task itself to access other AWS Services. To access services
	// like S3, SQS, etc then those permissions would need to be covered by the TaskRole.
	var taskRoleArn string
	if targetService.AwsEcsTaskRole != nil {
		role, err := infra.GetAwsIamRole(targetService.AwsEcsTaskRole.RoleName)
		if err != nil {
			return err
		}

		// Update the task definition with the task role ARN.
		log.Printf("\tAppend TaskRoleArn to task definition input for role %s.", role.RoleName)
		taskRoleArn = role.Arn
	}

	// Step 8: Register a new ECS task definition.
	var taskDef *AwsEcsTaskDefinitionResult
	{
		log.Println("\tECS - Register task definition")

		// Update the placeholders for the supplied task definition.
		var taskDefInput *ecs.RegisterTaskDefinitionInput
		{
			log.Println("\t\tFind and replace placeholders")

			vars := AwsEcsServiceDeployVariables{
				ProjectName:                  cfg.ProjectName,
				ServiceName:                  targetService.Name,
				ServiceBaseUrl:               "",
				PrimaryHostname:              targetService.ServiceHostPrimary,
				AlternativeHostnames:         targetService.ServiceHostNames,
				ReleaseImage:                 targetService.ReleaseImage,
				AwsRegion:                    cfg.AwsCredentials.Region,
				AwsLogGroupName:              targetService.AwsCloudWatchLogGroup.LogGroupName,
				AwsS3BucketNamePrivate:       cfg.AwsS3BucketPrivate.BucketName,
				AwsS3BucketNamePublic:        cfg.AwsS3BucketPublic.BucketName,
				AwsExecutionRoleArn:          executionRoleArn,
				AwsTaskRoleArn:               taskRoleArn,
				Env:                          cfg.Env,
				HTTPHost:                     "0.0.0.0:80",
				HTTPSHost:                    "",
				HTTPSEnabled:                 false,
				StaticFilesS3Enabled:         false,
				StaticFilesS3Prefix:          targetService.StaticFilesS3Prefix,
				StaticFilesCloudfrontEnabled: false,
				CacheHost:                    "",
				DbHost:                       "",
				DbUser:                       "",
				DbPass:                       "",
				DbName:                       "",
				DbDriver:                     "",
				DbDisableTLS:                 false,
				Route53Zones:                 zones,
				AwsEc2Vpc:                    vpc,
				AwsEc2SecurityGroup:          securityGroup,
				AwsSdService:                 sdService,
				AwsElbLoadBalancer:           elb,
				AwsEcsCluster:                ecsCluster,
				ProjectService:               targetService,
			}

			// For HTTPS support.
			if targetService.EnableHTTPS {
				vars.HTTPSEnabled = true

				// When there is no Elastic Load Balancer, we need to terminate HTTPS on the app.
				if elb == nil {
					vars.HTTPSHost = "0.0.0.0:443"
				}
			}

			// When a domain name if defined for the service, set the App Base URL. Default to HTTPS if enabled.
			if targetService.ServiceHostPrimary != "" {
				var appSchema string
				if targetService.EnableHTTPS {
					appSchema = "https"
				} else {
					appSchema = "http"
				}
				vars.ServiceBaseUrl = fmt.Sprintf("%s://%s/", appSchema, targetService.ServiceHostPrimary)
			}

			// Static files served from S3.
			if targetService.StaticFilesS3Prefix != "" {
				vars.StaticFilesS3Enabled = true
			}

			// Static files served from CloudFront.
			if cfg.AwsS3BucketPublic.CloudFront != nil {
				vars.StaticFilesCloudfrontEnabled = true
			}

			var dbConnInfo *DBConnInfo
			if cfg.AwsRdsDBCluster != nil {
				dbConnInfo, err = infra.GetDBConnInfo(cfg.AwsRdsDBCluster.DBClusterIdentifier)
				if err != nil {
					return err
				}
			} else if cfg.AwsRdsDBInstance != nil {
				dbConnInfo, err = infra.GetDBConnInfo(cfg.AwsRdsDBInstance.DBInstanceIdentifier)
				if err != nil {
					return err
				}
			} else {
				dbConnInfo = cfg.DBConnInfo
			}

			// When db is set, update the placeholders.
			if dbConnInfo != nil {
				vars.DbHost = dbConnInfo.Host
				vars.DbUser = dbConnInfo.User
				vars.DbPass = dbConnInfo.Pass
				vars.DbName = dbConnInfo.Database
				vars.DbDriver = dbConnInfo.Driver

				if dbConnInfo.DisableTLS {
					vars.DbDisableTLS = true
				}
			}

			// When cache cluster is set, set the host and port.
			if cfg.AwsElasticCacheCluster != nil {
				cacheCluster, err := infra.GetAwsElasticCacheCluster(cfg.AwsElasticCacheCluster.CacheClusterId)
				if err != nil {
					return err
				}

				var cacheHost string
				if cacheCluster.ConfigurationEndpoint != nil {
					// Works for memcache.
					cacheHost = fmt.Sprintf("%s:%d", cacheCluster.ConfigurationEndpoint.Address, cacheCluster.ConfigurationEndpoint.Port)
				} else if len(cacheCluster.CacheNodes) > 0 {
					// Works for redis.
					cacheHost = fmt.Sprintf("%s:%d", cacheCluster.CacheNodes[0].Endpoint.Address, cacheCluster.CacheNodes[0].Endpoint.Port)
				} else {
					return errors.New("Unable to determine cache host from cache cluster")
				}
				vars.CacheHost = cacheHost
			}

			// Get the task input and execute any defined PreRegister method.
			taskDefInput, err = targetService.AwsEcsTaskDefinition.Input(vars)
			if err != nil {
				return err
			}
		}

		// If a task definition value is empty, populate it with the default value.
		if taskDefInput.Family == nil || *taskDefInput.Family == "" {
			taskDefInput.Family = aws.String(targetService.Name)
		}
		if len(taskDefInput.ContainerDefinitions) > 0 {
			if taskDefInput.ContainerDefinitions[0].Name == nil || *taskDefInput.ContainerDefinitions[0].Name == "" {
				taskDefInput.ContainerDefinitions[0].Name = aws.String(targetService.Name)
			}
			if taskDefInput.ContainerDefinitions[0].Image == nil || *taskDefInput.ContainerDefinitions[0].Image == "" {
				taskDefInput.ContainerDefinitions[0].Image = aws.String(targetService.ReleaseImage)
			}
		}

		log.Printf("\t\t\tFamily: %s", *taskDefInput.Family)
		if taskDefInput.NetworkMode != nil {
			log.Printf("\t\t\tNetworkMode: %s", *taskDefInput.NetworkMode)
		}
		log.Printf("\t\t\tTask Definitions: %d", len(taskDefInput.ContainerDefinitions))

		// If memory or cpu for the task is not set, need to compute from container definitions.
		if (taskDefInput.Cpu == nil || *taskDefInput.Cpu == "") || (taskDefInput.Memory == nil || *taskDefInput.Memory == "") {
			log.Println("\t\tCompute CPU and Memory for task definition.")

			var (
				totalMemory int64
				totalCpu    int64
			)
			for _, c := range taskDefInput.ContainerDefinitions {
				if c.Memory != nil {
					totalMemory = totalMemory + *c.Memory
				} else if c.MemoryReservation != nil {
					totalMemory = totalMemory + *c.MemoryReservation
				} else {
					totalMemory = totalMemory + 1
				}
				if c.Cpu != nil {
					totalCpu = totalCpu + *c.Cpu
				} else {
					totalCpu = totalCpu + 1
				}
			}

			log.Printf("\t\t\tContainer Definitions has defined total memory %d and cpu %d", totalMemory, totalCpu)

			// The selected memory and CPU for ECS Fargate is determined by the made available by AWS.
			// For more information, reference the section "Task and CPU Memory" on this page:
			//	https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html
			//
			// If your service deployment encounters the ECS error: Invalid CPU or Memory Value Specified
			// reference this page and the values below may need to be updated accordingly.
			//	https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
			var (
				selectedMemory int64
				selectedCpu    int64
			)
			if totalMemory < 8192 {
				if totalMemory > 7168 {
					selectedMemory = 8192

					if totalCpu >= 2048 {
						selectedCpu = 4096
					} else if totalCpu >= 1024 {
						selectedCpu = 2048
					} else {
						selectedCpu = 1024
					}
				} else if totalMemory > 6144 {
					selectedMemory = 7168

					if totalCpu >= 2048 {
						selectedCpu = 4096
					} else if totalCpu >= 1024 {
						selectedCpu = 2048
					} else {
						selectedCpu = 1024
					}
				} else if totalMemory > 5120 || totalCpu >= 1024 {
					selectedMemory = 6144

					if totalCpu >= 2048 {
						selectedCpu = 4096
					} else if totalCpu >= 1024 {
						selectedCpu = 2048
					} else {
						selectedCpu = 1024
					}
				} else if totalMemory > 4096 {
					selectedMemory = 5120

					if totalCpu >= 512 {
						selectedCpu = 1024
					} else {
						selectedCpu = 512
					}
				} else if totalMemory > 3072 {
					selectedMemory = 4096

					if totalCpu >= 512 {
						selectedCpu = 1024
					} else {
						selectedCpu = 512
					}
				} else if totalMemory > 2048 || totalCpu >= 512 {
					selectedMemory = 3072

					if totalCpu >= 512 {
						selectedCpu = 1024
					} else {
						selectedCpu = 512
					}
				} else if totalMemory > 1024 || totalCpu >= 256 {
					selectedMemory = 2048

					if totalCpu >= 256 {
						if totalCpu >= 512 {
							selectedCpu = 1024
						} else {
							selectedCpu = 512
						}
					} else {
						selectedCpu = 256
					}
				} else if totalMemory > 512 {
					selectedMemory = 1024

					if totalCpu >= 256 {
						selectedCpu = 512
					} else {
						selectedCpu = 256
					}
				} else {
					selectedMemory = 512
					selectedCpu = 256
				}
			}
			log.Printf("\t\t\tSelected memory %d and cpu %d", selectedMemory, selectedCpu)
			taskDefInput.Memory = aws.String(strconv.Itoa(int(selectedMemory)))
			taskDefInput.Cpu = aws.String(strconv.Itoa(int(selectedCpu)))
		}
		log.Printf("\t%s\tLoaded task definition complete.\n", Success)

		// The execution role is the IAM role that executes ECS actions such as pulling the image and storing the
		// application logs in cloudwatch.
		if (taskDefInput.ExecutionRoleArn == nil || *taskDefInput.ExecutionRoleArn == "") && executionRoleArn != "" {
			// Update the task definition with the execution role ARN.
			log.Printf("\tAppend ExecutionRoleArn to task definition input for role %s.", executionRoleArn)
			taskDefInput.ExecutionRoleArn = aws.String(executionRoleArn)
		}

		// The task role is the IAM role used by the task itself to access other AWS Services. To access services
		// like S3, SQS, etc then those permissions would need to be covered by the TaskRole.
		if (taskDefInput.TaskRoleArn == nil || *taskDefInput.TaskRoleArn == "") && taskRoleArn != "" {
			// Update the task definition with the task role ARN.
			log.Printf("\tAppend TaskRoleArn to task definition input for role %s.", taskRoleArn)
			taskDefInput.TaskRoleArn = aws.String(taskRoleArn)
		}

		log.Println("\tRegister new task definition.")
		{
			inputHash := getInputHash(taskDefInput)

			svc := ecs.New(infra.AwsSession())

			// Registers a new task.
			res, err := svc.RegisterTaskDefinition(taskDefInput)
			if err != nil {
				return errors.Wrapf(err, "Failed to register task definition '%s'", *taskDefInput.Family)
			}
			taskDef = &AwsEcsTaskDefinitionResult{
				TaskDefinition: res.TaskDefinition,
				InputHash:      inputHash,
			}

			log.Printf("\t\tRegistered: %s.", *taskDef.TaskDefinitionArn)
			log.Printf("\t\t\tRevision: %d.", *taskDef.Revision)
			log.Printf("\t\t\tStatus: %s.", *taskDef.Status)

			log.Printf("\t%s\tTask definition registered.\n", Success)
		}
	}

	// Step 9: Wait for the goroutine to finish syncing files to s3
	if err := <-syncS3Chan; err != nil {
		return err
	}

	// Step 10: Find the existing ECS service and check if it needs to be recreated
	ecsService, err := infra.setupAwsEcsService(log, ecsCluster, targetService.AwsEcsService, taskDef, vpc, securityGroup, sdService, elb)
	if err != nil {
		return err
	}

	if targetService.AwsAppAutoscalingPolicy != nil {
		log.Println("\tConfigure application autoscaling policy.")

		svc := applicationautoscaling.New(infra.AwsSession())

		targetInput, err := targetService.AwsAppAutoscalingPolicy.RegisterTargetInput()
		if err != nil {
			return err
		}

		// The identifier of the resource associated with the scaling policy. This string
		// consists of the resource type and unique identifier.
		//    * ECS service - The resource type is service and the unique identifier
		//    is the cluster name and service name. Example: service/default/sample-webapp.
		targetInput.ResourceId = aws.String(filepath.Join("service", ecsCluster.ClusterName, ecsService.ServiceName))

		// The scalable dimension. This string consists of the service namespace, resource
		// type, and scaling property.
		//    * ecs:service:DesiredCount - The desired task count of an ECS service.
		targetInput.ScalableDimension = aws.String("ecs:service:DesiredCount")

		// The namespace of the AWS service that provides the resource or custom-resource
		// for a resource provided by your own application or service. For more information,
		// see AWS Service Namespaces (http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces)
		// in the Amazon Web Services General Reference.
		targetInput.ServiceNamespace = aws.String("ecs")

		targetRes, err := svc.RegisterScalableTarget(targetInput)
		if err != nil {
			return errors.Wrapf(err, "Failed to register scalable target '%s'", *targetInput.ResourceId)
		}
		log.Printf("\t\tRegistered target %s: %s", *targetInput.ResourceId, targetRes.String())

		policyInput, err := targetService.AwsAppAutoscalingPolicy.PutInput()
		if err != nil {
			return err
		}
		policyInput.ResourceId = targetInput.ResourceId
		policyInput.ScalableDimension = targetInput.ScalableDimension
		policyInput.ServiceNamespace = targetInput.ServiceNamespace

		// PredefinedMetricType is ALBRequestCountPerTarget and ResourceLabel is empty, set the associated value.
		if elb != nil && policyInput.TargetTrackingScalingPolicyConfiguration != nil &&
			policyInput.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification != nil &&
			policyInput.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.PredefinedMetricType != nil &&
			*policyInput.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.PredefinedMetricType == "ALBRequestCountPerTarget" {

			if policyInput.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.ResourceLabel == nil || *policyInput.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.ResourceLabel == "" {

				// Identifies the resource associated with the metric type. You can't specify
				// a resource label unless the metric type is ALBRequestCountPerTarget and there
				// is a target group attached to the Spot Fleet request or ECS service.
				//
				// The format is app/<load-balancer-name>/<load-balancer-id>/targetgroup/<target-group-name>/<target-group-id>,
				// where:
				//
				//    * app/<load-balancer-name>/<load-balancer-id> is the final portion of
				//    the load balancer ARN
				//
				//    * targetgroup/<target-group-name>/<target-group-id> is the final portion
				//    of the target group ARN.
				resourceLabel := filepath.Join(
					// arn:aws:elasticloadbalancing:us-west-2:3333333333:loadbalancer/app/prod-aws-ecs-go-web-api/582fb8014672363c
					strings.Split(elb.LoadBalancerArn, ":loadbalancer/")[1],

					// arn:aws:elasticloadbalancing:us-west-2:3333333333:targetgroup/aws-ecs-go-web-api-http/c36d550933467b14
					"targetgroup", strings.Split(elb.TargetGroups[0].TargetGroupArn, ":targetgroup/")[1])

				policyInput.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.ResourceLabel = aws.String(resourceLabel)

				log.Printf("\t\tSet resource labe to '%s' for ALBRequestCountPerTarget", resourceLabel)
			}
		}

		policyRes, err := svc.PutScalingPolicy(policyInput)
		if err != nil {
			return errors.Wrapf(err, "Failed to put scaling policy '%s'", targetService.AwsAppAutoscalingPolicy.PolicyName)
		}
		log.Printf("\t\tPut scaling policy %s: %s", *policyInput.ResourceId, policyRes.String())
	}

	// Step 11: Wait for the updated or created service to enter a stable state.
	{
		log.Println("\tWaiting for service to enter stable state.")

		// Helper method to get the logs from cloudwatch for a specific task ID.
		getTaskLogs := func(taskId string) ([]string, error) {
			if cfg.AwsS3BucketPrivate == nil || cfg.AwsS3BucketPrivate.BucketName == "" ||
				targetService.AwsCloudWatchLogGroup == nil || targetService.AwsCloudWatchLogGroup.LogGroupName == "" {
				// No private S3 bucket defined so unable to export logs streams.
				return []string{}, nil
			}

			privateBucket := cfg.AwsS3BucketPrivate
			logGroupName := targetService.AwsCloudWatchLogGroup.LogGroupName

			// Stream name generated by ECS for the awslogs driver.
			logStreamName := fmt.Sprintf("ecs/%s/%s", ecsService.ServiceName, taskId)

			// Define S3 key prefix used to export the stream logs to.
			s3KeyPrefix := filepath.Join(
				privateBucket.TempPrefix,
				"logs/cloudwatchlogs/exports",
				logGroupName)

			var downloadPrefix string
			{
				svc := cloudwatchlogs.New(infra.AwsSession())

				createRes, err := svc.CreateExportTask(&cloudwatchlogs.CreateExportTaskInput{
					LogGroupName:        aws.String(logGroupName),
					LogStreamNamePrefix: aws.String(logStreamName),
					//TaskName: aws.String(taskId),
					Destination:       aws.String(privateBucket.BucketName),
					DestinationPrefix: aws.String(s3KeyPrefix),
					From:              aws.Int64(startTime.UTC().AddDate(0, 0, -1).UnixNano() / int64(time.Millisecond)),
					To:                aws.Int64(time.Now().UTC().AddDate(0, 0, 1).UnixNano() / int64(time.Millisecond)),
				})
				if err != nil {
					return []string{}, errors.Wrapf(err, "Failed to create export task for from log group '%s' with stream name prefix '%s'", logGroupName, logStreamName)
				}
				exportTaskId := *createRes.TaskId

				for {
					descRes, err := svc.DescribeExportTasks(&cloudwatchlogs.DescribeExportTasksInput{
						TaskId: aws.String(exportTaskId),
					})
					if err != nil {
						return []string{}, errors.Wrapf(err, "Failed to describe export task '%s' for from log group '%s' with stream name prefix '%s'", exportTaskId, logGroupName, logStreamName)
					}
					taskStatus := *descRes.ExportTasks[0].Status.Code

					if taskStatus == "COMPLETED" {
						downloadPrefix = filepath.Join(s3KeyPrefix, exportTaskId) + "/"
						break
					} else if taskStatus == "CANCELLED" || taskStatus == "FAILED" {
						break
					}
					time.Sleep(time.Second * 5)
				}
			}

			// If downloadPrefix is set, then get logs from corresponding file for service.
			var logLines []string
			if downloadPrefix != "" {
				svc := s3.New(infra.AwsSession())

				var s3Keys []string
				err := svc.ListObjectsPages(&s3.ListObjectsInput{
					Bucket: aws.String(privateBucket.BucketName),
					Prefix: aws.String(downloadPrefix),
				},
					func(res *s3.ListObjectsOutput, lastPage bool) bool {
						for _, obj := range res.Contents {
							s3Keys = append(s3Keys, *obj.Key)
						}
						return !lastPage
					})
				if err != nil {
					return []string{}, errors.Wrapf(err, "Failed to list objects from s3 bucket '%s' with prefix '%s'", privateBucket.BucketName, downloadPrefix)
				}

				// Iterate trough S3 keys and get logs from file.
				for _, s3Key := range s3Keys {
					res, err := svc.GetObject(&s3.GetObjectInput{
						Bucket: aws.String(privateBucket.BucketName),
						Key:    aws.String(s3Key),
					})
					if err != nil {
						return []string{}, errors.Wrapf(err, "Failed to get s3 object 's3://%s%s'", privateBucket.BucketName, s3Key)
					}
					r, _ := gzip.NewReader(res.Body)
					dat, err := ioutil.ReadAll(r)
					res.Body.Close()
					if err != nil {
						return []string{}, errors.Wrapf(err, "Failed to read s3 object 's3://%s%s'", privateBucket.BucketName, s3Key)
					}

					// Iterate through file by line break and add each line to array of logs.
					for _, l := range strings.Split(string(dat), "\n") {
						l = strings.TrimSpace(l)
						if l == "" {
							continue
						}
						logLines = append(logLines, l)
					}
				}
			}

			return logLines, nil
		}

		// Helper method to display tasks errors that failed to start while we wait for the service to stable state.
		taskLogLines := make(map[string][]string)
		checkTasks := func() (bool, error) {
			svc := ecs.New(infra.AwsSession())

			clusterName := targetService.AwsEcsCluster.ClusterName
			serviceName := targetService.AwsEcsService.ServiceName

			serviceTaskRes, err := svc.ListTasks(&ecs.ListTasksInput{
				Cluster:       aws.String(clusterName),
				ServiceName:   aws.String(serviceName),
				DesiredStatus: aws.String("STOPPED"),
			})
			if err != nil {
				return false, errors.Wrapf(err,
					"Failed to list tasks for cluster '%s' service '%s'",
					clusterName,
					serviceName)
			}

			if len(serviceTaskRes.TaskArns) == 0 {
				return false, nil
			}

			taskRes, err := svc.DescribeTasks(&ecs.DescribeTasksInput{
				Cluster: aws.String(clusterName),
				Tasks:   serviceTaskRes.TaskArns,
			})
			if err != nil {
				return false, errors.Wrapf(err, "Failed to describe %d tasks for cluster '%s'", len(serviceTaskRes.TaskArns), clusterName)
			}

			var failures []*ecs.Failure
			var stoppedCnt int64
			for _, t := range taskRes.Tasks {
				if *t.TaskDefinitionArn != *taskDef.TaskDefinitionArn || t.TaskArn == nil {
					continue
				}
				stoppedCnt = stoppedCnt + 1

				taskId := filepath.Base(*t.TaskArn)

				log.Printf("\t\t\tTask %s stopped\n", *t.TaskArn)
				for _, tc := range t.Containers {
					if tc.ExitCode != nil && tc.Reason != nil {
						log.Printf("\t\t\tContainer %s exited with %d - %s.\n", *tc.Name, *tc.ExitCode, *tc.Reason)
					} else if tc.ExitCode != nil {
						log.Printf("\t\t\tContainer %s exited with %d.\n", *tc.Name, *tc.ExitCode)
					} else {
						log.Printf("\t\t\tContainer %s exited.\n", *tc.Name)
					}
				}

				// Avoid exporting the logs multiple times.
				logLines, ok := taskLogLines[taskId]
				if !ok {
					logLines, err = getTaskLogs(taskId)
					if err != nil {
						return false, errors.Wrapf(err, "Failed to get logs for task %s for cluster '%s'", *t.TaskArn, clusterName)
					}
					taskLogLines[taskId] = logLines
				}

				if len(logLines) > 0 {
					log.Printf("\t\t\tTask Logs:\n")
					for _, l := range logLines {
						log.Printf("\t\t\t\t%s\n", l)
					}
				}

				if t.StopCode != nil && t.StoppedReason != nil {
					log.Printf("\t%s\tTask %s stopped with %s - %s.\n", Failed, *t.TaskArn, *t.StopCode, *t.StoppedReason)
				} else if t.StopCode != nil {
					log.Printf("\t%s\tTask %s stopped with %s.\n", Failed, *t.TaskArn, *t.StopCode)
				} else {
					log.Printf("\t%s\tTask %s stopped.\n", Failed, *t.TaskArn)
				}

				// Limit failures to only the current task definition.
				for _, f := range taskRes.Failures {
					if *f.Arn == *t.TaskArn {
						failures = append(failures, f)
					}
				}
			}

			if len(failures) > 0 {
				for _, t := range failures {
					log.Printf("\t%s\tTask %s failed with %s.\n", Failed, *t.Arn, *t.Reason)
				}
			}

			// If the number of stopped tasks with the current task def match the desired count for the service,
			// then we no longer need to continue to check the status of the tasks.
			if stoppedCnt == ecsService.DesiredCount {
				return true, nil
			}

			return false, nil
		}

		// New wait group with only a count of one, this will allow the first go worker to exit to cancel both.
		checkErr := make(chan error, 1)

		// Check the status of the service tasks and print out info for debugging.
		ticker := time.NewTicker(10 * time.Second)
		go func() {
			for {
				select {
				case <-ticker.C:
					stop, err := checkTasks()
					if err != nil {
						log.Printf("\t%s\tFailed to check tasks.\n%+v\n", Failed, err)
					}

					if stop {
						checkErr <- errors.New("All tasks for service are stopped")
						return
					}
				}
			}
		}()

		// Use the AWS ECS method to check for the service to be stable.
		go func() {
			svc := ecs.New(infra.AwsSession())
			err := svc.WaitUntilServicesStable(&ecs.DescribeServicesInput{
				Cluster:  aws.String(ecsCluster.ClusterArn),
				Services: aws.StringSlice([]string{ecsService.ServiceArn}),
			})
			if err != nil {
				checkErr <- errors.Wrapf(err, "Failed to wait for service '%s' to enter stable state", ecsService.ServiceName)
			} else {
				// All done.
				checkErr <- nil
			}
		}()

		if err := <-checkErr; err != nil {
			log.Printf("\t%s\tFailed to check tasks.\n%+v\n", Failed, err)
			return err
		}

		// Wait for one of the methods to finish and then ensure the ticker is stopped.
		ticker.Stop()

		log.Printf("\t%s\tService running.\n", Success)
	}

	return nil
}

// FindServiceDockerFile finds the service directory.
func FindServiceDockerFile(projectRoot, targetService string) (string, error) {
	checkDirs := []string{
		filepath.Join(projectRoot, "cmd", targetService),
		filepath.Join(projectRoot, "tools", targetService),
	}

	var dockerFile string
	for _, cd := range checkDirs {
		// Check to see if directory contains Dockerfile.
		tf := filepath.Join(cd, "Dockerfile")

		ok, _ := exists(tf)
		if ok {
			dockerFile = tf
			break
		}
	}

	if dockerFile == "" {
		return "", errors.Errorf("failed to locate Dockerfile for service %s", targetService)
	}

	return dockerFile, nil
}
