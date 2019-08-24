package devdeploy

import (
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/pkg/errors"
	"gitlab.com/geeks-accelerator/oss/devops/internal/retry"
	"gopkg.in/go-playground/validator.v9"
)

// DeployService defines the detailed needed to deploy a service to AWS ECS as a Fargate task.
type DeployService struct {
	//DeploymentEnv *DeploymentEnv `validate:"required,dive,required"`

	ServiceName string `validate:"required" example:"web-api"`

	EnableHTTPS        bool     `validate:"omitempty"`
	ServiceHostPrimary string   `validate:"omitempty,required_with=EnableHTTPS,fqdn"`
	ServiceHostNames   []string `validate:"omitempty,dive,fqdn"`

	Dockerfile string `validate:"required" example:"./cmd/web-api/Dockerfile"`

	ReleaseTag string `validate:"required"`

	StaticFilesDir      string `validate:"omitempty" example:"./cmd/web-api"`
	StaticFilesS3Prefix string `validate:"omitempty"`

	// AwsEcsCluster defines the name of the ecs cluster and the details needed to create doesn't exist.
	AwsEcsCluster *AwsEcsCluster `validate:"required"`

	// AwsEcsService defines the name of the ecs service and the details needed to create doesn't exist.
	AwsEcsService *AwsEcsService `validate:"required"`

	// AwsEcsTaskDefinition defines the task definition.
	AwsEcsTaskDefinition *AwsEcsTaskDefinition `validate:"required"`

	// AwsEcsExecutionRole defines the name of the iam execution role for ecs task and the detailed needed to create doesn't exist.
	// This role executes ECS actions such as pulling the image and storing the application logs in cloudwatch.
	AwsEcsExecutionRole *AwsIamRole `validate:"required"`

	// AwsEcsExecutionRole defines the name of the iam task role for ecs task and the detailed needed to create doesn't exist.
	// This role is used by the task itself for calling other AWS services.
	AwsEcsTaskRole *AwsIamRole `validate:"required"`

	// AwsCloudWatchLogGroup defines the name of the cloudwatch log group that will be used to store logs for the ECS
	// task.
	AwsCloudWatchLogGroup *AwsCloudWatchLogGroup `validate:"required"`

	// AwsElbLoadBalancer defines if the service should use an elastic load balancer.
	AwsElbLoadBalancer *AwsElbLoadBalancer `validate:"omitempty"`

	// AwsSdPrivateDnsNamespace defines the name of the service discovery group and the details needed to create if
	// it does not exist.
	AwsSdPrivateDnsNamespace *AwsSdPrivateDnsNamespace `validate:"omitempty"`

	ReleaseImage string `validate:"omitempty"`
}

// DeployServiceToTargetEnv deploys a service to AWS ECS. The following steps will be executed for deployment:
// 1. AWS ECR repository
// 2. Find AWS Route 53 Zones for service hostnames.
// 3. Setup service discovery for service.
// 4. Ensure the Cloudwatch Log group exists.
// 5. Setup the AWS Elastic Load Balancer if enabled.
// 6. Setup the AWS ECS Cluster for the service.
// 7. Register AWS ECS task definition.
// 8. Check for an existing AWS ECS service and if it needs to be recreated.
// 9. Create or update the AWS ECS service.
// 10. Sync static files to AWS S3.
// 11. Wait for AWS ECS service to enter a stable state.
func DeployServiceToTargetEnv(log *log.Logger, cfg *Config, targetService *DeployService) error {

	err := SetupDeploymentEnv(log, cfg)
	if err != nil {
		return err
	}

	log.Printf("Deploy service %s to environment %s\n", targetService.ServiceName, cfg.Env)

	r, err := regexp.Compile(`^(\d+)`)
	if err != nil {
		return errors.WithStack(err)
	}

	// Workaround for domains that start with a numeric value like 8north.com
	// Validation fails with error: failed on the 'fqdn' tag
	origServiceHostPrimary := targetService.ServiceHostPrimary
	matches := r.FindAllString(targetService.ServiceHostPrimary, -1)
	if len(matches) > 0 {
		for _, m := range matches {
			targetService.ServiceHostPrimary = strings.Replace(targetService.ServiceHostPrimary, m, "X", -1)
		}
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetService)
	if errs != nil {
		return errs
	}

	targetService.ServiceHostPrimary = origServiceHostPrimary

	startTime := time.Now()

	vpcId := cfg.AwsEc2Vpc.VpcId
	subnetIds := cfg.AwsEc2Vpc.subnetIds
	securityGroupIds := []string{*cfg.AwsEc2SecurityGroup.result.GroupId}

	// Step 1: Find the AWS ECR repository.
	{
		log.Println("\tECR - Get repository")

		repository, err := setupAwsEcrRepository(log, cfg, cfg.AwsEcrRepository)
		if err != nil {
			return err
		}
		cfg.AwsEcrRepository.result = repository

		targetService.ReleaseImage = *cfg.AwsEcrRepository.result.RepositoryUri + ":" + targetService.ReleaseTag

		log.Printf("\t%s\tECR Respository available\n", Success)
	}

	// Step 2: Route 53 zone lookup when hostname is set. Supports both top level domains or sub domains.
	var zoneArecNames = map[string][]string{}
	if targetService.ServiceHostPrimary != "" {
		log.Println("\tRoute 53 - Get or create hosted zones.")

		svc := route53.New(cfg.AwsSession())

		log.Println("\t\tList all hosted zones.")
		var zones []*route53.HostedZone
		err := svc.ListHostedZonesPages(&route53.ListHostedZonesInput{},
			func(res *route53.ListHostedZonesOutput, lastPage bool) bool {
				for _, z := range res.HostedZones {
					zones = append(zones, z)
				}
				return !lastPage
			})
		if err != nil {
			return errors.Wrap(err, "Failed list route 53 hosted zones")
		}

		// Generate a slice with the primary domain name and include all the alternative domain names.
		lookupDomains := []string{}
		if targetService.ServiceHostPrimary != "" {
			lookupDomains = append(lookupDomains, targetService.ServiceHostPrimary)
		}
		for _, dn := range targetService.ServiceHostNames {
			if dn != targetService.ServiceHostPrimary {
				lookupDomains = append(lookupDomains, dn)
			}
		}

		// Loop through all the defined domain names and find the associated zone even when they are a sub domain.
		for _, dn := range lookupDomains {
			log.Printf("\t\t\tFind zone for domain '%s'", dn)

			// Get the top level domain from url.
			zoneName := domainutil.Domain(dn)
			var subdomain string
			if zoneName == "" {
				// Handle domain names that have weird TDL: ie .tech
				zoneName = dn
				log.Printf("\t\t\t\tNon-standard Level Domain: '%s'", zoneName)
			} else {
				log.Printf("\t\t\t\tTop Level Domain: '%s'", zoneName)

				// Check if url has subdomain.
				if domainutil.HasSubdomain(dn) {
					subdomain = domainutil.Subdomain(dn)
					log.Printf("\t\t\t\tsubdomain: '%s'", subdomain)
				}
			}

			// Start at the top level domain and try to find a hosted zone. Search until a match is found or there are
			// no more domain levels to search for.
			var zoneId string
			for {
				log.Printf("\t\t\t\tChecking zone '%s' for associated hosted zone.", zoneName)

				// Loop over each one of hosted zones and try to find match.
				for _, z := range zones {
					zn := strings.TrimRight(*z.Name, ".")

					log.Printf("\t\t\t\t\tChecking if '%s' matches '%s'", zn, zoneName)
					if zn == zoneName {
						zoneId = *z.Id
						break
					}
				}

				if zoneId != "" || zoneName == dn {
					// Found a matching zone or have to search all possibilities!
					break
				}

				// If we have not found a hosted zone, append the next level from the domain to the zone.
				pts := strings.Split(subdomain, ".")
				subs := []string{}
				for idx, sn := range pts {
					if idx == len(pts)-1 {
						zoneName = sn + "." + zoneName
					} else {
						subs = append(subs, sn)
					}
				}
				subdomain = strings.Join(subs, ".")
			}

			var aName string
			if zoneId == "" {

				// Get the top level domain from url again.
				zoneName := domainutil.Domain(dn)
				if zoneName == "" {
					// Handle domain names that have weird TDL: ie .tech
					zoneName = dn
				}

				log.Printf("\t\t\t\tNo hosted zone found for '%s', create '%s'.", dn, zoneName)
				createRes, err := svc.CreateHostedZone(&route53.CreateHostedZoneInput{
					Name: aws.String(zoneName),
					HostedZoneConfig: &route53.HostedZoneConfig{
						Comment: aws.String(fmt.Sprintf("Public hosted zone created by saas-starter-kit.")),
					},

					// A unique string that identifies the request and that allows failed CreateHostedZone
					// requests to be retried without the risk of executing the operation twice.
					// You must use a unique CallerReference string every time you submit a CreateHostedZone
					// request. CallerReference can be any unique string, for example, a date/time
					// stamp.
					//
					// CallerReference is a required field
					CallerReference: aws.String(fmt.Sprintf("devops-deploy-%s-%d", zoneName, time.Now().Unix())),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to create route 53 hosted zone '%s' for domain '%s'", zoneName, dn)
				}
				zoneId = *createRes.HostedZone.Id

				log.Printf("\t\t\t\tCreated hosted zone '%s'", zoneId)

				// The fully qualified A record name.
				aName = dn
			} else {
				log.Printf("\t\t\t\tFound hosted zone '%s'", zoneId)

				// The fully qualified A record name.
				if subdomain != "" {
					aName = subdomain + "." + zoneName
				} else {
					aName = zoneName
				}
			}

			// Add the A record to be maintained for the zone.
			if _, ok := zoneArecNames[zoneId]; !ok {
				zoneArecNames[zoneId] = []string{}
			}
			zoneArecNames[zoneId] = append(zoneArecNames[zoneId], aName)

			log.Printf("\t%s\tZone '%s' found with A record name '%s'.\n", Success, zoneId, aName)
		}
	}

	// Step 3: Setup service discovery.
	var sdService *AwsSdService
	if targetService.AwsSdPrivateDnsNamespace != nil {
		log.Println("\tService Discovery - Get or Create Namespace")

		svc := servicediscovery.New(cfg.AwsSession())

		namespaceName := targetService.AwsSdPrivateDnsNamespace.Name

		log.Println("\t\tList all the private namespaces and try to find an existing entry.")

		listNamespaces := func() (*servicediscovery.NamespaceSummary, error) {
			var found *servicediscovery.NamespaceSummary
			err := svc.ListNamespacesPages(&servicediscovery.ListNamespacesInput{
				Filters: []*servicediscovery.NamespaceFilter{
					&servicediscovery.NamespaceFilter{
						Name:      aws.String("TYPE"),
						Condition: aws.String("EQ"),
						Values:    aws.StringSlice([]string{"DNS_PRIVATE"}),
					},
				},
			}, func(res *servicediscovery.ListNamespacesOutput, lastPage bool) bool {
				for _, n := range res.Namespaces {
					if *n.Name == namespaceName {
						found = n
						return false
					}
				}
				return !lastPage
			})
			if err != nil {
				return nil, errors.Wrap(err, "Failed to list namespaces")
			}

			return found, nil
		}

		sdNamespace, err := listNamespaces()
		if err != nil {
			return err
		}

		if sdNamespace == nil {
			input, err := targetService.AwsSdPrivateDnsNamespace.Input(vpcId)
			if err != nil {
				return err
			}

			log.Println("\t\tCreate private namespace.")

			// If no namespace was found, create one.
			createRes, err := svc.CreatePrivateDnsNamespace(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create namespace '%s'", namespaceName)
			}
			operationId := createRes.OperationId

			log.Println("\t\tWait for create operation to finish.")
			retryFunc := func() (bool, error) {
				opRes, err := svc.GetOperation(&servicediscovery.GetOperationInput{
					OperationId: operationId,
				})
				if err != nil {
					return true, err
				}

				log.Printf("\t\t\tStatus: %s.", *opRes.Operation.Status)

				// The status of the operation. Values include the following:
				//    * SUBMITTED: This is the initial state immediately after you submit a
				//    request.
				//    * PENDING: AWS Cloud Map is performing the operation.
				//    * SUCCESS: The operation succeeded.
				//    * FAIL: The operation failed. For the failure reason, see ErrorMessage.
				if *opRes.Operation.Status == "SUCCESS" {
					return true, nil
				} else if *opRes.Operation.Status == "FAIL" {
					err = errors.Errorf("Operation failed")
					err = awserr.New(*opRes.Operation.ErrorCode, *opRes.Operation.ErrorMessage, err)
					return true, err
				}

				return false, nil
			}
			err = retry.Retry(context.Background(), nil, retryFunc)
			if err != nil {
				return errors.Wrapf(err, "Failed to get operation for namespace '%s'", namespaceName)
			}

			// Now that the create operation is complete, try to find the namespace again.
			sdNamespace, err = listNamespaces()
			if err != nil {
				return err
			}

			log.Printf("\t\tCreated: %s.", *sdNamespace.Arn)
		} else {
			log.Printf("\t\tFound: %s.", *sdNamespace.Arn)

			// The number of services that are associated with the namespace.
			if sdNamespace.ServiceCount != nil {
				log.Printf("\t\t\tServiceCount: %d.", *sdNamespace.ServiceCount)
			}
		}
		targetService.AwsSdPrivateDnsNamespace.result = sdNamespace
		log.Printf("\t%s\tService Discovery Namespace setup\n", Success)

		// Ensure the service exists in the namespace.
		if targetService.AwsSdPrivateDnsNamespace.Service != nil {
			sdService = targetService.AwsSdPrivateDnsNamespace.Service

			// Try to find an existing entry for the current service.
			err = svc.ListServicesPages(&servicediscovery.ListServicesInput{
				Filters: []*servicediscovery.ServiceFilter{
					&servicediscovery.ServiceFilter{
						Name:      aws.String("NAMESPACE_ID"),
						Condition: aws.String("EQ"),
						Values:    aws.StringSlice([]string{*sdNamespace.Id}),
					},
				},
			}, func(res *servicediscovery.ListServicesOutput, lastPage bool) bool {
				for _, n := range res.Services {
					if *n.Name == sdService.Name {
						sdService.resultArn = *n.Arn
						return false
					}
				}
				return !lastPage
			})
			if err != nil {
				return errors.Wrapf(err, "failed to list services for namespace '%s'", *sdNamespace.Id)
			}

			if sdService.resultArn == "" {
				input, err := sdService.Input(*sdNamespace.Id)
				if err != nil {
					return err
				}

				// If no namespace was found, create one.
				createRes, err := svc.CreateService(input)
				if err != nil {
					return errors.Wrapf(err, "failed to create service '%s'", sdService.Name)
				}
				sdService.resultArn = *createRes.Service.Arn

				log.Printf("\t\tCreated: %s.", sdService.resultArn)
			} else {
				log.Printf("\t\tFound: %s.", sdService.resultArn)
			}

			log.Printf("\t%s\tService Discovery Service setup\n", Success)
		}
	}

	// Step 4: Try to find the AWS Cloudwatch Log Group by name or create new one.
	{
		log.Println("\tCloudWatch Logs - Get or Create Log Group")

		svc := cloudwatchlogs.New(cfg.AwsSession())

		logGroupName := targetService.AwsCloudWatchLogGroup.LogGroupName

		input, err := targetService.AwsCloudWatchLogGroup.Input()
		if err != nil {
			return err
		}

		// If no log group was found, create one.
		_, err = svc.CreateLogGroup(input)
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != cloudwatchlogs.ErrCodeResourceAlreadyExistsException {
				return errors.Wrapf(err, "Failed to create log group '%s'", logGroupName)
			}

			log.Printf("\t\tFound: %s", logGroupName)
		} else {
			log.Printf("\t\tCreated: %s", logGroupName)
		}

		log.Printf("\t%s\tLog Group setup\n", Success)
	}

	// Step 5: If an Elastic Load Balancer is enabled, then ensure one exists else create one.
	var ecsELBs []*ecs.LoadBalancer
	if targetService.AwsElbLoadBalancer != nil {

		// If HTTPS enabled on ELB, then need to find ARN certificates first.
		var certificateArn string
		if targetService.EnableHTTPS {
			log.Println("\tACM - Find Elastic Load Balancer")

			svc := acm.New(cfg.AwsSession())

			err := svc.ListCertificatesPages(&acm.ListCertificatesInput{},
				func(res *acm.ListCertificatesOutput, lastPage bool) bool {
					for _, cert := range res.CertificateSummaryList {
						if *cert.DomainName == targetService.ServiceHostPrimary {
							certificateArn = *cert.CertificateArn
							return false
						}
					}
					return !lastPage
				})
			if err != nil {
				return errors.Wrapf(err, "Failed to list certificates for '%s'", targetService.ServiceHostPrimary)
			}

			if certificateArn == "" {
				// Create hash of all the domain names to be used to mark unique requests.
				idempotencyToken := targetService.ServiceHostPrimary + "|" + strings.Join(targetService.ServiceHostNames, "|")
				idempotencyToken = fmt.Sprintf("%x", md5.Sum([]byte(idempotencyToken)))

				// If no certicate was found, create one.
				createRes, err := svc.RequestCertificate(&acm.RequestCertificateInput{
					// Fully qualified domain name (FQDN), such as www.example.com, that you want
					// to secure with an ACM certificate. Use an asterisk (*) to create a wildcard
					// certificate that protects several sites in the same domain. For example,
					// *.example.com protects www.example.com, site.example.com, and images.example.com.
					//
					// The first domain name you enter cannot exceed 63 octets, including periods.
					// Each subsequent Subject Alternative Name (SAN), however, can be up to 253
					// octets in length.
					//
					// DomainName is a required field
					DomainName: aws.String(targetService.ServiceHostPrimary),

					// Customer chosen string that can be used to distinguish between calls to RequestCertificate.
					// Idempotency tokens time out after one hour. Therefore, if you call RequestCertificate
					// multiple times with the same idempotency token within one hour, ACM recognizes
					// that you are requesting only one certificate and will issue only one. If
					// you change the idempotency token for each call, ACM recognizes that you are
					// requesting multiple certificates.
					IdempotencyToken: aws.String(idempotencyToken),

					// Currently, you can use this parameter to specify whether to add the certificate
					// to a certificate transparency log. Certificate transparency makes it possible
					// to detect SSL/TLS certificates that have been mistakenly or maliciously issued.
					// Certificates that have not been logged typically produce an error message
					// in a browser. For more information, see Opting Out of Certificate Transparency
					// Logging (https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html#best-practices-transparency).
					Options: &acm.CertificateOptions{
						CertificateTransparencyLoggingPreference: aws.String("DISABLED"),
					},

					// Additional FQDNs to be included in the Subject Alternative Name extension
					// of the ACM certificate. For example, add the name www.example.net to a certificate
					// for which the DomainName field is www.example.com if users can reach your
					// site by using either name. The maximum number of domain names that you can
					// add to an ACM certificate is 100. However, the initial limit is 10 domain
					// names. If you need more than 10 names, you must request a limit increase.
					// For more information, see Limits (https://docs.aws.amazon.com/acm/latest/userguide/acm-limits.html).
					SubjectAlternativeNames: aws.StringSlice(targetService.ServiceHostNames),

					// The method you want to use if you are requesting a public certificate to
					// validate that you own or control domain. You can validate with DNS (https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html)
					// or validate with email (https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html).
					// We recommend that you use DNS validation.
					ValidationMethod: aws.String("DNS"),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to create certificate '%s'", targetService.ServiceHostPrimary)
				}
				certificateArn = *createRes.CertificateArn

				log.Printf("\t\tCreated certificate '%s'", targetService.ServiceHostPrimary)
			} else {
				log.Printf("\t\tFound certificate '%s'", targetService.ServiceHostPrimary)
			}

			descRes, err := svc.DescribeCertificate(&acm.DescribeCertificateInput{
				CertificateArn: aws.String(certificateArn),
			})
			if err != nil {
				return errors.Wrapf(err, "Failed to describe certificate '%s'", certificateArn)
			}
			cert := descRes.Certificate

			log.Printf("\t\t\tStatus: %s", *cert.Status)

			if *cert.Status == "PENDING_VALIDATION" {
				svc := route53.New(cfg.AwsSession())

				log.Println("\t\t\tList all hosted zones.")

				var zoneValOpts = map[string][]*acm.DomainValidation{}
				for _, opt := range cert.DomainValidationOptions {
					var found bool
					for zoneId, aNames := range zoneArecNames {
						for _, aName := range aNames {
							fmt.Println(*opt.DomainName, " ==== ", aName)

							if *opt.DomainName == aName {
								if _, ok := zoneValOpts[zoneId]; !ok {
									zoneValOpts[zoneId] = []*acm.DomainValidation{}
								}
								zoneValOpts[zoneId] = append(zoneValOpts[zoneId], opt)
								found = true
								break
							}
						}

						if found {
							break
						}
					}

					if !found {
						return errors.Errorf("Failed to find zone ID for '%s'", *opt.DomainName)
					}
				}

				for zoneId, opts := range zoneValOpts {
					for _, opt := range opts {
						if *opt.ValidationStatus == "SUCCESS" {
							continue
						}

						input := &route53.ChangeResourceRecordSetsInput{
							ChangeBatch: &route53.ChangeBatch{
								Changes: []*route53.Change{
									&route53.Change{
										Action: aws.String("UPSERT"),
										ResourceRecordSet: &route53.ResourceRecordSet{
											Name: opt.ResourceRecord.Name,
											ResourceRecords: []*route53.ResourceRecord{
												&route53.ResourceRecord{Value: opt.ResourceRecord.Value},
											},
											Type: opt.ResourceRecord.Type,
											TTL:  aws.Int64(60),
										},
									},
								},
							},
							HostedZoneId: aws.String(zoneId),
						}

						log.Printf("\t\t\tAdded verification record for '%s'.\n", *opt.ResourceRecord.Name)
						_, err := svc.ChangeResourceRecordSets(input)
						if err != nil {
							return errors.Wrapf(err, "Failed to update A records for zone '%s'", zoneId)
						}
					}
				}
			}

			log.Printf("\t%s\tUsing ACM Certicate '%s'.\n", Success, certificateArn)
		}

		log.Println("EC2 - Find Elastic Load Balancer")
		{
			svc := elbv2.New(cfg.AwsSession())

			loadBalancerName := targetService.AwsElbLoadBalancer.Name

			// Try to find load balancer given a name.
			var elb *elbv2.LoadBalancer
			err := svc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{
				Names: []*string{aws.String(loadBalancerName)},
			}, func(res *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
				// Loop through the results to find the match ELB.
				for _, lb := range res.LoadBalancers {
					if *lb.LoadBalancerName == loadBalancerName {
						elb = lb
						return false
					}
				}
				return !lastPage
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elbv2.ErrCodeLoadBalancerNotFoundException {
					return errors.Wrapf(err, "Failed to describe load balancer '%s'", loadBalancerName)
				}
			}

			var curListeners []*elbv2.Listener
			if elb == nil {
				input, err := targetService.AwsElbLoadBalancer.Input(subnetIds, securityGroupIds)
				if err != nil {
					return err
				}

				// If no repository was found, create one.
				createRes, err := svc.CreateLoadBalancer(input)
				if err != nil {
					return errors.Wrapf(err, "Failed to create load balancer '%s'", loadBalancerName)
				}
				elb = createRes.LoadBalancers[0]

				log.Printf("\t\tCreated: %s.", *elb.LoadBalancerArn)
			} else {
				log.Printf("\t\tFound: %s.", *elb.LoadBalancerArn)

				// Search for existing listeners associated with the load balancer.
				res, err := svc.DescribeListeners(&elbv2.DescribeListenersInput{
					// The Amazon Resource Name (ARN) of the load balancer.
					LoadBalancerArn: aws.String(*elb.LoadBalancerArn),
					// There are two target groups, return both associated listeners if they exist.
					PageSize: aws.Int64(2),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to find listeners for load balancer '%s'", loadBalancerName)
				}
				curListeners = res.Listeners
			}
			targetService.AwsElbLoadBalancer.result = elb

			// The state code. The initial state of the load balancer is provisioning. After
			// the load balancer is fully set up and ready to route traffic, its state is
			// active. If the load balancer could not be set up, its state is failed.
			log.Printf("\t\t\tState: %s.", *targetService.AwsElbLoadBalancer.result.State.Code)

			targetGroupName := targetService.AwsElbLoadBalancer.TargetGroup.Name

			var targetGroup *elbv2.TargetGroup
			err = svc.DescribeTargetGroupsPages(&elbv2.DescribeTargetGroupsInput{
				LoadBalancerArn: aws.String(*elb.LoadBalancerArn),
			}, func(res *elbv2.DescribeTargetGroupsOutput, lastPage bool) bool {
				for _, tg := range res.TargetGroups {
					if *tg.TargetGroupName == targetGroupName {
						targetGroup = tg
						return false
					}
				}
				return !lastPage
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != elbv2.ErrCodeTargetGroupNotFoundException {
					return errors.Wrapf(err, "Failed to describe target group '%s'", targetGroupName)
				}
			}

			if targetGroup == nil {
				input, err := targetService.AwsElbLoadBalancer.TargetGroup.Input(vpcId)
				if err != nil {
					return err
				}

				// If no target group was found, create one.
				createRes, err := svc.CreateTargetGroup(input)
				if err != nil {
					return errors.Wrapf(err, "Failed to create target group '%s'", targetGroupName)
				}
				targetGroup = createRes.TargetGroups[0]

				log.Printf("\t\tAdded target group: %s.", *targetGroup.TargetGroupArn)
			} else {
				log.Printf("\t\tHas target group: %s.", *targetGroup.TargetGroupArn)
			}
			targetService.AwsElbLoadBalancer.TargetGroup.result = targetGroup

			if targetService.AwsElbLoadBalancer.EcsTaskDeregistrationDelay > 0 {
				// If no target group was found, create one.
				_, err = svc.ModifyTargetGroupAttributes(&elbv2.ModifyTargetGroupAttributesInput{
					TargetGroupArn: targetGroup.TargetGroupArn,
					Attributes: []*elbv2.TargetGroupAttribute{
						&elbv2.TargetGroupAttribute{
							// The name of the attribute.
							Key: aws.String("deregistration_delay.timeout_seconds"),

							// The value of the attribute.
							Value: aws.String(strconv.Itoa(targetService.AwsElbLoadBalancer.EcsTaskDeregistrationDelay)),
						},
					},
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to modify target group '%s' attributes", targetGroupName)
				}

				log.Printf("\t\t\tSet sttributes.")
			}

			listenerPorts := map[string]int64{
				"HTTP": 80,
			}
			if targetService.EnableHTTPS {
				listenerPorts["HTTPS"] = 443
			}

			for listenerProtocol, listenerPort := range listenerPorts {

				var foundListener bool
				for _, cl := range curListeners {
					if *cl.Port == listenerPort {
						foundListener = true
						break
					}
				}

				if !foundListener {
					listenerInput := &elbv2.CreateListenerInput{
						// The actions for the default rule. The rule must include one forward action
						// or one or more fixed-response actions.
						//
						// If the action type is forward, you specify a target group. The protocol of
						// the target group must be HTTP or HTTPS for an Application Load Balancer.
						// The protocol of the target group must be TCP, TLS, UDP, or TCP_UDP for a
						// Network Load Balancer.
						//
						// DefaultActions is a required field
						DefaultActions: []*elbv2.Action{
							&elbv2.Action{
								// The type of action. Each rule must include exactly one of the following types
								// of actions: forward, fixed-response, or redirect.
								//
								// Type is a required field
								Type: aws.String("forward"),

								// The Amazon Resource Name (ARN) of the target group. Specify only when Type
								// is forward.
								TargetGroupArn: targetGroup.TargetGroupArn,
							},
						},

						// The Amazon Resource Name (ARN) of the load balancer.
						//
						// LoadBalancerArn is a required field
						LoadBalancerArn: elb.LoadBalancerArn,

						// The port on which the load balancer is listening.
						//
						// Port is a required field
						Port: aws.Int64(listenerPort),

						// The protocol for connections from clients to the load balancer. For Application
						// Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load
						// Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP.
						//
						// Protocol is a required field
						Protocol: aws.String(listenerProtocol),
					}

					if listenerProtocol == "HTTPS" {
						listenerInput.Certificates = append(listenerInput.Certificates, &elbv2.Certificate{
							CertificateArn: aws.String(certificateArn),
						})
					}

					// If no repository was found, create one.
					createRes, err := svc.CreateListener(listenerInput)
					if err != nil {
						return errors.Wrapf(err, "Failed to create listener '%s'", loadBalancerName)
					}

					log.Printf("\t\t\tAdded Listener: %s.", *createRes.Listeners[0].ListenerArn)
				}
			}

			ecsELBs = append(ecsELBs, &ecs.LoadBalancer{
				// The name of the container (as it appears in a container definition) to associate
				// with the load balancer.
				ContainerName: aws.String(targetService.AwsEcsService.ServiceName),
				// The port on the container to associate with the load balancer. This port
				// must correspond to a containerPort in the service's task definition. Your
				// container instances must allow ingress traffic on the hostPort of the port
				// mapping.
				ContainerPort: targetGroup.Port,
				// The full Amazon Resource Name (ARN) of the Elastic Load Balancing target
				// group or groups associated with a service or task set.
				TargetGroupArn: targetGroup.TargetGroupArn,
			})

			{
				log.Println("Ensure Load Balancer DNS name exists for hosted zones.")
				log.Printf("\t\tDNSName: '%s'.\n", *elb.DNSName)

				svc := route53.New(cfg.AwsSession())

				for zoneId, aNames := range zoneArecNames {
					log.Printf("\tChange zone '%s'.\n", zoneId)

					input := &route53.ChangeResourceRecordSetsInput{
						ChangeBatch: &route53.ChangeBatch{
							Changes: []*route53.Change{},
						},
						HostedZoneId: aws.String(zoneId),
					}

					// Add all the A record names with the same set of public IPs.
					for _, aName := range aNames {
						log.Printf("\t\tAdd A record for '%s'.\n", aName)

						input.ChangeBatch.Changes = append(input.ChangeBatch.Changes, &route53.Change{
							Action: aws.String("UPSERT"),
							ResourceRecordSet: &route53.ResourceRecordSet{
								Name: aws.String(aName),
								Type: aws.String("A"),
								AliasTarget: &route53.AliasTarget{
									HostedZoneId:         elb.CanonicalHostedZoneId,
									DNSName:              elb.DNSName,
									EvaluateTargetHealth: aws.Bool(true),
								},
							},
						})
					}

					log.Printf("\tUpdated '%s'.\n", zoneId)
					_, err := svc.ChangeResourceRecordSets(input)
					if err != nil {
						return errors.Wrapf(err, "Failed to update A records for zone '%s'", zoneId)
					}
				}
			}

			log.Printf("\t%s\tLoad balancer configured.\n", Success)
		}
	} else {

		// When not using an Elastic Load Balancer, services need to support direct access via HTTPS.
		// HTTPS is terminated via the web server and not on the Load Balancer.
		if targetService.EnableHTTPS {
			log.Println("\tEC2 - Enable HTTPS port 443 for security group.")

			svc := ec2.New(cfg.AwsSession())

			// Enable services to be publicly available via HTTPS port 443.
			_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				IpProtocol: aws.String("tcp"),
				CidrIp:     aws.String("0.0.0.0/0"),
				FromPort:   aws.Int64(443),
				ToPort:     aws.Int64(443),
				GroupId:    cfg.AwsEc2SecurityGroup.result.GroupId,
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "InvalidPermission.Duplicate" {
					return errors.Wrapf(err, "Failed to add ingress for security group '%s'",
						cfg.AwsEc2SecurityGroup.GroupName)
				}
			}
		}
	}

	// Step 6: Try to find AWS ECS Cluster by name or create new one.
	{
		log.Println("ECS - Get or Create Cluster")

		svc := ecs.New(cfg.AwsSession())

		clusterName := targetService.AwsEcsCluster.ClusterName

		var ecsCluster *ecs.Cluster
		descRes, err := svc.DescribeClusters(&ecs.DescribeClustersInput{
			Clusters: []*string{aws.String(clusterName)},
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != ecs.ErrCodeClusterNotFoundException {
				return errors.Wrapf(err, "Failed to describe cluster '%s'", clusterName)
			}
		} else if len(descRes.Clusters) > 0 {
			ecsCluster = descRes.Clusters[0]
		}

		if ecsCluster == nil || *ecsCluster.Status == "INACTIVE" {
			input, err := targetService.AwsEcsCluster.Input()
			if err != nil {
				return err
			}

			// If no cluster was found, create one.
			createRes, err := svc.CreateCluster(input)
			if err != nil {
				return errors.Wrapf(err, "Failed to create cluster '%s'", clusterName)
			}
			ecsCluster = createRes.Cluster

			log.Printf("\t\tCreated: %s.", *ecsCluster.ClusterArn)
		} else {
			log.Printf("\t\tFound: %s.", *ecsCluster.ClusterArn)

			// The number of services that are running on the cluster in an ACTIVE state.
			// You can view these services with ListServices.
			log.Printf("\t\t\tActiveServicesCount: %d.", *ecsCluster.ActiveServicesCount)
			// The number of tasks in the cluster that are in the PENDING state.
			log.Printf("\t\t\tPendingTasksCount: %d.", *ecsCluster.PendingTasksCount)
			// The number of container instances registered into the cluster. This includes
			// container instances in both ACTIVE and DRAINING status.
			log.Printf("\t\t\tRegisteredContainerInstancesCount: %d.", *ecsCluster.RegisteredContainerInstancesCount)
			// The number of tasks in the cluster that are in the RUNNING state.
			log.Printf("\t\t\tRunningTasksCount: %d.", *ecsCluster.RunningTasksCount)
		}
		targetService.AwsEcsCluster.result = ecsCluster

		// The status of the cluster. The valid values are ACTIVE or INACTIVE. ACTIVE
		// indicates that you can register container instances with the cluster and
		// the associated instances can accept tasks.
		log.Printf("\t\t\tStatus: %s.", *ecsCluster.Status)

		log.Printf("\t%s\tECS Cluster setup.\n", Success)
	}

	// Step 7: Register a new ECS task definition.
	var taskDef *ecs.TaskDefinition
	{
		log.Println("\tECS - Register task definition")

		// Update the placeholders for the supplied task definition.
		var taskDefInput *ecs.RegisterTaskDefinitionInput
		{
			log.Println("\t\tFind and replace placeholders")

			// List of placeholders that can be used in task definition and replaced on deployment.
			placeholders := map[string]string{
				"{SERVICE}":               targetService.ServiceName,
				"{RELEASE_IMAGE}":         targetService.ReleaseImage,
				"{AWS_DEFAULT_REGION}":    cfg.AwsCredentials.Region,
				"{AWS_LOGS_GROUP}":        targetService.AwsCloudWatchLogGroup.LogGroupName,
				"{AWS_S3_BUCKET_PRIVATE}": cfg.AwsS3BucketPrivate.BucketName,
				"{AWS_S3_BUCKET_PUBLIC}":  cfg.AwsS3BucketPublic.BucketName,
				"{ENV}":                   cfg.Env,
				"{HTTP_HOST}":             "0.0.0.0:80",
				"{HTTPS_HOST}":            "", // Not enabled by default
				"{HTTPS_ENABLED}":         "false",

				"{APP_PROJECT}":  cfg.ProjectName,
				"{APP_BASE_URL}": "", // Not set by default, requires a hostname to be defined.
				"{HOST_PRIMARY}": targetService.ServiceHostPrimary,
				"{HOST_NAMES}":   strings.Join(targetService.ServiceHostNames, ","),

				"{STATIC_FILES_S3_ENABLED}":         "false",
				"{STATIC_FILES_S3_PREFIX}":          targetService.StaticFilesS3Prefix,
				"{STATIC_FILES_CLOUDFRONT_ENABLED}": "false",
				"{STATIC_FILES_IMG_RESIZE_ENABLED}": "false",

				"{CACHE_HOST}": "-", // Not enabled by default

				"{DB_HOST}":        "",
				"{DB_USER}":        "",
				"{DB_PASS}":        "",
				"{DB_DATABASE}":    "",
				"{DB_DRIVER}":      "",
				"{DB_DISABLE_TLS}": "",

				"{" + ENV_KEY_ECS_CLUSTER + "}":             targetService.AwsEcsCluster.ClusterName,
				"{" + ENV_KEY_ECS_SERVICE + "}":             targetService.AwsEcsService.ServiceName,
				"{" + ENV_KEY_ROUTE53_ZONES + "}":           "",
				"{" + ENV_KEY_ROUTE53_UPDATE_TASK_IPS + "}": "false",

				// Directly map GitLab CICD env variables set during deploy.
				"{CI_COMMIT_REF_NAME}":     os.Getenv("CI_COMMIT_REF_NAME"),
				"{CI_COMMIT_REF_SLUG}":     os.Getenv("CI_COMMIT_REF_SLUG"),
				"{CI_COMMIT_SHA}":          os.Getenv("CI_COMMIT_SHA"),
				"{CI_COMMIT_TAG}":          os.Getenv("CI_COMMIT_TAG"),
				"{CI_COMMIT_JOB_ID}":       os.Getenv("CI_COMMIT_JOB_ID"),
				"{CI_COMMIT_JOB_URL}":      os.Getenv("CI_COMMIT_JOB_URL"),
				"{CI_COMMIT_PIPELINE_ID}":  os.Getenv("CI_COMMIT_PIPELINE_ID"),
				"{CI_COMMIT_PIPELINE_URL}": os.Getenv("CI_COMMIT_PIPELINE_URL"),
			}

			// For HTTPS support.
			if targetService.EnableHTTPS {
				placeholders["{HTTPS_ENABLED}"] = "true"

				// When there is no Elastic Load Balancer, we need to terminate HTTPS on the app.
				if len(ecsELBs) == 0 {
					placeholders["{HTTPS_HOST}"] = "0.0.0.0:443"
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

				placeholders["{APP_BASE_URL}"] = fmt.Sprintf("%s://%s/", appSchema, targetService.ServiceHostPrimary)
			}

			// Static files served from S3.
			if targetService.StaticFilesS3Prefix != "" {
				placeholders["{STATIC_FILES_S3_ENABLED}"] = "true"
			}

			// Static files served from CloudFront.
			if cfg.AwsS3BucketPublic.CloudFront != nil {
				placeholders["{STATIC_FILES_CLOUDFRONT_ENABLED}"] = "true"
			}

			// When db is set, update the placeholders.
			if cfg.DBConnInfo != nil {
				placeholders["{DB_HOST}"] = cfg.DBConnInfo.Host
				placeholders["{DB_USER}"] = cfg.DBConnInfo.User
				placeholders["{DB_PASS}"] = cfg.DBConnInfo.Pass
				placeholders["{DB_DATABASE}"] = cfg.DBConnInfo.Database
				placeholders["{DB_DRIVER}"] = cfg.DBConnInfo.Driver

				if cfg.DBConnInfo.DisableTLS {
					placeholders["{DB_DISABLE_TLS}"] = "true"
				} else {
					placeholders["{DB_DISABLE_TLS}"] = "false"
				}
			}

			// When cache cluster is set, set the host and port.
			if cfg.AwsElasticCacheCluster != nil {
				cacheCluster := cfg.AwsElasticCacheCluster.result

				var cacheHost string
				if cacheCluster.ConfigurationEndpoint != nil {
					// Works for memcache.
					cacheHost = fmt.Sprintf("%s:%d", *cacheCluster.ConfigurationEndpoint.Address, *cacheCluster.ConfigurationEndpoint.Port)
				} else if len(cacheCluster.CacheNodes) > 0 {
					// Works for redis.
					cacheHost = fmt.Sprintf("%s:%d", *cacheCluster.CacheNodes[0].Endpoint.Address, *cacheCluster.CacheNodes[0].Endpoint.Port)
				} else {
					return errors.New("Unable to determine cache host from cache cluster")
				}
				placeholders["{CACHE_HOST}"] = cacheHost
			}

			// Append the Route53 Zones as an env var to be used by the service for maintaining A records when new tasks
			// are spun up or down.
			if len(zoneArecNames) > 0 {
				dat, err := json.Marshal(zoneArecNames)
				if err != nil {
					return errors.Wrapf(err, "failed to json marshal zones")
				}

				placeholders["{"+ENV_KEY_ROUTE53_ZONES+"}"] = base64.RawURLEncoding.EncodeToString(dat)

				// When no Elastic Load Balance is used, tasks need to be able to directly update the Route 53 records.
				if targetService.AwsElbLoadBalancer == nil {
					placeholders["{"+ENV_KEY_ROUTE53_UPDATE_TASK_IPS+"}"] = "true"
				}
			}

			// Execute the custom function to update the placeholder key/values if one is defined.
			if targetService.AwsEcsTaskDefinition.UpdatePlaceholders != nil {
				err = targetService.AwsEcsTaskDefinition.UpdatePlaceholders(placeholders)
				if err != nil {
					return err
				}
			}

			// Json encode the task definition so the place holders can easily be replaced with no reflection.
			jsonB, err := json.Marshal(targetService.AwsEcsTaskDefinition.RegisterInput)
			if err != nil {
				return err
			}
			jsonStr := string(jsonB)

			// Loop through all the placeholders and create a list of keys to search json.
			var pks []string
			for k, _ := range placeholders {
				pks = append(pks, k)
			}

			// Replace placeholders used in the JSON task definition.
			{
				// Generate new regular expression for finding placeholders.
				expr := "(" + strings.Join(pks, "|") + ")"
				r, err := regexp.Compile(expr)
				if err != nil {
					return err
				}

				matches := r.FindAllString(jsonStr, -1)

				if len(matches) > 0 {
					log.Println("\t\tUpdating placeholders.")

					replaced := make(map[string]bool)
					for _, m := range matches {
						if replaced[m] {
							continue
						}
						replaced[m] = true

						newVal := placeholders[m]
						log.Printf("\t\t\t%s -> %s", m, newVal)
						jsonStr = strings.Replace(jsonStr, m, newVal, -1)
					}
				}
			}

			// Replace placeholders defined in task def but not here from env vars.
			{
				r, err := regexp.Compile(`{\b(\w*)\b}`)
				if err != nil {
					return err
				}

				matches := r.FindAllString(jsonStr, -1)
				if len(matches) > 0 {
					log.Println("\t\tSearching for placeholders in env variables.")

					replaced := make(map[string]bool)
					for _, m := range matches {
						if replaced[m] {
							continue
						}
						replaced[m] = true

						envKey := strings.Trim(m, "{}")
						newVal := os.Getenv(envKey)
						log.Printf("\t\t\t%s -> %s", m, newVal)
						jsonStr = strings.Replace(jsonStr, m, newVal, -1)
					}
				}
			}
			jsonB = []byte(jsonStr)

			log.Println("\t\tParse JSON to task definition.")

			taskDefInput, err = ParseTaskDefinitionInput(jsonB)
			if err != nil {
				return err
			}
		}

		// If a task definition value is empty, populate it with the default value.
		if taskDefInput.Family == nil || *taskDefInput.Family == "" {
			taskDefInput.Family = aws.String(targetService.ServiceName)
		}
		if len(taskDefInput.ContainerDefinitions) > 0 {
			if taskDefInput.ContainerDefinitions[0].Name == nil || *taskDefInput.ContainerDefinitions[0].Name == "" {
				taskDefInput.ContainerDefinitions[0].Name = aws.String(targetService.ServiceName)
			}
			if taskDefInput.ContainerDefinitions[0].Image == nil || *taskDefInput.ContainerDefinitions[0].Image == "" {
				taskDefInput.ContainerDefinitions[0].Image = aws.String(targetService.ReleaseImage)
			}
		}

		log.Printf("\t\t\tFamily: %s", *taskDefInput.Family)
		log.Printf("\t\t\tExecutionRoleArn: %s", *taskDefInput.ExecutionRoleArn)

		if taskDefInput.TaskRoleArn != nil {
			log.Printf("\t\t\tTaskRoleArn: %s", *taskDefInput.TaskRoleArn)
		}
		if taskDefInput.NetworkMode != nil {
			log.Printf("\t\t\tNetworkMode: %s", *taskDefInput.NetworkMode)
		}
		log.Printf("\t\t\tTaskDefinitions: %d", len(taskDefInput.ContainerDefinitions))

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
		if (taskDefInput.ExecutionRoleArn == nil || *taskDefInput.ExecutionRoleArn == "") && targetService.AwsEcsExecutionRole != nil {

			// Find or create role for ExecutionRoleArn.
			role, err := SetupIamRole(log, cfg, targetService.AwsEcsExecutionRole, targetService.AwsEcsExecutionRole.AttachRolePolicyArns...)
			if err != nil {
				return err
			}

			// Update the task definition with the execution role ARN.
			log.Printf("\tAppend ExecutionRoleArn to task definition input for role %s.", *role.RoleName)
			taskDefInput.ExecutionRoleArn = role.Arn

			log.Printf("\t%s\tExecutionRoleArn updated.\n", Success)
		}

		// The task role is the IAM role used by the task itself to access other AWS Services. To access services
		// like S3, SQS, etc then those permissions would need to be covered by the TaskRole.
		if (taskDefInput.TaskRoleArn == nil || *taskDefInput.TaskRoleArn == "") && targetService.AwsEcsTaskRole != nil {

			// Find or create role for TaskRoleArn.
			// Use the default policy defined for the entire project for all services and functions.
			role, err := SetupIamRole(log, cfg, targetService.AwsEcsTaskRole, *cfg.AwsIamPolicy.result.Arn)
			if err != nil {
				return err
			}

			// Update the task definition with the task role ARN.
			log.Printf("\tAppend TaskRoleArn to task definition input for role %s.", *role.RoleName)
			taskDefInput.TaskRoleArn = role.Arn
		}

		log.Println("\tRegister new task definition.")
		{
			svc := ecs.New(cfg.AwsSession())

			// Registers a new task.
			res, err := svc.RegisterTaskDefinition(taskDefInput)
			if err != nil {
				return errors.Wrapf(err, "Failed to register task definition '%s'", *taskDefInput.Family)
			}
			taskDef = res.TaskDefinition

			log.Printf("\t\tRegistered: %s.", *taskDef.TaskDefinitionArn)
			log.Printf("\t\t\tRevision: %d.", *taskDef.Revision)
			log.Printf("\t\t\tStatus: %s.", *taskDef.Status)

			log.Printf("\t%s\tTask definition registered.\n", Success)
		}

		targetService.AwsEcsTaskDefinition.result = taskDef
	}

	// Step 8: Find the existing ECS service and check if it needs to be recreated
	var ecsService *ecs.Service
	{
		svc := ecs.New(cfg.AwsSession())

		ecsServiceName := targetService.AwsEcsService.ServiceName

		// Try to find AWS ECS Service by name. This does not error on not found, but results are used to determine if
		// the full creation process of a service needs to be executed.
		{
			log.Println("\tECS - Find Service")

			// Find service by ECS cluster and service name.
			res, err := svc.DescribeServices(&ecs.DescribeServicesInput{
				Cluster:  targetService.AwsEcsCluster.result.ClusterArn,
				Services: []*string{aws.String(ecsServiceName)},
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != ecs.ErrCodeServiceNotFoundException {
					return errors.Wrapf(err, "Failed to describe service '%s'", ecsServiceName)
				}
			} else if len(res.Services) > 0 {
				ecsService = res.Services[0]

				log.Printf("\t\tFound: %s.", *ecsService.ServiceArn)

				// The desired number of instantiations of the task definition to keep running
				// on the service. This value is specified when the service is created with
				// CreateService, and it can be modified with UpdateService.
				log.Printf("\t\t\tDesiredCount: %d.", *ecsService.DesiredCount)
				// The number of tasks in the cluster that are in the PENDING state.
				log.Printf("\t\t\tPendingCount: %d.", *ecsService.PendingCount)
				// The number of tasks in the cluster that are in the RUNNING state.
				log.Printf("\t\t\tRunningCount: %d.", *ecsService.RunningCount)

				// The status of the service. The valid values are ACTIVE, DRAINING, or INACTIVE.
				log.Printf("\t\t\tStatus: %s.", *ecsService.Status)

				log.Printf("\t%s\tUsing ECS Service '%s'.\n", Success, ecsServiceName)
			} else {
				log.Printf("\t%s\tExisting ECS Service not found.\n", Success)
			}
		}

		// Check to see if the service should be re-created instead of updated.
		if ecsService != nil {
			var (
				recreateService bool
				forceDelete     bool
			)

			if targetService.AwsEcsService.ForceRecreate {
				// Flag was included to force recreate.
				recreateService = true
				forceDelete = true
			} else if len(ecsELBs) > 0 && (ecsService.LoadBalancers == nil || len(ecsService.LoadBalancers) == 0) {
				// Service was created without ELB and now ELB is enabled.
				recreateService = true
			} else if len(ecsELBs) == 0 && (ecsService.LoadBalancers != nil && len(ecsService.LoadBalancers) > 0) {
				// Service was created with ELB and now ELB is disabled.
				recreateService = true
			} else if targetService.AwsSdPrivateDnsNamespace != nil && targetService.AwsSdPrivateDnsNamespace.Service != nil && (ecsService.ServiceRegistries == nil || len(ecsService.ServiceRegistries) == 0) {
				// Service was created without Service Discovery and now Service Discovery is enabled.
				recreateService = true
			} else if (targetService.AwsSdPrivateDnsNamespace == nil || targetService.AwsSdPrivateDnsNamespace.Service == nil) && (ecsService.ServiceRegistries != nil && len(ecsService.ServiceRegistries) > 0) {
				// Service was created with Service Discovery and now Service Discovery is disabled.
				recreateService = true
			}

			// If determined from above that service needs to be recreated.
			if recreateService {

				// Needs to delete any associated services on ECS first before it can be recreated.
				log.Println("ECS - Delete Service")

				// The service cannot be stopped while it is scaled above 0.
				if ecsService.DesiredCount != nil && *ecsService.DesiredCount > 0 {
					log.Println("\t\tScaling service down to zero.")
					_, err := svc.UpdateService(&ecs.UpdateServiceInput{
						Cluster:      ecsService.ClusterArn,
						Service:      ecsService.ServiceArn,
						DesiredCount: aws.Int64(int64(0)),
					})
					if err != nil {
						return errors.Wrapf(err, "Failed to update service '%s'", ecsService.ServiceName)
					}

					// It may take some time for the service to scale down, so need to wait.
					log.Println("\t\tWait for the service to scale down.")
					err = svc.WaitUntilServicesStable(&ecs.DescribeServicesInput{
						Cluster:  targetService.AwsEcsCluster.result.ClusterArn,
						Services: aws.StringSlice([]string{*ecsService.ServiceArn}),
					})
					if err != nil {
						return errors.Wrapf(err, "Failed to wait for service '%s' to enter stable state", *ecsService.ServiceName)
					}
				}

				// Once task count is 0 for the service, then can delete it.
				log.Println("\t\tDelete Service.")
				res, err := svc.DeleteService(&ecs.DeleteServiceInput{
					Cluster: ecsService.ClusterArn,
					Service: ecsService.ServiceArn,

					// If true, allows you to delete a service even if it has not been scaled down
					// to zero tasks. It is only necessary to use this if the service is using the
					// REPLICA scheduling strategy.
					Force: aws.Bool(forceDelete),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to delete service '%s'", ecsService.ServiceName)
				}
				ecsService = res.Service

				log.Println("\t\tWait for the service to be deleted.")
				err = svc.WaitUntilServicesInactive(&ecs.DescribeServicesInput{
					Cluster:  targetService.AwsEcsCluster.result.ClusterArn,
					Services: aws.StringSlice([]string{*ecsService.ServiceArn}),
				})
				if err != nil {
					return errors.Wrapf(err, "Failed to wait for service '%s' to enter stable state", *ecsService.ServiceName)
				}

				// Manually mark the ECS has inactive since WaitUntilServicesInactive was executed.
				ecsService.Status = aws.String("INACTIVE")

				log.Printf("\t%s\tDelete Service.\n", Success)
			}
		}

		targetService.AwsEcsService.result = ecsService
	}

	// Step 9: If the service exists on ECS, update the service, else create a new service.
	if ecsService != nil && *ecsService.Status != "INACTIVE" {
		log.Println("\tECS - Update Service")

		svc := ecs.New(cfg.AwsSession())

		input, err := targetService.AwsEcsService.UpdateInput(targetService.AwsEcsCluster.ClusterName, *taskDef.TaskDefinitionArn)
		if err != nil {
			return err
		}

		updateRes, err := svc.UpdateService(input)
		if err != nil {
			return errors.Wrapf(err, "Failed to update service '%s'", *ecsService.ServiceName)
		}
		ecsService = updateRes.Service

		log.Printf("\t%s\tUpdated ECS Service '%s'.\n", Success, *ecsService.ServiceName)
	} else {

		// If not service exists on ECS, then create it.
		log.Println("\tECS - Create Service")
		{
			svc := ecs.New(cfg.AwsSession())

			input, err := targetService.AwsEcsService.CreateInput(targetService.AwsEcsCluster.ClusterName, *taskDef.TaskDefinitionArn, subnetIds, securityGroupIds, ecsELBs, sdService)
			if err != nil {
				return err
			}

			createRes, err := svc.CreateService(input)

			// If tags aren't enabled for the account, try the request again without them.
			// https://aws.amazon.com/blogs/compute/migrating-your-amazon-ecs-deployment-to-the-new-arn-and-resource-id-format-2/
			if err != nil && strings.Contains(err.Error(), "ARN and resource ID format must be enabled") {
				input.Tags = nil
				createRes, err = svc.CreateService(input)
			}

			if err != nil {
				return errors.Wrapf(err, "Failed to create service '%s'", targetService.AwsEcsService.ServiceName)
			}
			ecsService = createRes.Service

			log.Printf("\t%s\tCreated ECS Service '%s'.\n", Success, *ecsService.ServiceName)
		}
	}
	targetService.AwsEcsService.result = ecsService

	// Step 10: When static files are enabled to be to stored on S3, we need to upload all of them.
	if targetService.StaticFilesDir != "" && targetService.StaticFilesS3Prefix != "" {
		log.Println("\tUpload static files to public S3 bucket")

		staticDir := targetService.StaticFilesDir

		if _, err := os.Stat(staticDir); err != nil {
			if !os.IsNotExist(err) {
				return errors.Wrapf(err, "Static directory '%s' does not exist.", staticDir)
			}
		} else {
			err := SyncPublicS3Files(cfg.AwsSession(),
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
			logStreamName := fmt.Sprintf("ecs/%s/%s", *ecsService.ServiceName, taskId)

			// Define S3 key prefix used to export the stream logs to.
			s3KeyPrefix := filepath.Join(
				privateBucket.TempPrefix,
				"logs/cloudwatchlogs/exports",
				logGroupName)

			var downloadPrefix string
			{
				svc := cloudwatchlogs.New(cfg.AwsSession())

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
				svc := s3.New(cfg.AwsSession())

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
			svc := ecs.New(cfg.AwsSession())

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
			if stoppedCnt == *ecsService.DesiredCount {
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
			svc := ecs.New(cfg.AwsSession())
			err := svc.WaitUntilServicesStable(&ecs.DescribeServicesInput{
				Cluster:  targetService.AwsEcsCluster.result.ClusterArn,
				Services: aws.StringSlice([]string{*ecsService.ServiceArn}),
			})
			if err != nil {
				checkErr <- errors.Wrapf(err, "Failed to wait for service '%s' to enter stable state", *ecsService.ServiceName)
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
