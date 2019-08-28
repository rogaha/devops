package devdeploy

import (
	"github.com/aws/aws-sdk-go/aws"
	"log"

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/pkg/errors"
)

// DeployLambdaToTargetEnv deploys a function to AWS Lambda The following steps will be executed for deployment:
// 1. Find the AWS IAM role if defined.
// 2. Find the AWS function if it exists.
// 3. Create or update the code/configuration.
// 4. Hookup any AWS Cloudwatch Event Rules.
func DeployLambdaToTargetEnv(log *log.Logger, cfg *Config, target *ProjectFunction) error {

	log.Printf("Deploy function %s to environment %s\n", target.Name, cfg.Env)

	infra, err := NewInfrastructure(cfg)
	if err != nil {
		return err
	}

	// Step 1: Find or create the AWS IAM role.
	if target.AwsIamRole != nil {
		role, err := infra.GetAwsIamRole(target.AwsIamRole.RoleName)
		if err != nil {
			return err
		}
		target.AwsLambdaFunction.Role = role.Arn

		log.Printf("\t%s\tConfigured Lambda role.\n", Success)
	}

	lambdaSvc := lambda.New(infra.AwsSession())

	funcName := target.AwsLambdaFunction.FunctionName

	// Step 2: Search for an existing lambda function
	var lambdaFunc *lambda.FunctionConfiguration
	{
		log.Println("\tLambda - Check for existing function")

		err := lambdaSvc.ListFunctionsPages(&lambda.ListFunctionsInput{},
			func(res *lambda.ListFunctionsOutput, lastPage bool) bool {
				for _, n := range res.Functions {
					if *n.FunctionName == funcName {
						lambdaFunc = n
						return false
					}
				}
				return !lastPage
			})
		if err != nil {
			return errors.Wrap(err, "Failed to list functions")
		}
	}

	var (
		vpc           *AwsEc2VpcResult
		securityGroup *AwsEc2SecurityGroupResult
	)
	if target.EnableVPC {
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

		securityGroup, err = infra.GetAwsEc2SecurityGroup(cfg.AwsEc2SecurityGroup.GroupName)
		if err != nil {
			return err
		}
	}

	// Step 3: Create or update the code/configuration.
	if lambdaFunc != nil {
		log.Printf("\t\tFound: %s", *lambdaFunc.FunctionArn)

		cfgRes, err := lambdaSvc.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
			FunctionName: aws.String(funcName),
		})
		if err != nil {
			return errors.Wrapf(err, "Failed to get configuration for '%s'", funcName)
		}

		codeInput, err := target.AwsLambdaFunction.UpdateCodeInput(target.CodeS3Bucket, target.CodeS3Key)
		if err != nil {
			return err
		}
		codeRes, err := lambdaSvc.UpdateFunctionCode(codeInput)
		if err != nil {
			return errors.Wrapf(err, "Failed to update code for '%s'", funcName)
		}
		lambdaFunc = codeRes
		log.Printf("\t\tUpdated Code: %s", *lambdaFunc.FunctionArn)

		configInput, err := target.AwsLambdaFunction.UpdateConfigurationInput(vpc, securityGroup, cfgRes)
		if err != nil {
			return err
		}
		configRes, err := lambdaSvc.UpdateFunctionConfiguration(configInput)
		if err != nil {
			return errors.Wrapf(err, "Failed to update configuration for '%s'", funcName)
		}
		lambdaFunc = configRes
		log.Printf("\t\tUpdated Configuration: %s", *lambdaFunc.FunctionArn)

	} else {

		input, err := target.AwsLambdaFunction.CreateInput(target.CodeS3Bucket, target.CodeS3Key, vpc, securityGroup)
		if err != nil {
			return err
		}

		// If no repository was found, create one.
		createRes, err := lambdaSvc.CreateFunction(input)
		if err != nil {
			return errors.Wrapf(err, "Failed to create repository '%s'", funcName)
		}
		lambdaFunc = createRes
		log.Printf("\t\tCreated: %s", *lambdaFunc.FunctionArn)
	}

	// Hookup any defined Cloudwatch Event rules defined for the lambda function.
	for _, eventRule := range target.AwsCloudwatchEventRules {
		eventRule.Targets = append(eventRule.Targets, &AwsCloudwatchEventTarget{
			Arn:     *lambdaFunc.FunctionArn,
			Id:      *lambdaFunc.FunctionName,
			RoleArn: lambdaFunc.Role,
		})

		_, err = infra.setupAwsCloudwatchEventRule(log, eventRule)
		if err != nil {
			return err
		}
	}

	return nil
}
