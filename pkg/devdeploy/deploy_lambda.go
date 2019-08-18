package devdeploy

import (
	"log"

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/pkg/errors"
)

// DeployLambda defines the detailed needed to deploy a function to AWS Lambda.
type DeployLambda struct {
	// Required flags.
	FuncName     string `validate:"required" example:"web-api"`
	CodeS3Key    string `validate:"required"`
	CodeS3Bucket string `validate:"required"`

	// Optional flags.
	EnableVPC bool `validate:"omitempty"`

	// AwsLambdaFunction defines the details for a lambda function.
	AwsLambdaFunction *AwsLambdaFunction `validate:"required"`

	// AwsIamRole defines the details for assigning the lambda function to use a custom role.
	AwsIamRole *AwsIamRole `validate:"required"`

	// AwsIamPolicy defines the details for created a custom policy for the lambda function.
	AwsIamPolicy *AwsIamPolicy `validate:"required"`
}

// DeployLambdaToTargetEnv deploys a function to AWS Lambda The following steps will be executed for deployment:
// 1. Find or create the AWS IAM policy if defined.
// 2. Find or create the AWS IAM role if defined.
// 3. Find the AWS function if it exists.
// 4. Create or update the code/configuration.
func DeployLambdaToTargetEnv(log *log.Logger, cfg *Config, target *DeployLambda) error {

	err := SetupDeploymentEnv(log, cfg)
	if err != nil {
		return err
	}

	log.Printf("Deploy function %s to environment %s\n", target.FuncName, cfg.Env)

	lambdaSvc := lambda.New(cfg.AwsSession())

	funcName := target.AwsLambdaFunction.FunctionName

	// Step 1: Find or create the AWS IAM policy.
	var policyArns []string
	if target.AwsIamPolicy != nil {
		policy, err := SetupIamPolicy(log, cfg, target.AwsIamPolicy)
		if err != nil {
			return err
		}
		policyArns = append(policyArns, *policy.Arn)

		log.Printf("\t%s\tConfigured Lambda policy.\n", Success)
	}

	// Step 2: Find or create the AWS IAM role.
	if target.AwsIamRole != nil {
		role, err := SetupIamRole(log, cfg, target.AwsIamRole, policyArns...)
		if err != nil {
			return err
		}
		log.Printf("\t%s\tConfigured Lambda role.\n", Success)

		target.AwsLambdaFunction.Role = *role.Arn
	}

	// Step 3: Search for an existing lambda function
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

	subnetIds := cfg.AwsEc2Vpc.subnetIds
	securityGroupIds := []string{*cfg.AwsEc2SecurityGroup.result.GroupId}

	// Step 4: Create or update the code/configuration.
	if lambdaFunc != nil {
		log.Printf("\t\tFound: %s", *lambdaFunc.FunctionArn)

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

		configInput, err := target.AwsLambdaFunction.UpdateConfigurationInput(subnetIds, securityGroupIds, target.EnableVPC)
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

		input, err := target.AwsLambdaFunction.CreateInput(target.CodeS3Bucket, target.CodeS3Key, subnetIds, securityGroupIds, target.EnableVPC)
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

	return nil
}
