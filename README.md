# Devops 
[![Build Status](https://gitlab.com/geeks-accelerator/oss/devops/badges/master/pipeline.svg)](https://gitlab.com/geeks-accelerator/oss/devops/pipelines) 
[![GoDoc](https://godoc.org/gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy?status.svg)](https://godoc.org/gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy)
[![Go Report Card](https://goreportcard.com/badge/gitlab.com/geeks-accelerator/oss/devops?style=flat-square)](https://goreportcard.com/report/gitlab.com/geeks-accelerator/oss/devops)


__Devops__ is a set of tools for building a continuous deployment pipeline for [GitLab CI/CD](https://docs.gitlab.com/ee/ci/) 
with serverless infrastructure on AWS. 

Check out the [full presentation](https://docs.google.com/presentation/d/1sRFQwipziZlxBtN7xuF-ol8vtUqD55l_4GE-4_ns-qM/edit?usp=sharing) 
that covers how to setup your GitLab CI/CD pipeline that uses autoscaling GitLab Runners on AWS.

<!-- toc -->

- [Overview](#overview)
- [Installation](#installation)
- [Getting Started](#getting-started)
    * [Configuration](#configuration)
    * [Database Schema](#database-schema)
    * [GitLab CI/CD](#gitlab-cicd)
- [Usage](#usage)
    * [AWS Permissions](#aws-permissions)
- [Contributions](#contributions)
- [Join us on Gopher Slack](#join-us-on-gopher-slack)
- [License](#license)

<!-- tocstop -->


## Overview

_Devops_ handles creating AWS resources and serverless deployments for your project using Go code (hopefully the primary 
language your project is coded in). This is known _Configuration as Code_ where code is the formal migration of config 
between your applications and your deployment environment. What does this entail?

1. All configuration for your project is check into version control.  
 
2. Configurations are migrated as apart of your build pipeline and is therefore treated the same as application code. 

3. You can customizing any of the configuration code without having to deal with JSON or YAML files. 

This project was developed to support the [SaaS Startup Kit](https://gitlab.com/geeks-accelerator/oss/saas-starter-kit) 
to facilitate getting code to production with minimal additional configuration. 

Multiple AWS services are already integrated into the _SaaS Startup Kit_, using the [AWS SDK for Go](https://aws.amazon.com/sdk-for-go/). 
Leveraging this existing AWS integration reduces new project dependencies and limits the scope of additional technologies 
required to get your code successfully up and running on production. If you understand Golang, then you will be a master 
at devops with this tool.

This project has three main components:

1. [pkg/devdeploy](https://godoc.org/gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy) - A package which provides 
configuration for AWS resources and handles executing that configuration for you. 

2. [build/cicd](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/build/cicd) - An example implementation of the 
_devdeploy_ package that includes configuration for two example applications: 

    * [Go Web API](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples/aws-ecs-go-web-api) - An API service 
    written in GO that is deployed to [AWS Fargate](https://aws.amazon.com/fargate/) with built in support for HTTPS.
    
        AWS Fargate is a compute engine for Amazon ECS that allows you to run containers without having to manage servers or 
        clusters. With AWS Fargate, you no longer have to provision, configure, and scale clusters of virtual machines to 
        run containers.  

    * [Python Datadog Log Collector](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples/aws-lambda-python-ddlogs) - 
    An python script that is deployed to [AWS Lambda](https://aws.amazon.com/lambda/) to ship logs from AWS to Datadog. 
    
        AWS Lambda lets you run code without provisioning or managing servers. You pay only for the compute time you consume, 
        there is no charge when your code is not running. 

3. [cmd/devops](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/cmd/devops) - A tool developed to help make it 
easy to get starting with this project. This tool will copy the example _build/cicd_ to a desired project directory 
updating Go imports as necessary. 



## Installation

Make sure you have a working Go environment.  Go version 1.2+ is supported.  [See
the install instructions for Go](http://golang.org/doc/install.html).


To install _devops_, simply run:
```
$ go get gitlab.com/geeks-accelerator/oss/devops/cmd/devops
```

Make sure your `PATH` includes the `$GOPATH/bin` directory so your commands can
be easily used:
```
export PATH=$PATH:$GOPATH/bin
```


## Getting Started

Make a copy of [build/cicd](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/build/cicd) to your specified 
project path. 
```bash
$ devops inject-build cicd -project $GOPATH/src/gitlab.com/geeks-accelerator/oss/saas-starter-kit
```

You should only run this command once as it will only create files that don't exist. It will not update or overwrite 
existing files. Once this command is executed, you are in charge of maintaining your copy _cicd_ as it will contain 
configuration details only relevant to your project.  

The `build/cicd` directory should have been added to your project path with the following structure:
```
.
├── ...
├── build/cicd
│         ├── internal
│         │   ├── config      # Project configuration for build and deployment. 
│         │   └── schema      # Database schema migration helper.
│         ├── main.go         # Command line entry point for executing config and schema.        
│         └── README.md       # Instructions focused on using cicd for a project. 
└── ...
```

No changes should be necessary to `main.go`. You should review `README.md` instructions as it will cover the current 
capabilities currently coded in `config`.  Once you have completed updated the configuration for your services and 
functions, ensure the `README.md` reflects the changes you have made.  

### Configuration

The directory `build/cicd/internal/config` is where all the configuration for deployment exists. This code should be 
updated to reflect your desired configuration. 
```
config
├── config.go       # Configuration for AWS infrastructure. 
├── function.go     # Defines functions that will be deployed to AWS Lambda. 
├── service.go      # Defines services that will be deployed to AWS Fargate. 
└── schema.go       # Handles executution of schema migrations. 
```

* `config.go` - Defines the configuration for AWS infrastructure required for serverless deployment. This includes 
details for AWS VPC, security group, RDS postgres database, Redis cache cluster, etc. 
 
* `function.go` - Defines your functions that will be deployed to AWS Lambda. This includes settings for the runtime, 
amount of memory, and timeout. The code has one function defined, 
[Python Datadog Log Collector](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples/aws-lambda-python-ddlogs). 
Additional functions can easily be defined here.  

* `service.go` - Defines your services that will be deployed to AWS Fargate. This includes settings for your AWS ECS 
Cluster, the specific service and task definitions. The code as one service defined, 
[Go Web API](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples/aws-ecs-go-web-api). Additional 
services can easily be defined here.  

* `schema.go` - Handles execution of schema migrations for target the deployment environment. Database credentials are 
loaded from AWS Secrets Manager. 


### Database Schema

The directory `build/cicd/internal/schema` is a minimalistic database migration script that implements 
[github.com/geeks-accelerator/sqlxmigrate](https://godoc.org/github.com/geeks-accelerator/sqlxmigrate). Database schema 
for the entire project should be defined globally. The [SaaS Startup Kit](https://gitlab.com/geeks-accelerator/oss/saas-starter-kit) 
also uses this package to dynamically spin up database containers on-demand and automatically include all the 
migrations. This allows the testing package to programmatically execute schema migrations before running any unit tests. 
```
schema
├── schema.go       # Entry point for executing schema migration. 
├── init_schema.go  # SQL queries executed on new databases. 
└── migrations.go   # Versioned SQL queries that be applied to the database. 
```

* `init_schema.go` - SQL queries that will run as-if no migration was run before (in a new clean database). 

* `migrations.go` - List of direct SQL statements for each migration with defined version ID. A database table is 
created to persist executed migrations. Upon run of each schema migration run, the migration logic checks the migration 
database table to check if it’s already been executed. Thus, schema migrations are only ever executed once. Migrations 
are defined as a function to enable complex migrations so results from query manipulated before being piped to the next 
query. 


### GitLab CI/CD

_cicd_ command is primary executed by a GitLab runner. After you have updated the configuration for your project, you 
will need to configure GitLab CI/CD to execute the build and deployment. This project has example 
[.gitlab-ci.yml](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/.gitlab-ci.yml) that should be placed in 
your project root. 

The project includes a Postgres database which adds an additional resource dependency when deploying the 
project. It is important to know that the tasks running schema migration for the Postgres database can not run as shared 
GitLab Runners since they will be outside the deployment AWS VPC. There are two options here: 
1. Enable the AWS RDS database to be publicly available (not recommended).
2. Run your own GitLab runners inside the same AWS VPC and grant access for them to communicate with the database.

This project has opted to implement option 2 and thus setting up the deployment pipeline requires a few more additional steps. 

Note that using shared runners hosted by GitLab also requires AWS credentials to be input into GitLab for configuration.  

Hosted your own GitLab runners uses AWS Roles instead of hardcoding the access key ID and secret access key in GitLab and 
in other configuration files. And since this project is open-source, we wanted to avoid sharing our AWS credentials.

 
**Setup GitLab CI/CD**

Below outlines the basic steps to setup [Autoscaling GitLab Runner on AWS](https://docs.gitlab.com/runner/configuration/runner_autoscale_aws/). 

If you don't have an AWS account, signup for one now and then proceed with the deployment setup. 

We assume that if you are deploying the SaaS Stater Kit, you are starting from scratch with no existing dependencies. 
This however, excludes any domain names that you would like to use for resolving your services publicly. To use any 
pre-purchased domain names, make sure they are added to Route 53 in the AWS account. Or you can let the deploy script 
create a new zone is Route 53 and update the DNS for the domain name when your ready to make the transition. It is 
required to hosted the DNS on Route 53 so DNS entries can be managed by this deploy tool. It is possible to use a 
[subdomain that uses Route 53 as the DNS service without migrating the parent domain](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/CreatingNewSubdomain.html). 

1. Define an [AWS IAM Role](https://console.aws.amazon.com/iam/home?region=us-west-2#/roles$new?step=type) that will be
attached to the GitLab Runner instances. The role will need permission to scale (EC2), update the cache (via S3) and 
perform the project specific deployment commands.
    ```
    Trusted Entity: AWS Service
    Service that will use this role: EC2 
    Attach permissions policies:  AmazonEC2FullAccess, AmazonS3FullAccess, saas-starter-kit-deploy 
    Role Name: SaasStarterKitEc2RoleForGitLabRunner
    Role Description: Allows GitLab runners hosted on EC2 instances to call AWS services on your behalf.
    ``` 

2. Launch a new [AWS EC2 Instance](https://us-west-2.console.aws.amazon.com/ec2/v2/home?region=us-west-2#LaunchInstanceWizard). 
`GitLab Runner` will be installed on this instance and will serve as the bastion that spawns new instances. This 
instance will be a dedicated host since we need it always up and running, thus it will be the standard costs apply. 

    Note: Since this machine will not run any jobs itself, it does not need to be very powerful. A t2.micro instance will be sufficient.
    ``` 
    Amazon Machine Image (AMI): Amazon Linux AMI 2018.03.0 (HVM), SSD Volume Type - ami-0f2176987ee50226e
    Instance Type: t2.micro 
    ``` 

3. Configure Instance Details. 

    Note: Do not forget to select the IAM Role _SaasStarterKitEc2RoleForGitLabRunner_ 
    ```
    Number of instances: 1
    Network: default VPC
    Subnet: no Preference
    Auto-assign Public IP: Use subnet setting (Enable)
    Placement Group: not checked/disabled
    Capacity Reservation: Open
    IAM Role: SaasStarterKitEc2RoleForGitLabRunner
    Shutdown behavior: Stop
    Enable termination project: checked/enabled
    Monitoring: not checked/disabled
    Tenancy: Shared
    Elastic Interence: not checked/disabled
    T2/T3 Unlimited: not checked/disabled
    Advanced Details: none 
    ```
    
4. Add Storage. Increase the volume size for the root device to 30 GiB.
    ```    
    Volume Type |   Device      | Size (GiB) |  Volume Type 
    Root        |   /dev/xvda   | 30        |  General Purpose SSD (gp2)
    ```

5. Add Tags.
    ```
    Name:  gitlab-runner 
    ``` 
    
6. Configure Security Group. Create a new security group with the following details:
    ``` 
    Name: gitlab-runner
    Description: Gitlab runners for running CICD.
    Rules:                       
        Type        | Protocol  | Port Range    | Source    | Description
        SSH         | TCP       | 22            | My IP     | SSH access for setup.                        
    ```        
    
7. Review and Launch instance. Select an existing key pair or create a new one. This will be used to SSH into the 
    instance for additional configuration. 
     
8. Update the security group to reference itself. The instances need to be able to communicate between each other. 

    Navigate to edit the security group and add the following two rules where `SECURITY_GROUP_ID` is replaced with the 
    name of the security group created in step 6.
    ``` 
    Rules:                       
        Type        | Protocol  | Port Range    | Source            | Description
        Custom TCP  | TCP       | 2376          | SECURITY_GROUP_ID | Gitlab runner for Docker Machine to communicate with Docker daemon.
        SSH         | TCP       | 22            | SECURITY_GROUP_ID | SSH access for setup.                        
    ```     
    
8. SSH into the newly created instance. 

    ```bash
    ssh -i ~/saas-starter-kit-uswest2-gitlabrunner.pem ec2-user@ec2-52-36-105-172.us-west-2.compute.amazonaws.com
    ``` 
     Note: If you get the error `Permissions 0666 are too open`, then you will need to `chmod 400 FILENAME`
       
9. Install GitLab Runner from the [official GitLab repository](https://docs.gitlab.com/runner/install/linux-repository.html)
    ```bash 
    curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh | sudo bash
    sudo yum install gitlab-runner
    ``` 
    
10. [Install Docker Community Edition](https://docs.docker.com/install/).
    ```bash 
    sudo yum install docker
    ```
    
11. [Install Docker Machine](https://docs.docker.com/machine/install-machine/).
    ```bash
    base=https://github.com/docker/machine/releases/download/v0.16.0 &&
      curl -L $base/docker-machine-$(uname -s)-$(uname -m) >/tmp/docker-machine &&
      sudo install /tmp/docker-machine /usr/sbin/docker-machine
    ```
    
12. [Register the runner](https://docs.gitlab.com/runner/register/index.html).
    ```bash
    sudo gitlab-runner register
    ```    
    Notes: 
    * When asked for gitlab-ci tags, enter `master,prod,prod-*`
        * This will limit commits to the master or prod branches from triggering the pipeline to run. This includes a 
        wildcard for any branch named with the prefix `prod-`.
    * When asked the executor type, enter `docker+machine`
    * When asked for the default Docker image, enter `geeksaccelerator/docker-library:golang1.12-docker`
        
13. [Configuring the GitLab Runner](https://docs.gitlab.com/runner/configuration/runner_autoscale_aws/#configuring-the-gitlab-runner)   

    ```bash
    sudo vim /etc/gitlab-runner/config.toml
    ``` 
    
    Update the `[runners.docker]` configuration section in `config.toml` to match the example below replacing the 
    obvious placeholder `XXXXX` with the relevant value. 
    ```yaml
      [runners.docker]
        tls_verify = false
        image = "geeksaccelerator/docker-library:golang1.12-docker"
        privileged = true
        disable_entrypoint_overwrite = false
        oom_kill_disable = false
        disable_cache = true
        volumes = ["/cache"]
        shm_size = 0
      [runners.cache]
        Type = "s3"
        Shared = true
        [runners.cache.s3]
          ServerAddress = "s3.us-west-2.amazonaws.com"
          BucketName = "XXXXX"
          BucketLocation = "us-west-2"
      [runners.machine]
        IdleCount = 0
        IdleTime = 1800
        MachineDriver = "amazonec2"
        MachineName = "gitlab-runner-machine-%s"
        MachineOptions = [
          "amazonec2-iam-instance-profile=SaasStarterKitEc2RoleForGitLabRunner",
          "amazonec2-region=us-west-2",
          "amazonec2-vpc-id=XXXXX",
          "amazonec2-subnet-id=XXXXX",
          "amazonec2-zone=d",
          "amazonec2-use-private-address=true",
          "amazonec2-tags=runner-manager-name,gitlab-aws-autoscaler,gitlab,true,gitlab-runner-autoscale,true",
          "amazonec2-security-group=gitlab-runner",
          "amazonec2-instance-type=t2.large"
        ]                         
    ```  
    
    You will need use the same VPC subnet and availability zone as the instance launched in step 2. We are using AWS 
    region `us-west-2`. The _ServerAddress_ for S3 will need to be updated if the region is changed. For `us-east-1` the
    _ServerAddress_ is `s3.amazonaws.com`. Under MachineOptions you can add anything that the [AWS Docker Machine](https://docs.docker.com/machine/drivers/aws/#options) 
    driver supports.
     
    Below are some example values for the placeholders to ensure for format of your values are correct. 
    ```yaml
    BucketName = saas-starter-kit-usw
    amazonec2-vpc-id=vpc-5f43f027
    amazonec2-subnet-id=subnet-693d3110
    amazonec2-zone=a
    ``` 
    
    Once complete, restart the runner.
    ```bash 
    sudo gitlab-runner restart
    ``` 



## Usage  

You can execute the _cicd_ command locally as an alternative to having GitLab CI/CD execute the commands. Before you 
are able to run the build and deploy sub commands, you will need an AWS access/secret key. 

```bash
$ cicd help
NAME:
   cicd - Provides build and deploy for GitLab to Amazon AWS

USAGE:
   cicd [global options] command [command options] [arguments...]

VERSION:
   1.0

COMMANDS:
   build, b   build a service or function
   deploy, d  deploy a service or function
   schema, s  manage the database schema
   help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --env value             target environment, one of [dev, stage, prod]
   --aws-access-key value  AWS Access Key [$AWS_ACCESS_KEY_ID]
   --aws-secret-key value  AWS Secret Key [$AWS_SECRET_ACCESS_KEY]
   --aws-region value      AWS Region [$AWS_REGION]
   --aws-use-role          Use an IAM Role else AWS Access/Secret Keys are required [$AWS_USE_ROLE]
   --help, -h              show help
   --version, -v           print the version
```
Refer to the _cicd_ [readme](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/build/cicd#usage) for full 
command details 


### AWS Permissions 

Create an AWS user for development purposes. This user is not needed for the build pipeline using GitLab CI/CD.

1. You will need an existing AWS account or create a new AWS account.

2. Define a new [AWS IAM Policy](https://console.aws.amazon.com/iam/home?region=us-west-2#/policies$new?step=edit) 
called `saas-starter-kit-deploy` with a defined JSON statement instead of using the visual editor. The statement is 
rather large as each permission is granted individually. A copy of the statement is stored in the repo at 
[configs/aws-aim-deploy-policy.json](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/configs/aws-aim-deploy-policy.json)

3. Create new [AWS User](https://console.aws.amazon.com/iam/home?region=us-west-2#/users$new?step=details) 
called `saas-starter-kit-deploy` with _Programmatic Access_ and _Attach existing policies directly_ with the policy 
created from step 2 `saas-starter-kit-deploy`

4. Set your AWS credentials as [environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html). 
These can also be passed into _cicd_ as command line options. 
```bash
export AWS_ACCESS_KEY_ID=XXXXXXXXX
export AWS_SECRET_ACCESS_KEY=XXXXXXXXX
export AWS_REGION="us-west-2"
export AWS_USE_ROLE=false
```


## Contributions

We :heart: contributions.

Have you had a good experience with `devops` ? Why not share some love and contribute code?

Thank you to all those that have contributed to this project and are using it in their projects. You can find a 
CONTRIBUTORS file where we keep a list of contributors to the project. If you contribute a PR please consider adding 
your name there. 


## Join us on Gopher Slack

If you are having problems installing, getting the project running, or would like to contribute, join the         
channel #saas-starter-kit on [Gopher Slack](http://invite.slack.golangbridge.org/)


## License

Please read the [LICENSE](./LICENSE) file here.


Copyright 2019, Geeks Accelerator 
twins@geeksaccelerator.com
