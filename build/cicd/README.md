
cicd 
=== 

_cicd_ is a simple command line tool that facilitates build and deployment for your project. The goal is to help enable 
developers to easily setup a continuous build pipeline using [GitLab CI/CD](https://docs.gitlab.com/ee/ci/) and code 
driven deployment. 

<!-- toc -->

- [Overview](#overview)
    * [Deployment Environments](#deployment-environments)
    * [Services](#services)
    * [Functions](#functions)
    * [Schema Migrations](#schema-migrations)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Usage](#usage)
    * [Commands](#commands)
    * [Examples](#examples)
- [Join us on Gopher Slack](#join-us-on-gopher-slack)

<!-- tocstop -->



## Overview

The command line tool provides the functionality to configure, build and deploy your code. When new code is push to GitLab, 
this tool will enable building, testing and deploying your code to [Amazon AWS](https://aws.amazon.com/). 
 
Deploying your code to production always requires additional tooling and configuration. Instead of patching together a 
system of of existing tools and configuration files centralizes configuration for the application and any 
additional deployment resources needed. 

Configuration is defined with code. AWS resources are created/maintained using the [AWS SDK for Go](https://docs.aws.amazon.com/sdk-for-go/api/).

**This tool is used by GitLab CI/CD** and is configured by a file called .gitlab-ci.yml placed at the repository’s root. 

**All code is deployed to Amazon AWS**. 

Check out the [full presentation](https://docs.google.com/presentation/d/1sRFQwipziZlxBtN7xuF-ol8vtUqD55l_4GE-4_ns-qM/edit?usp=sharing) 
that covers how to setup your [GitLab CI/CD](https://docs.gitlab.com/ee/ci/) pipeline that uses autoscaling GitLab 
Runners on AWS.

Support is provided for both services and functions. The build process for both relies on docker and thus, neither are 
required to be written in go. 

Configuration for build and deploy is provided by 
[gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy](https://godoc.org/gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy)

For additional details regarding this tool, refer to 
[gitlab.com/geeks-accelerator/oss/devops](https://gitlab.com/geeks-accelerator/oss/devops)



### Deployment Environments 

All configuration for the deployment environments is defined in code that is located in the 
[internal/config](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/build/cicd/internal/config) package. 
Multiple development environments can easily be configured for more control. 
 
This tool supports three target deployment environments: 
* dev
* stage 
* prod 

Additional deployment resources will need be configured:
* S3 buckets
* RDS postgres database
* Redis elastic cache cluster  

Secrets and other credentials are stored in [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).
 
 

### Services 
Services are generally applications that will need to be long running or continuously available. An example 
[web API](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples/aws-ecs-go-web-api) deployed as service 
is provided by the devops project in [examples](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples). 

The [Dockerfile](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/examples/aws-ecs-go-web-api/Dockerfile) for 
the example service is defined as [multi-stage build](https://docs.docker.com/develop/develop-images/multistage-build/) 
that includes building a base layer, running unittests and compiling the go application as static binary. The final 
layer in the multi-stage uses [alpine:3.9](https://hub.docker.com/_/alpine?tab=description) as its base image and copies 
in the compiled binary resulting in a docker container that is around 50mbs excluding any additional static assets. It's 
possible to swap out `alpine:3.9` with [busybox](https://willschenk.com/articles/2019/building_a_slimmer_go_docker_container/) 
for an even small resulting docker image. 

A service is built using the defined Dockerfile. The resulting image is pushed to 
[Amazon Elastic Container Registry](https://aws.amazon.com/ecr/). 

    Amazon Elastic Container Registry (ECR) is a fully-managed Docker container registry that makes it easy for 
    developers to store, manage, and deploy Docker container images. Amazon ECR is integrated with Amazon Elastic 
    Container Service (ECS) simplifying the development to production workflow. 
 
A service is configured for deployment in [services.go](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/build/cicd/internal/config/service.go).
Services are deployed to [AWS Fargate](https://aws.amazon.com/fargate/) based on the defined task definition. 
    
    AWS Fargate is a compute engine for Amazon ECS that allows you to run containers without having to manage servers or 
    clusters. With AWS Fargate, you no longer have to provision, configure, and scale clusters of virtual machines to 
    run containers.  
 
If the docker file is a multi-stage build and it contains a stage with the name `build_base_golang`, additional caching 
will be implemented to reduce build times. The build command assumes for a stage named `build_base_golang` assumes that 
the stage will run `go mod download` to pull down all package dependencies. The build command computes a checksum for the 
project `go.sum` and then executes a docker build that targets the specific stage `build_base_golang`. The built container 
image is tagged with the go.mod hash and pushed to the projects 
[GitLab repository](https://docs.gitlab.com/ee/user/project/repository/). 

    When Go modules are enabled for the project, it includes a `go.sum` that provides checksums-trees for dependencies. 
    The same resulting checksum means that the go mod download result will be the same and is safe to use the same 
    base image again from cache. 
      

### Functions 

Functions are applications that can be executed in short period of time. An python script for 
[Datadog Log Collection](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples/datadog-lambda-logcollector) 
deployed as a function is provided by the devops project in 
[examples]((https://gitlab.com/geeks-accelerator/oss/devops/tree/master/examples). 

A function is built using the defined 
[Dockerfile](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/examples/datadog-lambda-logcollector/Dockerfile).

 The `Dockerfile` should use a [lambdaci image](https://hub.docker.com/r/lambci/lambda/) as the base image. 
  
  Lambdaci images provide a sandboxed local environment that replicates the live AWS Lambda environment almost 
  identically – including installed software and libraries, file structure and permissions, environment variables, 
  context objects and behaviors – even the user and running process are the same.
  
The build command then uses `docker cp` to extract all files from the resulting container image that are located in 
`/var/task`. These files are zipped and uploaded to AWS S3 for deployment. 

A function is configured for deployment in [functions.go](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/build/cicd/internal/config/function.go).
Functions are deployed to [AWS Lambda](https://aws.amazon.com/lambda/).

    AWS Lambda lets you run code without provisioning or managing servers. You pay only for the compute time you consume 
    - there is no charge when your code is not running. 


### Schema Migrations 

_cicd_ includes a minimalistic database migration script that implements 
[github.com/geeks-accelerator/sqlxmigrate](https://godoc.org/github.com/geeks-accelerator/sqlxmigrate). It provides 
schema versioning and migration rollback. The schema for the entire project is defined globally and is located inside 
internal: [internal/schema](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/build/cicd/internal/schema) 

The example schema package provides two separate methods for handling schema migration:
* [Migrations](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/build/cicd/internal/schema/migrations.go) -
List of direct SQL statements for each migration with defined version ID. A database table is created to persist 
executed migrations. Upon run of each schema migration run, the migration logic checks the migration database table to 
check if it’s already been executed. Thus, schema migrations are only ever executed once. Migrations are defined as a 
function to enable complex migrations so results from query manipulated before being piped to the next query. 

* [Init Schema](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/build/cicd/internal/schema/init_schema.go) - 
If you have a lot of migrations, it can be a pain to run all them. For example, when you are deploying a new instance of 
the app into a clean database. To prevent this, use the initSchema function that will run as-if no migration was run 
before (in a new clean database). 

Another bonus with the globally defined schema is that it enables your testing package the ability to dynamically spin 
up database containers on-demand and automatically include all the migrations. This allows the testing package to 
programmatically execute schema migrations before running any unit tests. 



## Installation

Make sure you have a working Go environment.  Go version 1.2+ is supported.  [See
the install instructions for Go](http://golang.org/doc/install.html).


To install _cicd_, simply run:
```
$ go get gitlab.com/geeks-accelerator/oss/devops/build/cicd
```

Make sure your `PATH` includes the `$GOPATH/bin` directory so your commands can
be easily used:
```
export PATH=$PATH:$GOPATH/bin
```



## Getting Started 

_cicd_ requires AWS permissions to be executed locally. For the GitLab CI/CD build pipeline, AWS roles will be used. This 
user is only necessary for running _cicd_ locally. 

1. You will need an existing AWS account or create a new AWS account.

2. Define a new [AWS IAM Policy](https://console.aws.amazon.com/iam/home?region=us-west-2#/policies$new?step=edit) 
called `saas-starter-kit-deploy` with a defined JSON statement instead of using the visual 
editor. The statement is rather large as each permission is granted individually. A copy of 
the statement is stored in the devops repo at 
[configs/aws-aim-deploy-policy.json](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/configs/aws-aim-deploy-policy.json)

3. Create new [AWS User](https://console.aws.amazon.com/iam/home?region=us-west-2#/users$new?step=details) 
called `saas-starter-kit-deploy` with _Programmatic Access_ and _Attach existing policies directly_ with the policy 
created from step 1 `saas-starter-kit-deploy`


4. Try running the build for a single service. 
```bash
cicd --env=dev build service --name=aws-ecs-go-web-api --release-tag=testv1
```

4. Try running the deploy for a single service. 
```bash
cicd --env=dev deploy service --name=aws-ecs-go-web-api --release-tag=testv1
```



## Usage 

```bash
$ cicd [global options] command [command options] [arguments...]
```

### Global Options 

* Target Environment - __required__ 

    `--env [dev|stage|prod]` 

* AWS Access Key - optional or can be set via env variable `AWS_ACCESS_KEY_ID`

    `--aws-access-key value` 

* AWS Secret Key - optional, can be set via env variable `AWS_SECRET_ACCESS_KEY`

    `--aws-secret-key value`   

* AWS Region - optional, can be set via env variable `AWS_DEFAULT_REGION`

    `--aws-region value`

* AWS Use Role - optional, can be set via env variable `AWS_USE_ROLE`, when enabled an IAM Role else AWS 
Access/Secret Keys are required

* Show help 

    `--help, -h`  

* Print the version 

   `--version, -v`  

### Commands

* `build service` - Executes a build for a single service   
   
    ```bash
    $ cicd -env [dev|stage|prod] build service -name NNNNN [command options]
    ``` 
    
    Options: 
    ```bash
    --name value, -n value            target service, required
    --release-tag value, --tag value  optional tag to override default CI_COMMIT_SHORT_SHA
    --dry-run                         print out the build details
    --no-cache                        skip caching for the docker build
    --no-push                         disable pushing release image to remote repository
    ``` 

* `build function` - Executes a build for a single function   
   
    ```bash
    $ cicd -env [dev|stage|prod] build function -name NNNNN [command options]
    ``` 
    
    Options: 
    ```bash
    --name value, -n value            target function, required
    --release-tag value, --tag value  optional tag to override default CI_COMMIT_SHORT_SHA
    --dry-run                         print out the build details
    --no-cache                        skip caching for the docker build
    --no-push                         disable pushing release image to remote repository
    ```
   
* `deploy infrastructure` - Executes a deploy to setup the infrastructure for the deployment environment.
      
    ```bash
    $ cicd -env [dev|stage|prod] deploy infrastructure [command options]
    ``` 
    
    Options: 
    ```bash
    --dry-run                         print out the deploy details
    ```    
   
* `deploy service` - Executes a deploy for a single service
      
    ```bash
    $ cicd -env [dev|stage|prod] deploy service -name NNNNN [command options]
    ``` 
    
    Options: 
    ```bash
    --name value, -n value            target service, one of [aws-ecs-go-web-api]
    --release-tag value, --tag value  optional tag to override default CI_COMMIT_SHORT_SHA
    --dry-run                         print out the deploy details
    ``` 
       
* `deploy function` - Executes a deploy for a single function 
      
    ```bash
    $ cicd -env [dev|stage|prod] deploy function -name NNNNN [command options]
    ``` 
    
    Options: 
    ```bash
    --name value, -n value            target function, required
    --release-tag value, --tag value  optional tag to override default CI_COMMIT_SHORT_SHA
    --dry-run                         print out the deploy details
    ``` 
            
* `schema` - Runs the database migration using credentials from AWS Secrets Manager. 

    ```bash
    $ cicd -env [dev|stage|prod] schema
    ``` 
    
* `help` - Shows a list of commands
       
    ```bash
    $ cicd help
    ```
        
    Or for one command:    
    ```bash
    $ cicd build help
    ```

### Examples


Setup the infrastructure for _dev_
```bash
$ cicid --env=dev deploy infrastructure --dry-run=false
```

Build the example service _aws-ecs-go-web-api_ 
```bash
$ cicid --env=dev build service --name=aws-ecs-go-web-api --release-tag=testv1 --dry-run=false
```

Deploy the example service _aws-ecs-go-web-api_ 
```bash
$ cicid --env=dev deploy service --name=aws-ecs-go-web-api --release-tag=testv1 --dry-run=false
```


## Join us on Gopher Slack

If you are having problems installing, troubles getting the project running or would like to contribute, join the 
channel #saas-starter-kit on [Gopher Slack](http://invite.slack.golangbridge.org/) 
