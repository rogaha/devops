package main

import (
	"log"
	"os"

	"geeks-accelerator/oss/devops/build/cicd/internal/config"
	"geeks-accelerator/oss/devops/pkg/devdeploy"
	"github.com/urfave/cli"
)

// service is the name of the program used for logging, tracing, etc.
var service = "CICD"

func main() {

	// =========================================================================
	// Logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix(service + " : ")
	log := log.New(os.Stdout, log.Prefix(), log.Flags())

	// =========================================================================
	// New CLI application.
	app := cli.NewApp()

	// Define global CLI flags.
	var awsCredentials devdeploy.AwsCredentials
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:     "env",
			Usage:    "target environment",
			Required: true,
		},
		cli.StringFlag{
			Name:        "aws-access-key",
			Usage:       "AWS Access Key",
			EnvVar:      "AWS_ACCESS_KEY_ID",
			Destination: &awsCredentials.AccessKeyID,
		},
		cli.StringFlag{
			Name:        "aws-secret-key",
			Usage:       "AWS Secret Key",
			EnvVar:      "AWS_SECRET_ACCESS_KEY",
			Destination: &awsCredentials.SecretAccessKey,
		},
		cli.StringFlag{
			Name:        "aws-region",
			Usage:       "AWS Region",
			EnvVar:      "AWS_REGION",
			Destination: &awsCredentials.Region,
		},
		cli.BoolFlag{
			Name:        "aws-use-role",
			Usage:       "target environment",
			EnvVar:      "AWS_USE_ROLE",
			Destination: &awsCredentials.UseRole,
		},
	}

	app.Commands = []cli.Command{
		// Build command for services and functions.
		{
			Name:    "build",
			Aliases: []string{"b"},
			Usage:   "build a service or function",
			Subcommands: []cli.Command{
				{
					Name:  "service",
					Usage: "build a service",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:     "name, n",
							Required: true,
						},
						cli.StringFlag{
							Name:  "release-tag, tag",
							Usage: "target environment",
						},
						cli.BoolFlag{
							Name:  "dry-run",
							Usage: "print out the build details",
						},
						cli.BoolFlag{
							Name:  "no-cache",
							Usage: "skip caching for the docker build",
						},
						cli.BoolFlag{
							Name:  "no-push",
							Usage: "disable pushing release image to remote repository",
						},
					},
					Action: func(c *cli.Context) error {
						targetEnv := c.GlobalString("env")
						serviceName := c.String("name")
						releaseTag := c.String("release-tag")
						dryRun := c.Bool("dry-run")
						noCache := c.Bool("no-cache")
						noPush := c.Bool("no-push")

						return config.BuildServiceForTargetEnv(log, awsCredentials, targetEnv, serviceName, releaseTag, dryRun, noCache, noPush)
					},
				},
				{
					Name:  "function",
					Usage: "build a function",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:     "name, n",
							Required: true,
						},
						cli.StringFlag{
							Name:  "release-tag, tag",
							Usage: "target environment",
						},
						cli.BoolFlag{
							Name:  "dry-run",
							Usage: "print out the build details",
						},
						cli.BoolFlag{
							Name:  "no-cache",
							Usage: "skip caching for the docker build",
						},
						cli.BoolFlag{
							Name:  "no-push",
							Usage: "disable pushing release image to remote repository",
						},
					},
					Action: func(c *cli.Context) error {
						targetEnv := c.GlobalString("env")
						funcName := c.String("name")
						releaseTag := c.String("release-tag")
						dryRun := c.Bool("dry-run")
						noCache := c.Bool("no-cache")
						noPush := c.Bool("no-push")

						return config.BuildFunctionForTargetEnv(log, awsCredentials, targetEnv, funcName, releaseTag, dryRun, noCache, noPush)
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
