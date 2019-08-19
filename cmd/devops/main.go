package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli"
	"github.com/gobuffalo/packr"
)

// service is the name of the program used for logging, tracing, etc.
var service = "DEVOPS"

func main() {

	// =========================================================================
	// Logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix(service + " : ")
	log := log.New(os.Stdout, log.Prefix(), log.Flags())

	// =========================================================================
	// New CLI application.
	app := cli.NewApp()

	app.Commands = []cli.Command{
		// inject is a command used to copy devops files as an example to a target repo.
		{
			Name:    "inject-build",
			Aliases: []string{"ib"},
			Usage:   "copy a build tool to a target repo",
			Subcommands: []cli.Command{
				{
					Name:  "cicd",
					Usage: "copies the build/cicd tool to a target repo",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "project",
							Usage: "the root directory of the project",
							Required: true,
						},
						cli.BoolFlag{
							Name:  "force",
							Usage: "force the files to be copied",
						},
					},
					Action: func(c *cli.Context) error {
						projectDir := c.String("project")
						force := c.Bool("force")

						return injectBuildCicd(projectDir, force)
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

func injectBuildCicd(projectDir string, force bool) error  {

	box := packr.NewBox("../../build/cicd")

	fmt.Println(box.List())

	return nil
}

