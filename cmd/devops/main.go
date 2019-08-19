package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"geeks-accelerator/oss/devops/pkg/devdeploy"
	"github.com/urfave/cli"
	"github.com/gobuffalo/packr/v2"
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

						return injectBuildCicd(log, projectDir, force)
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

// injectBuildCicd copies the example build/cicd tool to a target repo.
func injectBuildCicd(log *log.Logger, projectDir string, force bool) error  {

	// Ensure the project directory is valid.
	stat, err := os.Stat(projectDir)
	if err != nil  {
		return errors.WithMessagef(err, "Target project must be a directory")
	} else if !stat.IsDir() {
		return errors.Errorf("Target '%s' is not a directory")
	}

	if !filepath.IsAbs(projectDir) {
		projectDir, err = filepath.Abs(projectDir)
		if err != nil {
			return err
		}
	}

	// The current import path used for the tool that will need to be replaced.
	curImportPath := "geeks-accelerator/oss/devops/build/cicd"

	// Load the go module details for the target project.
	projectDetails, err := devdeploy.LoadModuleDetails(projectDir)
	if err != nil {
		return err
	}

	newImportPath := filepath.Join(projectDetails.GoModName, "build/cicd")
	log.Printf("Replacing package import '%s' with '%s'\n", curImportPath, newImportPath)

	targetDir := filepath.Join(projectDir,"build/cicd")
	err = os.MkdirAll(targetDir, os.ModePerm)
	if err != nil {
		return errors.WithMessagef(err, "Failed to create target directory '%s'.", targetDir)
	}
	log.Printf("Writing files to '%s'\n", targetDir)

	dir := "../../build/cicd"
	box := packr.New("cicd", dir)

	for _, f := range box.List() {

		dat, err := box.FindString(filepath.Join(dir, f))
		if err != nil {
			return err
		}
		dat = strings.Replace(dat, curImportPath, newImportPath, - 1)

		newFilePath := filepath.Join(targetDir, f )

		if _, err := os.Stat(newFilePath); err != nil {
			if !os.IsNotExist(err) {
				return err
			}

			// Ensure the directory for the new file exists.
			fileDir := filepath.Dir(newFilePath)
			err = os.MkdirAll(fileDir, os.ModePerm)
			if err != nil {
				return errors.WithMessagef(err, "Failed to create file directory '%s'.", fileDir)
			}

			// Write the new file.
			err = ioutil.WriteFile(newFilePath, []byte( dat), 0644)
			if err != nil {
				return errors.WithMessagef(err, "Failed to write file '%s'", newFilePath)
			}
			log.Printf("\t%s created\n", f)
		} else {
			log.Printf("\t%s already exists, skipping\n", f)
		}
	}

	return nil
}
