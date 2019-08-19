package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gobuffalo/packr/v2"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy"
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
							Name:     "project",
							Usage:    "the root directory of the project",
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
func injectBuildCicd(log *log.Logger, projectDir string, force bool) error {

	// Ensure the project directory is valid.
	stat, err := os.Stat(projectDir)
	if err != nil {
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
	curImportPath := "gitlab.com/geeks-accelerator/oss/devops/build/cicd"

	// Load the go module details for the target project.
	projectDetails, err := devdeploy.LoadModuleDetails(projectDir)
	if err != nil {
		return err
	}

	// Determine that the new import path should be for the project that will be used by main.go to import internal/config.
	newImportPath := filepath.Join(projectDetails.GoModName, "build/cicd")
	log.Printf("Replacing package import '%s' with '%s'\n", curImportPath, newImportPath)

	// The actual file directory new files will be copied to.
	targetDir := filepath.Join(projectDir, "build/cicd")
	err = os.MkdirAll(targetDir, os.ModePerm)
	if err != nil {
		return errors.WithMessagef(err, "Failed to create target directory '%s'.", targetDir)
	}
	log.Printf("Writing files to '%s'\n", targetDir)

	// List of values that will be replaced in the files being copied.
	replacements := map[string]string{
		curImportPath: newImportPath,
	}

	// List of path prefixes that should be not be copied to target project.
	var skipPaths []string

	// If the project already has a schema folder, assume its what we are looking for and use that instead.
	schemaDir := filepath.Join(projectDir, "internal/schema")
	if _, err := os.Stat(schemaDir); err == nil {
		curSchemaPath := filepath.Join(newImportPath, "internal/schema")
		projectSchemaPath := filepath.Join(projectDetails.GoModName, "internal/schema")

		replacements[curSchemaPath] = projectSchemaPath
		skipPaths = append(skipPaths, "internal/schema")

		log.Printf("Using project schema '%s'\n", projectSchemaPath)

	}

	// The current copy of the build/cicd tool will be used as the template for deploying a copy of the tool to a project.
	// Packr is used to bundle these files when compiling the binary to make it easy for this tool to be installed
	// without having manage templates as some external resource.
	dir := "../../build/cicd"
	box := packr.New("cicd", dir)

	// Loop through all the files in the box and copy each one to the target project.
	for _, f := range box.List() {

		var skipFile bool
		for _, p := range skipPaths {
			if strings.HasPrefix(f, p) {
				skipFile = true
				break
			}
		}
		if skipFile {
			continue
		}

		dat, err := box.FindString(filepath.Join(dir, f))
		if err != nil {
			return err
		}

		for k, v := range replacements {
			dat = strings.Replace(dat, k, v, -1)
		}

		newFilePath := filepath.Join(targetDir, f)

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
			err = ioutil.WriteFile(newFilePath, []byte(dat), 0644)
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
