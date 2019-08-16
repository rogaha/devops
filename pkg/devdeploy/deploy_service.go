package devdeploy

import (
	"github.com/pkg/errors"
	"path/filepath"
)

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


