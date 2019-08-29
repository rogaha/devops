package devdeploy

import (
	"log"
	"os"

	"gopkg.in/go-playground/validator.v9"
)

// BuildImageForTargetEnv builds an image using the defined Dockerfile and pushes the image to a local repo.
func BuildImageForTargetEnv(log *log.Logger, cfg *Config, targetImage *ProjectImage, noCache, noPush bool) error {

	log.Printf("Build image %s for environment %s\n", targetImage.Name, cfg.Env)

	if targetImage.DockerBuildDir == "" {
		targetImage.DockerBuildDir = cfg.ProjectRoot
	}

	log.Println("\tValidate request.")
	errs := validator.New().Struct(targetImage)
	if errs != nil {
		return errs
	}

	var releaseDockerLoginCmd []string
	var releaseImage string
	if ciReg := os.Getenv("CI_REGISTRY"); ciReg != "" {
		releaseDockerLoginCmd = []string{
			"docker", "login",
			"-u", os.Getenv("CI_REGISTRY_USER"),
			"-p", os.Getenv("CI_REGISTRY_PASSWORD"),
			ciReg}

		releaseImage = os.Getenv("CI_REGISTRY_IMAGE") + ":" + targetImage.ReleaseTag
	} else {
		releaseImage = cfg.ProjectName + ":" + targetImage.ReleaseTag
		noPush = true
	}

	req := &BuildDockerRequest{
		Env:         cfg.Env,
		ProjectName: cfg.ProjectName,
		Name:        targetImage.Name,

		ReleaseImage: releaseImage,

		BuildDir:           targetImage.DockerBuildDir,
		Dockerfile:         targetImage.Dockerfile,
		DockerBuildContext: targetImage.DockerBuildContext,
		BaseImageTags:      targetImage.BaseImageTags,
		TargetLayer:        targetImage.DockerBuildTargetLayer,

		ReleaseDockerLoginCmd: releaseDockerLoginCmd,

		NoCache: noCache,
		NoPush:  noPush,

		BuildArgs: targetImage.DockerBuildArgs,
	}

	return BuildDocker(log, req)
}
