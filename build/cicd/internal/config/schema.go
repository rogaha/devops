package config

import (
	"context"
	"log"

	"geeks-accelerator/oss/devops/build/cicd/internal/schema"
	"geeks-accelerator/oss/devops/pkg/devdeploy"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

// RunSchemaMigrationsForTargetEnv executes the build commands for a target service.
func RunSchemaMigrationsForTargetEnv(log *log.Logger, awsCredentials devdeploy.AwsCredentials, targetEnv Env, isUnittest bool) error {

	cfgCtx, err := NewConfigContext(targetEnv, awsCredentials)
	if err != nil {
		return err
	}

	cfg, err := cfgCtx.Config(log)
	if err != nil {
		return err
	}

	err = devdeploy.SetupDeploymentEnv(log, cfg)
	if err != nil {
		return err
	}

	masterDb, err := sqlx.Open(cfg.DBConnInfo.Driver, cfg.DBConnInfo.URL())
	if err != nil {
		return errors.WithMessage(err, "Failed to connect to db for schema migration.")
	}
	defer masterDb.Close()

	return schema.Migrate(context.Background(), masterDb, log, false)
}
