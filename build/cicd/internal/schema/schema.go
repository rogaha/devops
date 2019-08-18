package schema

import (
	"context"
	"log"

	"github.com/geeks-accelerator/sqlxmigrate"
	"github.com/jmoiron/sqlx"
)

func Migrate(ctx context.Context, masterDb *sqlx.DB, log *log.Logger, isUnittest bool) error {
	// Load list of Schema migrations and init new sqlxmigrate client
	migrations := migrationList(ctx, masterDb, log, isUnittest)
	m := sqlxmigrate.New(masterDb, sqlxmigrate.DefaultOptions, migrations)
	m.SetLogger(log)

	// Append any schema that need to be applied if this is a fresh migration
	// ie. the migrations database table does not exist.
	m.InitSchema(initSchema(ctx, masterDb, log, isUnittest))

	// Execute the migrations
	return m.Migrate()
}
