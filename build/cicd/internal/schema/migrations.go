package schema

import (
	"context"
	"database/sql"
	"log"

	"github.com/geeks-accelerator/sqlxmigrate"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
)

// migrationList returns a list of migrations to be executed. If the id of the
// migration already exists in the migrations table it will be skipped.
func migrationList(ctx context.Context, db *sqlx.DB, log *log.Logger, isUnittest bool) []*sqlxmigrate.Migration {
	return []*sqlxmigrate.Migration{
		// Create table users.
		{
			ID: "20190818-01",
			Migrate: func(tx *sql.Tx) error {
				q1 := `CREATE TABLE IF NOT EXISTS users (
					  id char(36) NOT NULL,
					  email varchar(200) NOT NULL,
					  name varchar(200) NOT NULL DEFAULT '',
					  password_hash varchar(256) NOT NULL,
					  password_salt varchar(36) NOT NULL,
					  password_reset varchar(36) DEFAULT NULL,
					  timezone varchar(128) NOT NULL DEFAULT 'America/Anchorage',
					  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
					  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
					  archived_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
					  PRIMARY KEY (id),
					  CONSTRAINT email UNIQUE  (email)
					) ;`
				if _, err := tx.Exec(q1); err != nil {
					return errors.Wrapf(err, "Query failed %s", q1)
				}
				return nil
			},
			Rollback: func(tx *sql.Tx) error {
				q1 := `DROP TABLE IF EXISTS users`
				if _, err := tx.Exec(q1); err != nil {
					return errors.Wrapf(err, "Query failed %s", q1)
				}
				return nil
			},
		},
	}
}
