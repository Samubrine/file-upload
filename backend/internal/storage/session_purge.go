package storage

import (
	"context"
	"database/sql"
	"time"
)

// purgeExpiredSessions deletes sessions whose expiry has passed.
func (db *DB) purgeExpiredSessions() error {
	return db.WithTx(context.Background(), func(tx *sql.Tx) error {
		return db.PurgeExpiredSessions(tx)
	})
}

// StartSessionPurge deletes expired sessions every interval until ctx is done.
func (db *DB) StartSessionPurge(ctx context.Context, every time.Duration) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = db.purgeExpiredSessions()
			}
		}
	}()
}
