// Go: only the security-TODO rule covers Go so far.
package handlers

import (
	"database/sql"
	"fmt"
	"os/exec"
)

// TODO: add authentication before release  expect[VIBE054]
// TODO: rename package  safe[VIBE054]
func Get(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)) // miss[VIBE013] SQL injection in Go
	exec.Command("sh", "-c", "convert "+id).Run()                  // miss[VIBE011] shell injection in Go
}
