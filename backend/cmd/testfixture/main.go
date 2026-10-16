// This command seeds a dedicated _test database only. It cannot seed the application database.
package main

import (
	"cherrysecurity/internal/app"
	"context"
	"encoding/json"
	"flag"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "/src/browser-fixture.json", "private output file; never commit")
	flag.Parse()
	dsn := os.Getenv("TEST_DATABASE_URL")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(config.ConnConfig.Database, "_test") {
		log.Fatal("dedicated TEST_DATABASE_URL ending in _test required")
	}
	if _, err = os.Stat(*out); !os.IsNotExist(err) {
		log.Fatal("refusing to replace existing fixture credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := app.Open(ctx, dsn)
	if err != nil {
		log.Fatal("fixture connection failed")
	}
	defer db.Close()
	if err = app.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	password := app.RandomToken()[:40]
	email := "owner@cherrysecurity.test"
	if err = app.BootstrapOwner(ctx, db, email, password); err != nil {
		log.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"email": email, "password": password, "admin_email": "admin@cherrysecurity.test", "admin_password": app.RandomToken()[:40], "suffix": app.RandomToken()[:8]})
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatal("fixture output creation failed")
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		log.Fatal("fixture output write failed")
	}
	log.Print("Disposable test owner created; credentials written only to private fixture file.")
}
