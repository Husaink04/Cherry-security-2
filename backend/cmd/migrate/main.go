package main

import (
	"cherrysecurity/internal/app"
	"context"
	"log"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := app.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("invalid database configuration")
	}
	defer db.Close()
	if err = app.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	if os.Getenv("GRANT_APP_ROLE") == "true" {
		_, err = db.Exec(ctx, "GRANT USAGE ON SCHEMA public TO cherryapp; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO cherryapp")
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("CherrySecurity schema ready (version %d)", app.SchemaVersion)
}
