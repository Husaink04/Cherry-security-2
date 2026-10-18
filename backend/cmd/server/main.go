package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"cherrysecurity/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	origin := os.Getenv("APP_ORIGIN")
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.Path != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		log.Fatal("valid APP_ORIGIN required")
	}
	if parsed.Scheme == "http" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" {
		log.Fatal("HTTP development origin must be loopback; use HTTPS for remote access")
	}
	db, err := app.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("database configuration invalid")
	}
	defer db.Close()
	startup, startupCancel := context.WithTimeout(ctx, 10*time.Second)
	if err = app.CheckSchema(startup, db); err != nil {
		startupCancel()
		log.Fatal("database unavailable or schema incompatible; run the matching migrations")
	}
	if err = app.CheckRuntimeRole(startup, db); err != nil {
		startupCancel()
		log.Fatal("database role bypasses row-level security; connect as the restricted application role")
	}
	startupCancel()
	server := &http.Server{Addr: ":8080", Handler: app.New(db, app.Config{Origin: origin, SecureCookies: parsed.Scheme == "https", TrustProxyHeader: os.Getenv("TRUST_PROXY_HEADER") == "true"}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			if err := app.Cleanup(ctx, db, time.Now().UTC()); err != nil && ctx.Err() == nil {
				log.Print("retention cleanup failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("CherrySecurity API listening on internal port 8080")
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
