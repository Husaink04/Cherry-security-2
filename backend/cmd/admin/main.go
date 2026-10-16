package main

import (
	"bufio"
	"cherrysecurity/internal/app"
	"context"
	"fmt"
	"golang.org/x/term"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Fatal("bootstrap requires an interactive terminal; passwords must not be passed as command arguments")
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Product Owner email: ")
	email, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("email input failed")
	}
	fmt.Print("Product Owner password (14–72 bytes): ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatal("password input failed")
	}
	fmt.Print("Confirm password: ")
	confirmation, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil || string(password) != string(confirmation) {
		log.Fatal("passwords do not match")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := app.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("invalid database configuration")
	}
	defer db.Close()
	if err = app.BootstrapOwner(ctx, db, strings.TrimSpace(email), string(password)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Product Owner created. No default password has been stored in source.")
}
