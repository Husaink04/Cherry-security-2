package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"cherrysecurity/agent/internal/agent"
)

func main() {
	flags := flag.NewFlagSet("CherrySecurityHelper", flag.ContinueOnError)
	configPath := flags.String("config", "", "absolute path to agent.json")
	if err := flags.Parse(os.Args[1:]); err != nil || *configPath == "" {
		os.Exit(2)
	}
	config, err := agent.LoadConfig(*configPath)
	if err != nil {
		os.Exit(1)
	}
	binding, err := agent.CurrentSessionBinding(config)
	if err != nil {
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err = agent.RunHelper(ctx, binding); err != nil {
		os.Exit(1)
	}
}
