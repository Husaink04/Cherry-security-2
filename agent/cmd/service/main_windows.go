package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"cherrysecurity/agent/internal/agent"
	"golang.org/x/sys/windows/svc"
)

const pbtAPMSuspend = 0x4 // PBT_APMSUSPEND: the system is about to sleep.

type handler struct{ config agent.Config }

func (service handler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan agent.SystemBoundary, 8)
	config := service.config
	config.SystemEvents = events
	done := make(chan error, 1)
	go func() { done <- agent.RunService(ctx, config) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				err := <-done
				if err != nil {
					return true, 1
				}
				return false, 0
			case svc.PowerEvent:
				if request.EventType == pbtAPMSuspend {
					// Never block the control handler; a full buffer drops only this boundary.
					select {
					case events <- agent.SystemBoundary{State: "suspended", At: time.Now().UTC()}:
					default:
					}
				}
			case svc.Interrogate:
				changes <- request.CurrentStatus
			}
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

func main() {
	flags := flag.NewFlagSet("CherrySecurityAgent", flag.ContinueOnError)
	configPath := flags.String("config", "", "absolute path to agent.json")
	if err := flags.Parse(os.Args[1:]); err != nil || *configPath == "" {
		os.Exit(2)
	}
	config, err := agent.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	service, err := svc.IsWindowsService()
	if err != nil {
		os.Exit(1)
	}
	if service {
		if err = svc.Run("CherrySecurityAgent", handler{config: config}); err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err = agent.RunService(ctx, config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
