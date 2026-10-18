package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"cherrysecurity/agent/internal/agent"
	"golang.org/x/sys/windows"
)

func hiddenLine(prompt string) ([]byte, error) {
	handle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return nil, err
	}
	var mode uint32
	if err = windows.GetConsoleMode(handle, &mode); err != nil {
		return nil, errors.New("interactive console required")
	}
	fmt.Fprint(os.Stderr, prompt)
	if err = windows.SetConsoleMode(handle, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	defer windows.SetConsoleMode(handle, mode)
	line, err := bufio.NewReaderSize(os.Stdin, 256).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(line)), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	action := flag.String("action", "plan", "plan, install, enroll, or uninstall")
	endpoint := flag.String("endpoint", "", "agent HTTPS origin")
	userSID := flag.String("user-sid", "", "selected employee SID")
	serviceBinary := flag.String("service", "", "absolute service executable path")
	helperBinary := flag.String("helper", "", "absolute helper executable path")
	controlBinary := flag.String("control", "", "absolute control executable path")
	caCertificate := flag.String("ca", "", "absolute scoped CA certificate path")
	configPath := flag.String("config", "", "absolute installed agent.json path")
	deleteData := flag.Bool("delete-data", false, "also delete CherrySecurity data")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch *action {
	case "plan", "install":
		plan, err := agent.PlanInstall(agent.InstallOptions{Endpoint: *endpoint, UserSID: *userSID, ServiceBinary: *serviceBinary, HelperBinary: *helperBinary, ControlBinary: *controlBinary, CACertificate: *caCertificate})
		if err != nil {
			fail(err)
		}
		encoded, _ := json.MarshalIndent(plan, "", "  ")
		fmt.Println(string(encoded))
		if *action == "install" {
			if err = agent.ApplyInstall(ctx, plan); err != nil {
				fail(err)
			}
			fmt.Println("CherrySecurity Agent installed. Enrollment is still required.")
		}
	case "enroll":
		config, err := agent.LoadConfig(*configPath)
		if err != nil {
			fail(err)
		}
		serviceIdentity, err := agent.ServiceIdentity()
		if err != nil {
			fail(err)
		}
		key, err := hiddenLine("Enrollment key: ")
		if err != nil {
			fail(err)
		}
		defer clear(key)
		if err = agent.RequestEnrollment(ctx, agent.SessionBinding{ServiceSID: serviceIdentity, ServicePath: config.ServicePath}, key); err != nil {
			fail(err)
		}
		fmt.Println("CherrySecurity Agent enrolled.")
	case "uninstall":
		if err := agent.Uninstall(ctx, !*deleteData); err != nil {
			fail(err)
		}
		fmt.Println("CherrySecurity Agent uninstalled.")
	default:
		fail(errors.New("unknown action"))
	}
}
