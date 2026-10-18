package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceManagementACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;AU)"
const installDirectoryACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;AU)"
const dataDirectoryACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)"

var serviceRecovery = [4]uint32{10, 30, 60, 0}

type InstallOptions struct {
	Endpoint      string
	UserSID       string
	ServiceBinary string
	HelperBinary  string
	ControlBinary string
	CACertificate string
}

type InstallPlan struct {
	Endpoint         string
	UserSID          string
	ServiceSource    string
	HelperSource     string
	ControlSource    string
	CASource         string
	InstallDirectory string
	DataDirectory    string
	ServicePath      string
	HelperPath       string
	ControlPath      string
	CAPath           string
	ConfigPath       string
	ServiceSHA256    string
	HelperSHA256     string
	ControlSHA256    string
	CASHA256         string
	ServiceCommand   string
	ServiceName      string
	TaskName         string
}

func PlanInstall(options InstallOptions) (InstallPlan, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return InstallPlan{}, err
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString("CherrySecurityAgent")
	if err != nil {
		return InstallPlan{}, err
	}
	service, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_STATUS)
	if err == nil {
		windows.CloseServiceHandle(service)
		return InstallPlan{}, errors.New("CherrySecurity service already exists")
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return InstallPlan{}, err
	}
	queryContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	taskPresent, err := helperTaskExists(queryContext, "CherrySecurity Session Helper")
	if err != nil {
		return InstallPlan{}, err
	}
	if taskPresent {
		return InstallPlan{}, errors.New("CherrySecurity helper task already exists")
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return InstallPlan{}, err
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return InstallPlan{}, err
	}
	return planInstallAt(options, programFiles, programData)
}

func rejectReparseAncestors(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute path required")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		pointer, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("reparse point in installation path")
		}
		if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return err
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func sourceHash(path string, limit int64) (string, error) {
	if err := rejectReparseAncestors(path); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return "", errors.New("invalid installation source")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit || written != info.Size() {
		return "", errors.New("installation source changed during hash")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func planInstallAt(options InstallOptions, programFiles, programData string) (InstallPlan, error) {
	user, err := windows.StringToSid(options.UserSID)
	if err != nil || user.String() != options.UserSID || !(strings.HasPrefix(options.UserSID, "S-1-5-21-") || strings.HasPrefix(options.UserSID, "S-1-12-1-")) {
		return InstallPlan{}, errors.New("selected user SID required")
	}
	for _, root := range []string{programFiles, programData} {
		if err := rejectReparseAncestors(root); err != nil {
			return InstallPlan{}, err
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() {
			return InstallPlan{}, errors.New("known folder unavailable")
		}
	}
	installDirectory := filepath.Join(programFiles, "CherrySecurity")
	dataDirectory := filepath.Join(programData, "CherrySecurity")
	for _, target := range []string{installDirectory, dataDirectory} {
		if _, err := os.Lstat(target); err == nil {
			return InstallPlan{}, fmt.Errorf("installation target already exists: %s", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return InstallPlan{}, err
		}
	}
	sources := []struct {
		path  string
		limit int64
	}{
		{options.ServiceBinary, 100 << 20}, {options.HelperBinary, 100 << 20},
		{options.ControlBinary, 100 << 20}, {options.CACertificate, 1 << 20},
	}
	var hashes [4]string
	for index, source := range sources {
		hashes[index], err = sourceHash(source.path, source.limit)
		if err != nil {
			return InstallPlan{}, err
		}
	}
	servicePath := filepath.Join(installDirectory, "CherrySecurityAgent.exe")
	config := Config{Endpoint: options.Endpoint, TrustPath: filepath.Join(dataDirectory, "agent-ca.crt"), DataDirectory: dataDirectory, UserSID: options.UserSID, ServicePath: servicePath}
	if err = config.Validate(); err != nil {
		return InstallPlan{}, err
	}
	return InstallPlan{
		Endpoint: options.Endpoint, UserSID: options.UserSID, ServiceSource: options.ServiceBinary, HelperSource: options.HelperBinary,
		ControlSource: options.ControlBinary, CASource: options.CACertificate,
		InstallDirectory: installDirectory, DataDirectory: dataDirectory,
		ServicePath: servicePath, HelperPath: filepath.Join(installDirectory, "CherrySecurityHelper.exe"),
		ControlPath: filepath.Join(installDirectory, "CherrySecurityControl.exe"), CAPath: filepath.Join(dataDirectory, "agent-ca.crt"),
		ConfigPath:    filepath.Join(installDirectory, "agent.json"),
		ServiceSHA256: hashes[0], HelperSHA256: hashes[1], ControlSHA256: hashes[2], CASHA256: hashes[3],
		ServiceCommand: syscall.EscapeArg(servicePath) + " --config " + syscall.EscapeArg(filepath.Join(installDirectory, "agent.json")), ServiceName: "CherrySecurityAgent", TaskName: "CherrySecurity Session Helper",
	}, nil
}

func validateInstallPlan(plan InstallPlan) error {
	if plan.ServiceName != "CherrySecurityAgent" || plan.TaskName != "CherrySecurity Session Helper" || !filepath.IsAbs(plan.InstallDirectory) || !filepath.IsAbs(plan.DataDirectory) {
		return errors.New("invalid install plan")
	}
	checks := []struct {
		path  string
		want  string
		limit int64
	}{
		{plan.ServiceSource, plan.ServiceSHA256, 100 << 20},
		{plan.HelperSource, plan.HelperSHA256, 100 << 20},
		{plan.ControlSource, plan.ControlSHA256, 100 << 20},
		{plan.CASource, plan.CASHA256, 1 << 20},
	}
	for _, check := range checks {
		digest, err := sourceHash(check.path, check.limit)
		if err != nil || digest != check.want {
			return errors.New("installation source integrity check failed")
		}
	}
	for _, target := range []string{plan.InstallDirectory, plan.DataDirectory} {
		if err := rejectReparseAncestors(filepath.Dir(target)); err != nil {
			return err
		}
		if _, err := os.Lstat(target); err == nil {
			return errors.New("installation target already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := (Config{Endpoint: plan.Endpoint, TrustPath: plan.CAPath, DataDirectory: plan.DataDirectory, UserSID: plan.UserSID, ServicePath: plan.ServicePath}).Validate(); err != nil {
		return err
	}
	return nil
}

func descriptorDACL(sddl string) (*windows.ACL, error) {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	dacl, _, err := descriptor.DACL()
	return dacl, err
}

func protectPath(path, sddl string) error {
	dacl, err := descriptorDACL(sddl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func copyExclusive(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err == nil {
		err = output.Sync()
	}
	closeError := output.Close()
	if err != nil {
		return err
	}
	return closeError
}

func writeConfigExclusive(plan InstallPlan) error {
	config := Config{Endpoint: plan.Endpoint, TrustPath: plan.CAPath, DataDirectory: plan.DataDirectory, UserSID: plan.UserSID, ServicePath: plan.ServicePath}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(plan.ConfigPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(encoded); err == nil {
		err = file.Sync()
	}
	closeError := file.Close()
	if err != nil {
		return err
	}
	return closeError
}

func taskExecutable() (string, error) {
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "schtasks.exe"), nil
}

// runTool runs a fixed Windows tool and includes its bounded output in any error, so install failures are diagnosable.
func runTool(command *exec.Cmd) error {
	command.Stdin = nil
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(output))
	if len(text) > 512 {
		text = text[:512]
	}
	return fmt.Errorf("%s failed: %w: %s", filepath.Base(command.Path), err, text)
}

func helperTaskSecurityDescriptor(userSID string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;" + userSID + ")"
}

func protectHelperTask(ctx context.Context, plan InstallPlan) error {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	powerShell := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	script := `$ErrorActionPreference = 'Stop'; $service = New-Object -ComObject 'Schedule.Service'; $service.Connect(); $task = $service.GetFolder('\').GetTask($env:CHERRY_TASK_NAME); $task.SetSecurityDescriptor($env:CHERRY_TASK_SDDL, 0)`
	command := exec.CommandContext(ctx, powerShell, "-NoProfile", "-NonInteractive", "-Command", script)
	command.Env = append(os.Environ(), "CHERRY_TASK_NAME="+plan.TaskName, "CHERRY_TASK_SDDL="+helperTaskSecurityDescriptor(plan.UserSID))
	return runTool(command)
}

const taskXMLHeader = `<?xml version="1.0" encoding="UTF-16"?>` + "\n"

// utf16LEWithBOM encodes task XML the way schtasks /XML reads it; a UTF-8 file fails with "unable to switch the encoding".
func utf16LEWithBOM(text []byte) []byte {
	units := utf16.Encode([]rune(string(text)))
	encoded := make([]byte, 2+2*len(units))
	encoded[0], encoded[1] = 0xFF, 0xFE
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[2+2*index:], unit)
	}
	return encoded
}

func helperTaskXML(plan InstallPlan) ([]byte, error) {
	type logonTrigger struct {
		Enabled bool   `xml:"Enabled"`
		UserID  string `xml:"UserId"`
	}
	type principal struct {
		ID        string `xml:"id,attr"`
		UserID    string `xml:"UserId"`
		LogonType string `xml:"LogonType"`
		RunLevel  string `xml:"RunLevel"`
	}
	type execAction struct {
		Command   string `xml:"Command"`
		Arguments string `xml:"Arguments"`
	}
	type task struct {
		XMLName  xml.Name `xml:"Task"`
		XMLNS    string   `xml:"xmlns,attr"`
		Version  string   `xml:"version,attr"`
		Triggers struct {
			Logon logonTrigger `xml:"LogonTrigger"`
		} `xml:"Triggers"`
		Principals struct {
			Principal principal `xml:"Principal"`
		} `xml:"Principals"`
		Settings struct {
			MultipleInstances  string `xml:"MultipleInstancesPolicy"`
			DisallowBattery    bool   `xml:"DisallowStartIfOnBatteries"`
			StopOnBattery      bool   `xml:"StopIfGoingOnBatteries"`
			AllowTerminate     bool   `xml:"AllowHardTerminate"`
			StartWhenAvailable bool   `xml:"StartWhenAvailable"`
			Enabled            bool   `xml:"Enabled"`
			ExecutionLimit     string `xml:"ExecutionTimeLimit"`
		} `xml:"Settings"`
		Actions struct {
			Context string     `xml:"Context,attr"`
			Exec    execAction `xml:"Exec"`
		} `xml:"Actions"`
	}
	definition := task{XMLNS: "http://schemas.microsoft.com/windows/2004/02/mit/task", Version: "1.4"}
	definition.Triggers.Logon = logonTrigger{Enabled: true, UserID: plan.UserSID}
	definition.Principals.Principal = principal{ID: "SelectedUser", UserID: plan.UserSID, LogonType: "InteractiveToken", RunLevel: "LeastPrivilege"}
	definition.Settings.MultipleInstances = "IgnoreNew"
	definition.Settings.AllowTerminate = true
	definition.Settings.Enabled = true
	definition.Settings.ExecutionLimit = "PT0S"
	definition.Actions.Context = "SelectedUser"
	definition.Actions.Exec = execAction{Command: plan.HelperPath, Arguments: "--config \"" + plan.ConfigPath + "\""}
	encoded, err := xml.MarshalIndent(definition, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(taskXMLHeader), encoded...), nil
}

func createHelperTask(ctx context.Context, plan InstallPlan) error {
	encoded, err := helperTaskXML(plan)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(plan.DataDirectory, "helper-task-*.xml")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err = temporary.Write(utf16LEWithBOM(encoded)); err == nil {
		err = temporary.Sync()
	}
	if closeError := temporary.Close(); err == nil {
		err = closeError
	}
	if err != nil {
		return err
	}
	executable, err := taskExecutable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "/Create", "/TN", plan.TaskName, "/XML", temporaryPath)
	if err = runTool(command); err != nil {
		return err
	}
	if err = protectHelperTask(ctx, plan); err != nil {
		_ = deleteHelperTask(context.Background(), plan.TaskName)
		return err
	}
	return nil
}

func deleteHelperTask(ctx context.Context, taskName string) error {
	executable, err := taskExecutable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "/Delete", "/TN", taskName, "/F")
	return runTool(command)
}

func runHelperTask(ctx context.Context, taskName string) error {
	executable, err := taskExecutable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "/Run", "/TN", taskName)
	return runTool(command)
}

func stopHelperTask(ctx context.Context, taskName string) {
	executable, err := taskExecutable()
	if err != nil {
		return
	}
	command := exec.CommandContext(ctx, executable, "/End", "/TN", taskName)
	command.Stdin = nil
	_ = command.Run()
}

func helperTaskExists(ctx context.Context, taskName string) (bool, error) {
	executable, err := taskExecutable()
	if err != nil {
		return false, err
	}
	command := exec.CommandContext(ctx, executable, "/Query", "/TN", taskName)
	command.Stdin = nil
	err = command.Run()
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func applyServiceACL(service *mgr.Service) error {
	dacl, err := descriptorDACL(serviceManagementACL)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(service.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func ApplyInstall(ctx context.Context, plan InstallPlan) (resultError error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("elevated administrator required")
	}
	if err := validateInstallPlan(plan); err != nil {
		return err
	}
	taskPresent, err := helperTaskExists(ctx, plan.TaskName)
	if err != nil {
		return err
	}
	if taskPresent {
		return errors.New("CherrySecurity helper task already exists")
	}
	createdFiles := []string{}
	createdDirectories := []string{}
	var service *mgr.Service
	taskCreated := false
	serviceStarted := false
	defer func() {
		if resultError == nil {
			return
		}
		if taskCreated {
			stopHelperTask(context.Background(), plan.TaskName)
			_ = deleteHelperTask(context.Background(), plan.TaskName)
		}
		if service != nil {
			if serviceStarted {
				_, _ = service.Control(svc.Stop)
			}
			_ = service.Delete()
			service.Close()
		}
		for index := len(createdFiles) - 1; index >= 0; index-- {
			_ = os.Remove(createdFiles[index])
		}
		for index := len(createdDirectories) - 1; index >= 0; index-- {
			_ = os.Remove(createdDirectories[index])
		}
	}()
	for _, directory := range []struct{ path, acl string }{{plan.InstallDirectory, installDirectoryACL}, {plan.DataDirectory, dataDirectoryACL}} {
		if err := os.Mkdir(directory.path, 0700); err != nil {
			return err
		}
		createdDirectories = append(createdDirectories, directory.path)
		if err := protectPath(directory.path, directory.acl); err != nil {
			return err
		}
	}
	for _, file := range []struct{ source, destination string }{{plan.ServiceSource, plan.ServicePath}, {plan.HelperSource, plan.HelperPath}, {plan.ControlSource, plan.ControlPath}, {plan.CASource, plan.CAPath}} {
		if err := copyExclusive(file.source, file.destination); err != nil {
			return err
		}
		createdFiles = append(createdFiles, file.destination)
	}
	for _, check := range []struct {
		path, expected string
		limit          int64
	}{{plan.ServicePath, plan.ServiceSHA256, 100 << 20}, {plan.HelperPath, plan.HelperSHA256, 100 << 20}, {plan.ControlPath, plan.ControlSHA256, 100 << 20}, {plan.CAPath, plan.CASHA256, 1 << 20}} {
		digest, hashError := sourceHash(check.path, check.limit)
		if hashError != nil || digest != check.expected {
			return errors.New("copied installation file failed integrity check")
		}
	}
	if err := writeConfigExclusive(plan); err != nil {
		return err
	}
	createdFiles = append(createdFiles, plan.ConfigPath)
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err = manager.CreateService(plan.ServiceName, plan.ServicePath, mgr.Config{DisplayName: "CherrySecurity Agent", Description: "Collects organization-authorized endpoint activity and service status.", StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, ServiceStartName: `NT AUTHORITY\LocalService`, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED, DelayedAutoStart: true}, "--config", plan.ConfigPath)
	if err != nil {
		return err
	}
	actions := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Duration(serviceRecovery[0]) * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Duration(serviceRecovery[1]) * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Duration(serviceRecovery[2]) * time.Second}, {Type: mgr.NoAction, Delay: time.Duration(serviceRecovery[3]) * time.Second}}
	if err = service.SetRecoveryActions(actions, 24*60*60); err != nil {
		return err
	}
	if err = service.SetRecoveryActionsOnNonCrashFailures(false); err != nil {
		return err
	}
	if err = applyServiceACL(service); err != nil {
		return err
	}
	if err = createHelperTask(ctx, plan); err != nil {
		return err
	}
	taskCreated = true
	if err = service.Start(); err != nil {
		return err
	}
	serviceStarted = true
	// Best effort: the task also starts at the employee's next sign-in, so an absent session must not undo the install.
	_ = runHelperTask(ctx, plan.TaskName)
	service.Close()
	service = nil
	return nil
}

func Uninstall(ctx context.Context, preserveData bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("elevated administrator required")
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return err
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return err
	}
	installDirectory := filepath.Join(programFiles, "CherrySecurity")
	dataDirectory := filepath.Join(programData, "CherrySecurity")
	for _, path := range []string{installDirectory, dataDirectory} {
		if err = rejectReparseAncestors(path); err != nil {
			return err
		}
	}
	// Refuse before changing anything: a control program inside the install folder cannot delete itself.
	if err = refuseRunningFromInstall(installDirectory); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	service, openError := manager.OpenService("CherrySecurityAgent")
	if openError == nil {
		_, _ = service.Control(svc.Stop)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			status, queryError := service.Query()
			if queryError != nil || status.State == svc.Stopped {
				break
			}
			if !waitContext(ctx, 250*time.Millisecond) {
				service.Close()
				manager.Disconnect()
				return ctx.Err()
			}
		}
		err = service.Delete()
		service.Close()
		if err != nil {
			manager.Disconnect()
			return err
		}
	} else if !errors.Is(openError, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		manager.Disconnect()
		return openError
	}
	manager.Disconnect()
	taskPresent, err := helperTaskExists(ctx, "CherrySecurity Session Helper")
	if err != nil {
		return err
	}
	if taskPresent {
		stopHelperTask(ctx, "CherrySecurity Session Helper")
		if err = deleteHelperTask(ctx, "CherrySecurity Session Helper"); err != nil {
			return err
		}
	}
	installed := []string{"agent.json"}
	for _, name := range upgradeBinaries {
		// Leftovers from an interrupted upgrade are removed with the binaries they belong to.
		installed = append(installed, name, name+".new", name+".old")
	}
	for _, name := range installed {
		if removeError := removeWhenReleased(ctx, filepath.Join(installDirectory, name)); removeError != nil {
			return removeError
		}
	}
	if err = os.Remove(installDirectory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if preserveData {
		return nil
	}
	for _, name := range []string{"credential.dat", "agent-ca.crt", "queue.db", "queue.db-journal", "agent.log"} {
		if removeError := removeWhenReleased(ctx, filepath.Join(dataDirectory, name)); removeError != nil {
			return removeError
		}
	}
	if err = os.Remove(dataDirectory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

var upgradeBinaries = []string{"CherrySecurityAgent.exe", "CherrySecurityHelper.exe", "CherrySecurityControl.exe"}

// retryWhileLocked repeats a file operation for up to 15 s while an exiting process still holds the file.
func retryWhileLocked(ctx context.Context, operation func() error) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := operation()
		if err == nil || !(errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)) || time.Now().After(deadline) {
			return err
		}
		if !waitContext(ctx, 250*time.Millisecond) {
			return ctx.Err()
		}
	}
}

// removeWhenReleased deletes a file once a process that is still exiting releases it; a missing file is not an error.
func removeWhenReleased(ctx context.Context, path string) error {
	return retryWhileLocked(ctx, func() error {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

func runningFrom(executable, directory string) bool {
	relative, err := filepath.Rel(strings.ToLower(filepath.Clean(directory)), strings.ToLower(filepath.Clean(executable)))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func refuseRunningFromInstall(installDirectory string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, resolveError := filepath.EvalSymlinks(executable); resolveError == nil {
		executable = resolved
	}
	if runningFrom(executable, installDirectory) {
		return fmt.Errorf("run the control program from its build or download folder, not from %s", installDirectory)
	}
	return nil
}

type UpgradeOptions struct {
	ServiceBinary string
	HelperBinary  string
	ControlBinary string
}

type UpgradeFile struct {
	Source      string
	Destination string
	OldSHA256   string
	NewSHA256   string
}

type UpgradePlan struct {
	InstallDirectory string
	ServiceName      string
	TaskName         string
	Files            []UpgradeFile
}

// PlanUpgrade checks an existing installation and the new binaries without changing anything.
func PlanUpgrade(ctx context.Context, options UpgradeOptions) (UpgradePlan, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return UpgradePlan{}, err
	}
	installDirectory := filepath.Join(programFiles, "CherrySecurity")
	if err = rejectReparseAncestors(installDirectory); err != nil {
		return UpgradePlan{}, err
	}
	if err = refuseRunningFromInstall(installDirectory); err != nil {
		return UpgradePlan{}, err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return UpgradePlan{}, err
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString("CherrySecurityAgent")
	if err != nil {
		return UpgradePlan{}, err
	}
	service, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return UpgradePlan{}, errors.New("CherrySecurity service is not installed; use install instead")
	}
	windows.CloseServiceHandle(service)
	taskPresent, err := helperTaskExists(ctx, "CherrySecurity Session Helper")
	if err != nil {
		return UpgradePlan{}, err
	}
	if !taskPresent {
		return UpgradePlan{}, errors.New("CherrySecurity helper task is missing; reinstall instead")
	}
	if info, statError := os.Lstat(filepath.Join(installDirectory, "agent.json")); statError != nil || !info.Mode().IsRegular() {
		return UpgradePlan{}, errors.New("installed agent.json is missing")
	}
	plan := UpgradePlan{InstallDirectory: installDirectory, ServiceName: "CherrySecurityAgent", TaskName: "CherrySecurity Session Helper"}
	for index, source := range []string{options.ServiceBinary, options.HelperBinary, options.ControlBinary} {
		destination := filepath.Join(installDirectory, upgradeBinaries[index])
		newHash, hashError := sourceHash(source, 100<<20)
		if hashError != nil {
			return UpgradePlan{}, hashError
		}
		oldHash, hashError := sourceHash(destination, 100<<20)
		if hashError != nil {
			return UpgradePlan{}, hashError
		}
		plan.Files = append(plan.Files, UpgradeFile{Source: source, Destination: destination, OldSHA256: oldHash, NewSHA256: newHash})
	}
	return plan, nil
}

// replaceWithBackup swaps each binary for its verified new copy, keeping the previous one as <name>.old.
// It returns the files already swapped so the caller can restore them.
func replaceWithBackup(ctx context.Context, files []UpgradeFile) ([]UpgradeFile, error) {
	swapped := []UpgradeFile{}
	for _, file := range files {
		staged, backup := file.Destination+".new", file.Destination+".old"
		for _, leftover := range []string{staged, backup} {
			if err := removeWhenReleased(ctx, leftover); err != nil {
				return swapped, err
			}
		}
		if err := copyExclusive(file.Source, staged); err != nil {
			return swapped, err
		}
		if digest, err := sourceHash(staged, 100<<20); err != nil || digest != file.NewSHA256 {
			_ = os.Remove(staged)
			return swapped, errors.New("staged upgrade file failed integrity check")
		}
		if err := retryWhileLocked(ctx, func() error { return os.Rename(file.Destination, backup) }); err != nil {
			_ = os.Remove(staged)
			return swapped, err
		}
		if err := os.Rename(staged, file.Destination); err != nil {
			_ = os.Rename(backup, file.Destination)
			_ = os.Remove(staged)
			return swapped, err
		}
		swapped = append(swapped, file)
	}
	return swapped, nil
}

// restoreBackups puts the previous binaries back in reverse order.
func restoreBackups(ctx context.Context, swapped []UpgradeFile) error {
	var first error
	for index := len(swapped) - 1; index >= 0; index-- {
		file := swapped[index]
		err := retryWhileLocked(ctx, func() error { return os.Rename(file.Destination+".old", file.Destination) })
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func stopServiceAndWait(ctx context.Context, service *mgr.Service) error {
	_, _ = service.Control(svc.Stop)
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("CherrySecurity service did not stop within 15 seconds")
		}
		if !waitContext(ctx, 250*time.Millisecond) {
			return ctx.Err()
		}
	}
}

// startAndConfirm starts the service and requires it to still be running after the settle time,
// which catches a build that exits during startup.
func startAndConfirm(ctx context.Context, service *mgr.Service, settle time.Duration) error {
	if err := service.Start(); err != nil {
		return err
	}
	if !waitContext(ctx, settle) {
		return ctx.Err()
	}
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Running {
		return fmt.Errorf("CherrySecurity service is not running after %s (state %d)", settle, status.State)
	}
	return nil
}

// ApplyUpgrade replaces the installed binaries in place, keeping the credential, queue, configuration and ACLs.
// Any failure after the service stops restores the previous binaries and restarts the service.
func ApplyUpgrade(ctx context.Context, plan UpgradePlan) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("elevated administrator required")
	}
	if plan.ServiceName != "CherrySecurityAgent" || plan.TaskName != "CherrySecurity Session Helper" || len(plan.Files) != len(upgradeBinaries) {
		return errors.New("invalid upgrade plan")
	}
	if err := refuseRunningFromInstall(plan.InstallDirectory); err != nil {
		return err
	}
	for _, file := range plan.Files {
		newHash, newError := sourceHash(file.Source, 100<<20)
		oldHash, oldError := sourceHash(file.Destination, 100<<20)
		if newError != nil || oldError != nil || newHash != file.NewSHA256 || oldHash != file.OldSHA256 {
			return errors.New("installation or upgrade source changed since the plan")
		}
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(plan.ServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	stopHelperTask(ctx, plan.TaskName)
	if err = stopServiceAndWait(ctx, service); err != nil {
		return err
	}
	rollBack := func(swapped []UpgradeFile, cause error) error {
		restoreError := restoreBackups(context.Background(), swapped)
		startError := service.Start()
		_ = runHelperTask(context.Background(), plan.TaskName)
		if restoreError != nil {
			return fmt.Errorf("upgrade failed (%v) and restoring the previous build also failed: %w", cause, restoreError)
		}
		if startError != nil {
			return fmt.Errorf("upgrade failed (%v); previous build restored but the service did not start: %w", cause, startError)
		}
		return fmt.Errorf("upgrade failed; previous build restored: %w", cause)
	}
	swapped, err := replaceWithBackup(ctx, plan.Files)
	if err != nil {
		return rollBack(swapped, err)
	}
	if err = startAndConfirm(ctx, service, 10*time.Second); err != nil {
		_ = stopServiceAndWait(context.Background(), service)
		return rollBack(swapped, err)
	}
	// Best effort: the task also starts at the employee's next sign-in.
	_ = runHelperTask(ctx, plan.TaskName)
	for _, file := range plan.Files {
		_ = removeWhenReleased(ctx, file.Destination+".old")
	}
	return nil
}
