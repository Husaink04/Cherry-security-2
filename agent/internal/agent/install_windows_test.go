package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestRunToolReportsBoundedToolOutput(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	shell := filepath.Join(system, "cmd.exe")
	if err = runTool(exec.Command(shell, "/c", "exit /b 0")); err != nil {
		t.Fatalf("successful tool reported %v", err)
	}
	// The installer must surface why schtasks or PowerShell failed, not only "exit status 1".
	err = runTool(exec.Command(shell, "/c", "echo ERROR: task XML is malformed& exit /b 1"))
	if err == nil || !strings.Contains(err.Error(), "cmd.exe failed") || !strings.Contains(err.Error(), "task XML is malformed") {
		t.Fatalf("tool output missing from error: %v", err)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("exit status not preserved: %v", err)
	}
	long := strings.Repeat("x", 600)
	err = runTool(exec.Command(shell, "/c", "echo "+long+"& exit /b 2"))
	if err == nil || strings.Contains(err.Error(), long) || !strings.Contains(err.Error(), strings.Repeat("x", 512)) {
		t.Fatalf("tool output was not bounded to 512 bytes: %d bytes", len(err.Error()))
	}
}

func TestInstallPlanRejectsExistingResources(t *testing.T) {
	root := t.TempDir()
	programFiles := filepath.Join(root, "Program Files")
	programData := filepath.Join(root, "ProgramData")
	for _, directory := range []string{programFiles, programData} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sources := []string{}
	for _, name := range []string{"service.exe", "helper.exe", "control.exe", "ca.crt"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("synthetic "+name), 0600); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, path)
	}
	options := InstallOptions{Endpoint: "https://192.0.2.10:8443", UserSID: "S-1-5-21-1-2-3-1001", ServiceBinary: sources[0], HelperBinary: sources[1], ControlBinary: sources[2], CACertificate: sources[3]}
	plan, err := planInstallAt(options, programFiles, programData)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plan.ServicePath, programFiles) || len(plan.ServiceSHA256) != 64 {
		t.Fatal("incomplete install plan")
	}
	if err := os.Mkdir(filepath.Join(programFiles, "CherrySecurity"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := planInstallAt(options, programFiles, programData); err == nil {
		t.Fatal("existing install directory accepted")
	}
}

func TestManagedServiceRecoveryAndAdminStop(t *testing.T) {
	if len(serviceRecovery) != 4 || serviceRecovery[0] != 10 || serviceRecovery[1] != 30 || serviceRecovery[2] != 60 || serviceRecovery[3] != 0 {
		t.Fatal("recovery must end in no action")
	}
	if !strings.Contains(serviceManagementACL, "(A;;GA;;;BA)") || !strings.Contains(serviceManagementACL, "(A;;LC;;;AU)") || strings.Contains(serviceManagementACL, "WP;;;AU") {
		t.Fatal("administrator stop or user query rights incorrect")
	}
	if !strings.Contains(installDirectoryACL, ";GRGX;;;AU)") || strings.Contains(dataDirectoryACL, ";;;AU)") || !strings.Contains(dataDirectoryACL, ";;;LS)") {
		t.Fatal("installation or data ACL is not least privilege")
	}
	for _, descriptor := range []string{serviceManagementACL, installDirectoryACL, dataDirectoryACL} {
		if _, err := descriptorDACL(descriptor); err != nil {
			t.Fatalf("invalid security descriptor: %v", err)
		}
	}
}

func lockWithoutDeleteSharing(t *testing.T, path string) windows.Handle {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

func TestRemoveWhenReleasedWaitsForAnExitingProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CherrySecurityHelper.exe")
	if err := os.WriteFile(path, []byte("synthetic helper"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := lockWithoutDeleteSharing(t, path)
	if err := os.Remove(path); err == nil {
		t.Fatal("test lock did not block deletion")
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		windows.CloseHandle(handle)
	}()
	// Uninstall used to fail here with "Access is denied" while the helper was still exiting.
	if err := removeWhenReleased(context.Background(), path); err != nil {
		t.Fatalf("file released after 300 ms was not removed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file still present after removal")
	}
	if err := removeWhenReleased(context.Background(), path); err != nil {
		t.Fatalf("missing file must not be an error: %v", err)
	}
	held := filepath.Join(t.TempDir(), "held.exe")
	if err := os.WriteFile(held, []byte("held"), 0600); err != nil {
		t.Fatal(err)
	}
	lock := lockWithoutDeleteSharing(t, held)
	defer windows.CloseHandle(lock)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if err := removeWhenReleased(ctx, held); err == nil {
		t.Fatal("a file that stays locked must eventually fail")
	}
}

func TestControlRefusesToRunFromInstallFolder(t *testing.T) {
	install := `C:\Program Files\CherrySecurity`
	for _, executable := range []string{`C:\Program Files\CherrySecurity\CherrySecurityControl.exe`, `c:\program files\cherrysecurity\CherrySecurityControl.exe`} {
		if !runningFrom(executable, install) {
			t.Fatalf("%s not detected as inside the install folder", executable)
		}
	}
	for _, executable := range []string{`D:\Cherry-security\artifacts\agent\batch-c6\CherrySecurityControl-m1.exe`, `C:\Program Files\CherrySecurity-old\CherrySecurityControl.exe`} {
		if runningFrom(executable, install) {
			t.Fatalf("%s wrongly treated as inside the install folder", executable)
		}
	}
}

func TestUpgradeSwapKeepsBackupAndRestores(t *testing.T) {
	root := t.TempDir()
	files := []UpgradeFile{}
	for _, name := range []string{"CherrySecurityAgent.exe", "CherrySecurityHelper.exe"} {
		destination, source := filepath.Join(root, name), filepath.Join(root, "new-"+name)
		if err := os.WriteFile(destination, []byte("old "+name), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte("new "+name), 0600); err != nil {
			t.Fatal(err)
		}
		oldHash, err := sourceHash(destination, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		newHash, err := sourceHash(source, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, UpgradeFile{Source: source, Destination: destination, OldSHA256: oldHash, NewSHA256: newHash})
	}
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	swapped, err := replaceWithBackup(context.Background(), files)
	if err != nil || len(swapped) != 2 {
		t.Fatalf("swap failed: %v", err)
	}
	if read(files[0].Destination) != "new CherrySecurityAgent.exe" || read(files[0].Destination+".old") != "old CherrySecurityAgent.exe" {
		t.Fatal("swap did not install the new file and keep the old one")
	}
	if err = restoreBackups(context.Background(), swapped); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasPrefix(read(file.Destination), "old ") {
			t.Fatalf("%s not restored", file.Destination)
		}
	}
	// A corrupted staged copy must stop the swap; only files already swapped are reported for restoring.
	files[1].NewSHA256 = strings.Repeat("0", 64)
	swapped, err = replaceWithBackup(context.Background(), files)
	if err == nil || len(swapped) != 1 {
		t.Fatalf("integrity failure not detected: swapped=%d err=%v", len(swapped), err)
	}
	if err = restoreBackups(context.Background(), swapped); err != nil {
		t.Fatal(err)
	}
	if read(files[0].Destination) != "old CherrySecurityAgent.exe" || read(files[1].Destination) != "old CherrySecurityHelper.exe" {
		t.Fatal("failed upgrade did not leave the previous build in place")
	}
	if _, err = os.Lstat(files[1].Destination + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected staged file left behind")
	}
}

func TestHelperTaskFileIsUTF16(t *testing.T) {
	plan := InstallPlan{UserSID: "S-1-5-21-1-2-3-1001", HelperPath: `C:\Program Files\CherrySecurity\CherrySecurityHelper.exe`, ConfigPath: `C:\Program Files\CherrySecurity\agent.json`}
	definition, err := helperTaskXML(plan)
	if err != nil {
		t.Fatal(err)
	}
	// schtasks /XML rejects a UTF-8 declaration with "unable to switch the encoding".
	if !strings.HasPrefix(string(definition), `<?xml version="1.0" encoding="UTF-16"?>`) {
		t.Fatalf("task XML must declare UTF-16: %.60s", definition)
	}
	file := utf16LEWithBOM(definition)
	if len(file) < 2 || file[0] != 0xFF || file[1] != 0xFE || len(file)%2 != 0 {
		t.Fatal("task file must be UTF-16LE with a byte-order mark")
	}
	units := make([]uint16, (len(file)-2)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(file[2+2*index:])
	}
	if string(utf16.Decode(units)) != string(definition) {
		t.Fatal("UTF-16 task file does not round-trip to the original XML")
	}
}

func TestHelperTaskUsesSelectedInteractiveIdentity(t *testing.T) {
	plan := InstallPlan{UserSID: "S-1-5-21-1-2-3-1001", HelperPath: `C:\Program Files\CherrySecurity\CherrySecurityHelper.exe`, ConfigPath: `C:\Program Files\CherrySecurity\agent.json`}
	definition, err := helperTaskXML(plan)
	if err != nil {
		t.Fatal(err)
	}
	xml := string(definition)
	for _, required := range []string{plan.UserSID, "InteractiveToken", "LeastPrivilege", plan.HelperPath, plan.ConfigPath} {
		if !strings.Contains(xml, required) {
			t.Fatalf("task definition missing %q", required)
		}
	}
	if strings.Contains(xml, "<Password>") || strings.Contains(xml, "HighestAvailable") {
		t.Fatal("task requests credentials or elevation")
	}
	descriptor := helperTaskSecurityDescriptor(plan.UserSID)
	for _, required := range []string{"D:P", "(A;;GA;;;SY)", "(A;;GA;;;BA)", "(A;;GRGX;;;" + plan.UserSID + ")"} {
		if !strings.Contains(descriptor, required) {
			t.Fatalf("task security descriptor missing %q", required)
		}
	}
	if strings.Contains(descriptor, "GWGX;;;"+plan.UserSID) || strings.Contains(descriptor, "GA;;;"+plan.UserSID) {
		t.Fatal("selected user can modify the managed task")
	}
}

func TestInstallPlanRejectsChangedSourceBeforeMutation(t *testing.T) {
	root := t.TempDir()
	programFiles := filepath.Join(root, "Program Files")
	programData := filepath.Join(root, "ProgramData")
	for _, directory := range []string{programFiles, programData} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sources := make([]string, 4)
	for index, name := range []string{"service.exe", "helper.exe", "control.exe", "ca.crt"} {
		sources[index] = filepath.Join(root, name)
		if err := os.WriteFile(sources[index], []byte("synthetic "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := planInstallAt(InstallOptions{Endpoint: "https://192.0.2.10:8443", UserSID: "S-1-5-21-1-2-3-1001", ServiceBinary: sources[0], HelperBinary: sources[1], ControlBinary: sources[2], CACertificate: sources[3]}, programFiles, programData)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sources[1], []byte("replaced helper"), 0600); err != nil {
		t.Fatal(err)
	}
	if validateInstallPlan(plan) == nil {
		t.Fatal("changed source accepted")
	}
	if _, err := os.Stat(plan.InstallDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("validation mutated install target")
	}
}

func TestInstallPlanRejectsReparseSourceWhenAvailable(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real.exe")
	link := filepath.Join(root, "linked.exe")
	if err := os.WriteFile(real, []byte("synthetic executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("Windows symlink creation unavailable to this test identity: %v", err)
	}
	if _, err := sourceHash(link, 100<<20); err == nil {
		t.Fatal("reparse source accepted")
	}
}
