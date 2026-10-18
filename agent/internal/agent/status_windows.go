package agent

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type trayWindowClass struct {
	Size, Style             uint32
	WindowProcedure         uintptr
	ClassExtra, WindowExtra int32
	Instance, Icon, Cursor  windows.Handle
	Background              windows.Handle
	MenuName, ClassName     *uint16
	SmallIcon               windows.Handle
}

type trayIconData struct {
	Size                uint32
	Window              windows.Handle
	ID, Flags, Callback uint32
	Icon                windows.Handle
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	TimeoutOrVersion    uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         windows.Handle
}

var (
	trayUser32        = windows.NewLazySystemDLL("user32.dll")
	trayShell32       = windows.NewLazySystemDLL("shell32.dll")
	registerClassEx   = trayUser32.NewProc("RegisterClassExW")
	createWindowEx    = trayUser32.NewProc("CreateWindowExW")
	destroyWindow     = trayUser32.NewProc("DestroyWindow")
	defaultWindowProc = trayUser32.NewProc("DefWindowProcW")
	loadIcon          = trayUser32.NewProc("LoadIconW")
	messageBox        = trayUser32.NewProc("MessageBoxW")
	trayGetMessage    = trayUser32.NewProc("GetMessageW")
	trayPostThread    = trayUser32.NewProc("PostThreadMessageW")
	postQuitMessage   = trayUser32.NewProc("PostQuitMessage")
	shellNotifyIcon   = trayShell32.NewProc("Shell_NotifyIconW")
)

func RunStatus(ctx context.Context, current func() Status) error {
	return runStatus(ctx, current, nil)
}

func runStatus(ctx context.Context, current func() Status, ready chan<- error) (resultError error) {
	readySent := false
	defer func() {
		if ready != nil && !readySent {
			ready <- resultError
		}
	}()
	if current == nil {
		return errors.New("status provider required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	className, _ := windows.UTF16PtrFromString("CherrySecurityStatusWindow")
	title, _ := windows.UTF16PtrFromString("CherrySecurity Agent")
	callbackMessage := uint32(0x8001)
	windowProcedure := windows.NewCallback(func(window uintptr, message uint32, word, long uintptr) uintptr {
		switch message {
		case callbackMessage:
			if uint32(long) == 0x202 || uint32(long) == 0x205 {
				notice, err := current().Notice()
				if err == nil {
					body, _ := windows.UTF16PtrFromString(notice)
					messageBox.Call(window, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x40)
				}
			}
			return 0
		case 2:
			postQuitMessage.Call(0)
			return 0
		}
		result, _, _ := defaultWindowProc.Call(window, uintptr(message), word, long)
		return result
	})
	class := trayWindowClass{Size: uint32(unsafe.Sizeof(trayWindowClass{})), WindowProcedure: windowProcedure, ClassName: className}
	if result, _, err := registerClassEx.Call(uintptr(unsafe.Pointer(&class))); result == 0 {
		return err
	}
	window, _, err := createWindowEx.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)), 0, 0, 0, 0, 0, 0, 0, 0, 0)
	if window == 0 {
		return err
	}
	defer destroyWindow.Call(window)
	icon, _, _ := loadIcon.Call(0, 32512)
	data := trayIconData{Size: uint32(unsafe.Sizeof(trayIconData{})), Window: windows.Handle(window), ID: 1, Flags: 1 | 2 | 4, Callback: callbackMessage, Icon: windows.Handle(icon)}
	copy(data.Tip[:], syscall.StringToUTF16("CherrySecurity Agent - click for collection notice"))
	if result, _, err := shellNotifyIcon.Call(0, uintptr(unsafe.Pointer(&data))); result == 0 {
		return err
	}
	defer shellNotifyIcon.Call(2, uintptr(unsafe.Pointer(&data)))
	if ready != nil {
		ready <- nil
		readySent = true
	}
	threadID := windows.GetCurrentThreadId()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			trayPostThread.Call(uintptr(threadID), 0x12, 0, 0)
		case <-done:
		}
	}()
	var message [8]uintptr
	for {
		result, _, callError := trayGetMessage.Call(uintptr(unsafe.Pointer(&message[0])), 0, 0, 0)
		if result == 0 {
			return ctx.Err()
		}
		if result == ^uintptr(0) {
			return callError
		}
	}
}
