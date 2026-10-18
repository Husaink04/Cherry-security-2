package agent

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type desktopReading struct {
	activeSession bool
	unlocked      bool
	unknown       bool
	idle          time.Duration
	application   string
}

func classifyDesktop(reading desktopReading, at time.Time, monotonic time.Duration, session string) Sample {
	sample := Sample{At: at, Monotonic: monotonic, LastInputAge: reading.idle, Session: session}
	switch {
	case !reading.activeSession:
		sample.State = "unsupported_session"
	case reading.unknown:
		sample.State = "process_unavailable"
	case !reading.unlocked:
		sample.State = "locked"
	case reading.application == "":
		sample.State = "process_unavailable"
	default:
		sample.State = "active"
		sample.App = reading.application
	}
	return sample
}

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	getLastInputInfo    = user32.NewProc("GetLastInputInfo")
	setWinEventHook     = user32.NewProc("SetWinEventHook")
	unhookWinEvent      = user32.NewProc("UnhookWinEvent")
	getMessage          = user32.NewProc("GetMessageW")
	postThreadMessage   = user32.NewProc("PostThreadMessageW")
	peekMessage         = user32.NewProc("PeekMessageW")
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64      = kernel32.NewProc("GetTickCount64")
	wtsapi32            = windows.NewLazySystemDLL("wtsapi32.dll")
	wtsQuerySessionInfo = wtsapi32.NewProc("WTSQuerySessionInformationW")
	wtsFreeMemory       = wtsapi32.NewProc("WTSFreeMemory")
)

type lastInputInfo struct {
	Size uint32
	Tick uint32
}

func desktopInputAge() (time.Duration, error) {
	info := lastInputInfo{Size: uint32(unsafe.Sizeof(lastInputInfo{}))}
	result, _, callError := getLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		return 0, callError
	}
	uptime, _, _ := getTickCount64.Call()
	// LASTINPUTINFO is a DWORD tick count; unsigned subtraction handles its wrap.
	return time.Duration(uint32(uptime)-info.Tick) * time.Millisecond, nil
}

func desktopUnlocked(sessionID uint32) (bool, error) {
	var buffer *byte
	var length uint32
	// WTSSessionInfoEx = 25; WTSINFOEX starts with Level, then aligned Level1.
	result, _, callError := wtsQuerySessionInfo.Call(0, uintptr(sessionID), 25, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&length)))
	if result == 0 {
		return false, callError
	}
	defer wtsFreeMemory.Call(uintptr(unsafe.Pointer(buffer)))
	if buffer == nil || length < 20 || *(*uint32)(unsafe.Pointer(buffer)) != 1 {
		return false, errors.New("unsupported session information")
	}
	flags := *(*uint32)(unsafe.Add(unsafe.Pointer(buffer), 16))
	if flags > 1 {
		return false, errors.New("unknown session lock state")
	}
	return flags == 1, nil
}

func foregroundApplication(sessionID uint32) string {
	hwnd := windows.GetForegroundWindow()
	if hwnd == 0 {
		return ""
	}
	var processID uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &processID); err != nil || processID == 0 {
		return ""
	}
	var foregroundSession uint32
	if err := windows.ProcessIdToSessionId(processID, &foregroundSession); err != nil || foregroundSession != sessionID {
		return ""
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(process)
	path := make([]uint16, windows.MAX_PATH)
	length := uint32(len(path))
	if err := windows.QueryFullProcessImageName(process, 0, &path[0], &length); err != nil {
		return ""
	}
	name := filepath.Base(windows.UTF16ToString(path[:length]))
	if len(name) > 120 || strings.ContainsAny(name, "\\/:\x00\r\n") {
		return ""
	}
	return name
}

func readDesktop(sessionID uint32) desktopReading {
	reading := desktopReading{activeSession: sessionID == windows.WTSGetActiveConsoleSessionId()}
	if !reading.activeSession {
		return reading
	}
	unlocked, err := desktopUnlocked(sessionID)
	if err != nil {
		reading.unknown = true
		return reading
	}
	if !unlocked {
		return reading
	}
	reading.unlocked = true
	age, err := desktopInputAge()
	if err != nil {
		reading.unknown = true
		return reading
	}
	reading.idle = age
	reading.application = foregroundApplication(sessionID)
	return reading
}

func foregroundNotifications(ctx context.Context) (<-chan struct{}, error) {
	changes := make(chan struct{}, 1)
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		threadID := windows.GetCurrentThreadId()
		var message [8]uintptr
		// Create the message queue before cancellation can post WM_QUIT.
		peekMessage.Call(uintptr(unsafe.Pointer(&message[0])), 0, 0, 0, 0)
		callback := windows.NewCallback(func(uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
			select {
			case changes <- struct{}{}:
			default:
			}
			return 0
		})
		hook, _, hookError := setWinEventHook.Call(3, 3, 0, callback, 0, 0, 0)
		if hook == 0 {
			ready <- hookError
			return
		}
		defer unhookWinEvent.Call(hook)
		ready <- nil
		stop := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				postThreadMessage.Call(uintptr(threadID), 0x12, 0, 0)
			case <-stop:
			}
		}()
		defer close(stop)
		for {
			result, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&message[0])), 0, 0, 0)
			if result == 0 || result == ^uintptr(0) {
				return
			}
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return changes, nil
}

func ObserveDesktop(ctx context.Context, emit func(Sample) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil {
		return err
	}
	started := time.Now()
	foreground, err := foregroundNotifications(ctx)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := emit(classifyDesktop(readDesktop(sessionID), time.Now().UTC(), time.Since(started), "console")); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-foreground:
		}
	}
}
