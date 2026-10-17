package agent

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	sechost                   = windows.NewLazySystemDLL("sechost.dll")
	subscribeServiceChanges   = sechost.NewProc("SubscribeServiceChangeNotifications")
	unsubscribeServiceChanges = sechost.NewProc("UnsubscribeServiceChangeNotifications")
)

func reconcileInventory(previous, current map[string]ServiceObservation, at time.Time, refresh bool) []ServiceObservation {
	changed := make([]ServiceObservation, 0)
	for name, observation := range current {
		old, exists := previous[name]
		if refresh || !exists || old.State != observation.State || old.StartupType != observation.StartupType {
			changed = append(changed, observation)
		}
	}
	for name := range previous {
		if _, exists := current[name]; !exists {
			changed = append(changed, ServiceObservation{Name: name, State: "removed", StartupType: "unknown", At: at})
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].Name < changed[j].Name })
	return changed
}

func serviceState(state uint32) string {
	switch state {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_PAUSED:
		return "paused"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_CONTINUE_PENDING:
		return "continue_pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "pause_pending"
	default:
		return "unknown"
	}
}

func serviceStartupType(manager windows.Handle, name string) string {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "unknown"
	}
	service, err := windows.OpenService(manager, pointer, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(service)
	var needed uint32
	err = windows.QueryServiceConfig(service, nil, 0, &needed)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || needed < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || needed > 64*1024 {
		return "unknown"
	}
	buffer := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err = windows.QueryServiceConfig(service, config, needed, &needed); err != nil {
		return "unknown"
	}
	switch config.StartType {
	case windows.SERVICE_AUTO_START:
		return "automatic"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	default:
		return "unknown"
	}
}

func readServices(at time.Time, previous map[string]ServiceObservation) (map[string]ServiceObservation, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(manager)
	var needed, count, resume uint32
	var buffer []byte
	result := make(map[string]ServiceObservation)
	for {
		var pointer *byte
		if len(buffer) != 0 {
			pointer = &buffer[0]
		}
		err = windows.EnumServicesStatusEx(manager, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, pointer, uint32(len(buffer)), &needed, &count, &resume, nil)
		if count > 0 {
			entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0])), int(count))
			for _, entry := range entries {
				name := windows.UTF16PtrToString(entry.ServiceName)
				if name == "" || len(name) > 120 || strings.ContainsAny(name, "\x00\r\n") {
					continue
				}
				result[name] = ServiceObservation{Name: name, State: serviceState(entry.ServiceStatusProcess.CurrentState), StartupType: serviceStartupType(manager, name), At: at}
			}
		}
		if err == nil {
			for name := range previous {
				if _, present := result[name]; present {
					continue
				}
				pointer, conversionError := windows.UTF16PtrFromString(name)
				if conversionError != nil {
					continue
				}
				service, openError := windows.OpenService(manager, pointer, windows.SERVICE_QUERY_STATUS)
				if openError == nil {
					windows.CloseServiceHandle(service)
				}
				if openError != windows.ERROR_SERVICE_DOES_NOT_EXIST && openError != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
					result[name] = ServiceObservation{Name: name, State: "unknown", StartupType: "unknown", At: at}
				}
			}
			return result, nil
		}
		if err != windows.ERROR_MORE_DATA || needed > 1024*1024 {
			return nil, err
		}
		nextSize := needed
		if nextSize <= uint32(len(buffer)) {
			nextSize = uint32(len(buffer)) * 2
		}
		if nextSize <= uint32(len(buffer)) || nextSize > 1024*1024 {
			return nil, errors.New("service enumeration exceeded bounded buffer")
		}
		// A larger buffer restarts enumeration, avoiding stale partial snapshots.
		resume = 0
		result = make(map[string]ServiceObservation)
		buffer = make([]byte, nextSize)
	}
}

func serviceDatabaseChanges() (<-chan struct{}, func(), error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, nil, err
	}
	changes := make(chan struct{}, 1)
	callback := windows.NewCallback(func(uintptr, uintptr) uintptr {
		select {
		case changes <- struct{}{}:
		default:
		}
		return 0
	})
	var registration uintptr
	status, _, _ := subscribeServiceChanges.Call(uintptr(manager), 0, callback, 0, uintptr(unsafe.Pointer(&registration)))
	if status != 0 {
		windows.CloseServiceHandle(manager)
		return nil, nil, windows.Errno(status)
	}
	closeSubscription := func() {
		unsubscribeServiceChanges.Call(registration)
		windows.CloseServiceHandle(manager)
	}
	return changes, closeSubscription, nil
}

func ObserveServices(ctx context.Context, emit func(ServiceObservation) error) error {
	changes, closeSubscription, err := serviceDatabaseChanges()
	if err != nil {
		return err
	}
	defer closeSubscription()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	previous := make(map[string]ServiceObservation)
	lastRefresh := time.Time{}
	forceRefresh := false
	for {
		now := time.Now().UTC()
		current, err := readServices(now, previous)
		if err != nil {
			return err
		}
		refresh := forceRefresh || lastRefresh.IsZero() || now.Sub(lastRefresh) >= 24*time.Hour
		for _, observation := range reconcileInventory(previous, current, now, refresh) {
			if err := emit(observation); err != nil {
				return err
			}
		}
		previous = current
		forceRefresh = false
		if refresh {
			lastRefresh = now
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-changes:
			forceRefresh = true
		}
	}
}
