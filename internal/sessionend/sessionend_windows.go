// SPDX-License-Identifier: MIT

package sessionend

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// None of these are bound in golang.org/x/sys/windows, so they are reached by name. Both
// ShutdownBlockReason calls live in user32 rather than kernel32.
var (
	user32 = windows.NewLazySystemDLL("user32.dll")

	procRegisterClassEx            = user32.NewProc("RegisterClassExW")
	procCreateWindowEx             = user32.NewProc("CreateWindowExW")
	procDestroyWindow              = user32.NewProc("DestroyWindow")
	procDefWindowProc              = user32.NewProc("DefWindowProcW")
	procGetMessage                 = user32.NewProc("GetMessageW")
	procTranslateMessage           = user32.NewProc("TranslateMessage")
	procDispatchMessage            = user32.NewProc("DispatchMessageW")
	procPostQuitMessage            = user32.NewProc("PostQuitMessage")
	procPostMessage                = user32.NewProc("PostMessageW")
	procShutdownBlockReasonCreate  = user32.NewProc("ShutdownBlockReasonCreate")
	procShutdownBlockReasonDestroy = user32.NewProc("ShutdownBlockReasonDestroy")
)

const (
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmQueryEndSession  = 0x0011
	wmEndSession       = 0x0016
	wsOverlapped       = 0x00000000
	wsExToolWindow     = 0x00000080
	windowClassName    = "AppTailSessionEnd"
	windowInstanceName = "app-tail session end"
)

// wndClassEx and msg are declared here because x/sys/windows carries neither.
type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	HWnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

// window is the hidden top-level window the session end arrives at, and the thread pumping
// its messages.
//
// Top-level, never message-only. A message-only window is a child, and Windows delivers
// WM_QUERYENDSESSION and WM_ENDSESSION by walking top-level windows -- a message-only one
// compiles, runs, pumps forever and is never once told the machine is going down, which is
// the worst of the failure modes available here because it looks like it is working.
type window struct {
	watch *Watch
	ready chan error
	done  chan struct{}

	mu   sync.Mutex
	hwnd windows.HWND
}

var (
	// creationMu serializes window creation, so that at most one window is waiting to learn
	// its own handle at a time.
	creationMu sync.Mutex
	// liveMu guards both of the below. It is never held across a Win32 call: the wndproc
	// runs on the creating thread, inside CreateWindowEx, and a Go mutex does not recurse.
	liveMu   sync.Mutex
	live     = map[windows.HWND]*window{}
	creating *window
)

// wndProcCallback is built once. NewCallback is capped at a few thousand per process and
// never releases one, so building it per window would be a slow leak.
var wndProcCallback = sync.OnceValue(func() uintptr { return windows.NewCallback(wndProc) })

func watch(w *Watch) platform {
	win := &window{watch: w, ready: make(chan error, 1), done: make(chan struct{})}
	go win.run()
	if err := <-win.ready; err != nil {
		w.opts.Logf("app-tail will not be told when this session ends, so a shutdown will not "+
			"wait for it to put this machine back: %v", err)
		return nil
	}
	return win
}

// run owns the window for its whole life. The window and its message pump must be on one
// thread, and Windows delivers WM_ENDSESSION to the thread owning the window, so that thread
// is locked to this goroutine and does nothing else.
func (win *window) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(win.done)

	hwnd, err := win.create()
	if err != nil {
		win.ready <- err
		return
	}
	win.mu.Lock()
	win.hwnd = hwnd
	win.mu.Unlock()
	win.ready <- nil

	win.pump()
}

func (win *window) create() (windows.HWND, error) {
	class, err := windows.UTF16PtrFromString(windowClassName)
	if err != nil {
		return 0, fmt.Errorf("name the window class app-tail is told about the session ending through: %w", err)
	}
	name, err := windows.UTF16PtrFromString(windowInstanceName)
	if err != nil {
		return 0, fmt.Errorf("name the window app-tail is told about the session ending through: %w", err)
	}
	var instance windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
		return 0, fmt.Errorf("find this process's own module: %w", err)
	}

	creationMu.Lock()
	defer creationMu.Unlock()

	definition := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   wndProcCallback(),
		Instance:  instance,
		ClassName: class,
	}
	// A second watch in the same process finds the class already registered, which is not a
	// failure: the class it would register is this one.
	registered, err := call(procRegisterClassEx, uintptr(unsafe.Pointer(&definition)))
	if registered == 0 && !errors.Is(err, windows.ERROR_CLASS_ALREADY_EXISTS) {
		return 0, fmt.Errorf("register the window class app-tail is told about the session ending through: %w", err)
	}
	runtime.KeepAlive(definition)

	// Claimed before the window exists, because the wndproc runs for the creation messages
	// before CreateWindowEx has returned a handle there is anywhere to store.
	setCreating(win)
	defer setCreating(nil)

	// WS_EX_TOOLWINDOW and never ShowWindow: hidden, but top-level, which is what the
	// session-end messages are delivered to. Zero parent is what makes it top-level.
	handle, err := call(procCreateWindowEx,
		wsExToolWindow,
		uintptr(unsafe.Pointer(class)),
		uintptr(unsafe.Pointer(name)),
		wsOverlapped,
		0, 0, 0, 0,
		0, 0, uintptr(instance), 0,
	)
	runtime.KeepAlive(class)
	runtime.KeepAlive(name)
	if handle == 0 {
		return 0, fmt.Errorf("create the window app-tail is told about the session ending through: %w", err)
	}
	hwnd := windows.HWND(handle)
	adopt(hwnd, win)
	return hwnd, nil
}

// pump runs until the window is destroyed. GetMessage returns 0 for WM_QUIT and -1 for a real
// failure, which is the one case worth reporting: the others are the window going away.
func (win *window) pump() {
	var m msg
	for {
		got, err := call(procGetMessage, uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(got) == -1 {
			win.watch.opts.Logf("app-tail stopped listening for the end of this session: %v", err)
			return
		}
		if got == 0 {
			return
		}
		//nolint:errcheck // neither reports anything a caller can act on, and the pump has
		// nowhere to go but on.
		call(procTranslateMessage, uintptr(unsafe.Pointer(&m)))
		//nolint:errcheck // see above.
		call(procDispatchMessage, uintptr(unsafe.Pointer(&m)))
	}
}

// stop takes the window down and waits for its thread to finish with it.
func (win *window) stop() {
	win.mu.Lock()
	hwnd := win.hwnd
	win.mu.Unlock()
	if hwnd == 0 {
		return
	}
	posted, err := call(procPostMessage, uintptr(hwnd), wmClose, 0, 0)
	if posted == 0 {
		win.watch.opts.Logf("could not close the window app-tail is told about the session ending through: %v", err)
		return
	}
	<-win.done
}

// wndProc is the whole handshake with Windows.
//
// Blocking in here is what makes this work, and it is safe: this runs on a cgo callback, so
// the thread is parked in a C frame and the Go runtime starts a fresh one for everything else
// -- the agent's own teardown keeps running while this waits for it. Returning from the
// WM_ENDSESSION case is how a process tells Windows it is finished, so returning early is
// exactly the bug this package exists to fix.
//
// The hwnd parameter is used and never a stored field: this runs for the creation messages
// before CreateWindowEx has returned a handle to store.
func wndProc(hwnd windows.HWND, message uint32, wparam, lparam uintptr) uintptr {
	switch message {
	case wmQueryEndSession:
		// Nothing is torn down here. A logoff can still be called off, and a teardown
		// started on a query that is then cancelled leaves this machine with no resolver
		// and app-tail still running beside it.
		if win := lookup(hwnd); win != nil {
			win.blockShutdown(hwnd)
		}
		return 1
	case wmEndSession:
		win := lookup(hwnd)
		if win == nil {
			return 0
		}
		// wParam zero is the session end being called off after all.
		if wparam != 0 {
			win.watch.begin(endingFrom(lparam))
		}
		win.unblockShutdown(hwnd)
		return 0
	case wmClose:
		if destroyed, err := call(procDestroyWindow, uintptr(hwnd)); destroyed == 0 {
			if win := lookup(hwnd); win != nil {
				win.watch.opts.Logf("could not take down the window app-tail is told about the session ending through: %v", err)
			}
		}
		return 0
	case wmDestroy:
		forget(hwnd)
		//nolint:errcheck // it returns nothing; the pump ends on the WM_QUIT this posts.
		call(procPostQuitMessage, 0)
		return 0
	}
	handled, _ := call(procDefWindowProc, uintptr(hwnd), uintptr(message), wparam, lparam)
	return handled
}

// blockShutdown puts app-tail's own sentence on the machine's blocking screen. It buys no
// extra time -- it replaces a generic "this app is preventing shutdown" with what app-tail is
// actually doing, and a forced shutdown ignores it entirely.
func (win *window) blockShutdown(hwnd windows.HWND) {
	if win.watch.opts.Reason == "" {
		return
	}
	reason, err := windows.UTF16PtrFromString(win.watch.opts.Reason)
	if err != nil {
		win.watch.opts.Logf("could not say why app-tail is holding this shutdown up: %v", err)
		return
	}
	blocked, err := call(procShutdownBlockReasonCreate, uintptr(hwnd), uintptr(unsafe.Pointer(reason)))
	runtime.KeepAlive(reason)
	if blocked == 0 {
		win.watch.opts.Logf("this machine's shutdown screen will not say why app-tail is still running: %v", err)
	}
}

func (win *window) unblockShutdown(hwnd windows.HWND) {
	if cleared, err := call(procShutdownBlockReasonDestroy, uintptr(hwnd)); cleared == 0 {
		win.watch.opts.Logf("could not take app-tail's sentence off this machine's shutdown screen: %v", err)
	}
}

// call runs a lazily-bound entry point, checking that it exists first: a LazyProc that cannot
// find its library or its entry point panics inside Call.
//
// The returned error is only meaningful where the returned value says the call failed --
// Call always reports the thread's last error, which is routinely a success.
func call(proc *windows.LazyProc, args ...uintptr) (uintptr, error) {
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("%s: %w", proc.Name, err)
	}
	result, _, err := proc.Call(args...)
	return result, err
}

func setCreating(win *window) {
	liveMu.Lock()
	defer liveMu.Unlock()
	creating = win
}

func adopt(hwnd windows.HWND, win *window) {
	liveMu.Lock()
	defer liveMu.Unlock()
	live[hwnd] = win
}

func forget(hwnd windows.HWND) {
	liveMu.Lock()
	defer liveMu.Unlock()
	delete(live, hwnd)
}

// lookup finds the window a message is for, taking in the one still being created: its first
// messages arrive before CreateWindowEx has returned the handle they are keyed by.
func lookup(hwnd windows.HWND) *window {
	liveMu.Lock()
	defer liveMu.Unlock()
	if win, ok := live[hwnd]; ok {
		return win
	}
	if creating != nil {
		live[hwnd] = creating
		return creating
	}
	return nil
}
