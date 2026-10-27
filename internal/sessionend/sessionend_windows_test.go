// SPDX-License-Identifier: MIT

package sessionend

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

var (
	procGetAncestor      = user32.NewProc("GetAncestor")
	procGetDesktopWindow = user32.NewProc("GetDesktopWindow")
	procSendMessage      = user32.NewProc("SendMessageW")
)

const gaParent = 1

// liveWindow is the window this watch is holding, or the test gives up: every assertion here
// is about the real one.
func liveWindow(t *testing.T, w *Watch) windows.HWND {
	t.Helper()
	if !w.Watching() {
		t.Fatal("this machine gave app-tail no window, so it will never be told the session is ending")
	}
	win, ok := w.plat.(*window)
	if !ok {
		t.Fatalf("the watch is held by %T, which is not a window", w.plat)
	}
	win.mu.Lock()
	defer win.mu.Unlock()
	if win.hwnd == 0 {
		t.Fatal("the watch reports that it is watching and holds no window")
	}
	return win.hwnd
}

// The trap this whole package is arranged around. A message-only window (HWND_MESSAGE) is a
// child, and Windows delivers WM_QUERYENDSESSION and WM_ENDSESSION by walking top-level
// windows -- so one compiles, runs, pumps forever, and is never once told the machine is going
// down. It is the worst failure available here because it looks exactly like working code.
func TestItIsATopLevelWindowAndNotAMessageOnlyOne(t *testing.T) {
	_, w := Notify(context.Background(), Options{})
	t.Cleanup(w.Stop)
	hwnd := liveWindow(t, w)

	parent, err := call(procGetAncestor, uintptr(hwnd), gaParent)
	if parent == 0 {
		t.Fatalf("ask what the window's parent is: %v", err)
	}
	desktop, err := call(procGetDesktopWindow)
	if desktop == 0 {
		t.Fatalf("ask for the desktop window: %v", err)
	}
	if parent != desktop {
		t.Error("the window's parent is not the desktop, so it is a child -- and children are not told the session is ending")
	}
}

// Returning from the WM_ENDSESSION handler is how a process tells Windows it is finished, so
// the handler has to hold the session open until the teardown really has run. SendMessage
// blocks the sender until the window procedure returns, which is exactly the property under
// test -- no real logoff needed.
func TestTheEndSessionHandlerDoesNotReturnUntilTheShutdownHas(t *testing.T) {
	ctx, w := Notify(context.Background(), Options{Budget: 30 * time.Second})
	t.Cleanup(w.Stop)
	hwnd := liveWindow(t, w)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		//nolint:errcheck // the handler's return value is not what is under test here.
		call(procSendMessage, uintptr(hwnd), wmEndSession, 1, endSessionLogoff)
	}()

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session end never told app-tail to stop, so it is holding the session open for a teardown nobody started")
	}

	select {
	case <-returned:
		t.Fatal("the handler returned before the teardown finished, which tells Windows it may end this process now")
	case <-time.After(100 * time.Millisecond):
	}

	w.Finished()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still holding the session up after the teardown reported itself done")
	}
}
