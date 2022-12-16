//go:build linux && !appengine
// +build linux,!appengine

package fsnotify

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var (
	// ErrCapSysAdmin indicates caller is missing CAP_SYS_ADMIN permissions
	ErrCapSysAdmin = errors.New("require CAP_SYS_ADMIN capability")
	// ErrInvalidFlagCombination indicates the bit/combination of flags are invalid
	ErrInvalidFlagCombination = errors.New("invalid flag bitmask")
	// ErrUnsupportedOnKernelVersion indicates the feature/flag is unavailable for the current kernel version
	ErrUnsupportedOnKernelVersion = errors.New("feature unsupported on current kernel version")
	// ErrWatchPath indicates path needs to be specified for watching
	ErrWatchPath = errors.New("missing watch path")
)

// PermissionType represents value indicating when the permission event must be requested.
type PermissionType int

const (
	// PermissionNone is used to indicate the listener is for notification events only.
	PermissionNone PermissionType = 0
	// PreContent is intended for event listeners that
	// need to access files before they contain their final data.
	PreContent PermissionType = 1
	// PostContent is intended for event listeners that
	// need to access files when they already contain their final content.
	PostContent PermissionType = 2
)

// FanotifyEvent represents a notification or a permission event from the kernel for the file,
// directory marked for watching.
// Notification events are merely informative and require
// no action to be taken by the receiving application with the exception being that the
// file descriptor provided within the event must be closed.
// Permission events are requests to the receiving application to decide whether permission
// for a file access shall be granted. For these events, the recipient must write a
// response which decides whether access is granted or not.
type FanotifyEvent struct {
	Event
	// Fd is the open file descriptor for the file/directory being watched
	Fd int
	// Pid Process ID of the process that caused the event
	Pid int
}

// FanotifyWatcher watches a set of paths, delivering events on a channel.
type FanotifyWatcher struct {
	// Events sends the filesystem change events.
	//
	// fsnotify can send the following events; a "path" here can refer to a
	// file, directory, symbolic link, or special file like a FIFO.
	//
	//   fsnotify.Create    A new path was created; this may be followed by one
	//                      or more Write events if data also gets written to a
	//                      file.
	//
	//   fsnotify.Remove    A path was removed.
	//
	//   fsnotify.Write     A file or named pipe was written to. A Truncate will
	//                      also trigger a Write. A single "write action"
	//                      initiated by the user may show up as one or multiple
	//                      writes, depending on when the system syncs things to
	//                      disk. For example when compiling a large Go program
	//                      you may get hundreds of Write events, so you
	//                      probably want to wait until you've stopped receiving
	//                      them (see the dedup example in cmd/fsnotify).
	//
	//   fsnotify.Chmod     Attributes were changed. On Linux this is also sent
	//                      when a file is removed (or more accurately, when a
	//                      link to an inode is removed). On kqueue it's sent
	//                      and on kqueue when a file is truncated. On Windows
	//                      it's never sent.
	Events chan FanotifyEvent
	// PermissionEvents holds permission request events for the watched file/directory.
	PermissionEvents chan FanotifyEvent

	// fd returned by fanotify_init
	fd int
	// flags passed to fanotify_init
	flags              uint
	mountpoint         *os.File
	kernelMajorVersion int
	kernelMinorVersion int
	entireMount        bool
	notificationOnly   bool
	stopper            struct {
		r *os.File
		w *os.File
	}
}

// NewFanotifyWatcher returns a fanotify listener from which filesystem
// notification events can be read. Each listener
// supports listening to events under a single mount point.
// For cases where multiple mount points need to be monitored
// multiple listener instances need to be used.
//
// Notification events are merely informative and require
// no action to be taken by the receiving application with the
// exception being that the file descriptor provided within the
// event must be closed.
//
// Permission events are requests to the receiving application to
// decide whether permission for a file access shall be granted.
// For these events, the recipient must write a response which decides
// whether access is granted or not.
//
// - mountPoint can be any file/directory under the mount point being
//   watched.
// - entireMount initializes the listener to monitor either the
//   the entire mount point (when true) or allows adding files
//   or directories to the listener's watch list (when false).
// - permType initializes the listener either notification events
//   or both notification and permission events.
//   Passing [PreContent] value allows the receipt of events
//   notifying that a file has been accessed and events for permission
//   decisions if a file may be accessed. It is intended for event listeners
//   that need to access files before they contain their final data. Passing
//   [PostContent] is intended for event listeners that need to access
//   files when they already contain their final content.
//
// The function returns a new instance of the listener. The fanotify flags
// are set based on the running kernel version. [ErrCapSysAdmin] is returned
// if the process does not have CAP_SYS_ADM capability.
//
//  - For Linux kernel version 5.0 and earlier no additional information about the underlying filesystem object is available.
//  - For Linux kernel versions 5.1 till 5.8 (inclusive) additional information about the underlying filesystem object is correlated to an event.
//  - For Linux kernel version 5.9 or later the modified file name is made available in the event.
func NewFanotifyWatcher(mountPoint string, entireMount bool, permType PermissionType) (*FanotifyWatcher, error) {
	capSysAdmin, err := checkCapSysAdmin()
	if err != nil {
		return nil, err
	}
	if !capSysAdmin {
		return nil, ErrCapSysAdmin
	}
	isNotificationListener := true
	if permType == PreContent || permType == PostContent {
		isNotificationListener = false
	}
	w, err := newFanotifyWatcher(mountPoint, entireMount, isNotificationListener, permType)
	if err != nil {
		return nil, err
	}
	go w.start()
	return w, nil
}

// start starts the listener and polls the fanotify event notification group for marked events.
// The events are pushed into the Listener's `Events` buffered channel.
// The function panics if there nothing to watch.
func (w *FanotifyWatcher) start() {
	var fds [2]unix.PollFd
	// Fanotify Fd
	fds[0].Fd = int32(w.fd)
	fds[0].Events = unix.POLLIN
	// Stopper/Cancellation Fd
	fds[1].Fd = int32(w.stopper.r.Fd())
	fds[1].Events = unix.POLLIN
	for {
		n, err := unix.Poll(fds[:], -1)
		if n == 0 {
			continue
		}
		if err != nil {
			if err == unix.EINTR {
				continue
			} else {
				// TODO handle error
				return
			}
		}
		if fds[1].Revents != 0 {
			if fds[1].Revents&unix.POLLIN == unix.POLLIN {
				// found data on the stopper
				return
			}
		}
		if fds[0].Revents != 0 {
			if fds[0].Revents&unix.POLLIN == unix.POLLIN {
				w.readEvents() // blocks when the channel bufferred is full
			}
		}
	}
}

// Close stops the watcher and closes the notification group and the events channel
func (w *FanotifyWatcher) Close() {
	if w == nil {
		return
	}
	// stop the listener
	unix.Write(int(w.stopper.w.Fd()), []byte("stop"))
	w.mountpoint.Close()
	w.stopper.r.Close()
	w.stopper.w.Close()
	close(w.Events)
	close(w.PermissionEvents)
	unix.Close(w.fd)
}

// Add watches the specified directory for specified actions
func (w *FanotifyWatcher) Add(path string) error {
	var actions fanotifyAction
	actions = fanotifyAction(unix.FAN_ACCESS | unix.FAN_MODIFY |
		unix.FAN_OPEN |
		unix.FAN_OPEN_EXEC |
		unix.FAN_ATTRIB |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_DELETE_SELF |
		unix.FAN_MOVED_FROM |
		unix.FAN_MOVED_TO |
		unix.FAN_MOVE_SELF)
	return w.fanotifyMark(path, unix.FAN_MARK_ADD, uint64(actions|unix.FAN_EVENT_ON_CHILD))
}

// AddWithPermissions watches the specified directory for actions
// and permission requests for permission to open file/directory,
// permission to open file for execution and permission to read
// file or directory.
func (w *FanotifyWatcher) AddWithPermissions(path string) error {
	var actions fanotifyAction
	// all except FAN_ACCESS
	actions = fanotifyAction(unix.FAN_MODIFY |
		unix.FAN_OPEN |
		unix.FAN_OPEN_EXEC |
		unix.FAN_ATTRIB |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_DELETE_SELF |
		unix.FAN_MOVED_FROM |
		unix.FAN_MOVED_TO |
		unix.FAN_MOVE_SELF |
		unix.FAN_OPEN_PERM |
		unix.FAN_OPEN_EXEC_PERM |
		unix.FAN_ACCESS_PERM)
	return w.fanotifyMark(path, unix.FAN_MARK_ADD, uint64(actions|unix.FAN_EVENT_ON_CHILD))
}

// AddMountPoint watches the entire mount point for specified actions
func (w *FanotifyWatcher) AddMountPoint() error {
	var action fanotifyAction
	action = fanotifyAction(unix.FAN_ACCESS |
		unix.FAN_MODIFY |
		unix.FAN_CLOSE_WRITE |
		unix.FAN_CLOSE_NOWRITE |
		unix.FAN_OPEN |
		unix.FAN_OPEN_EXEC)

	return w.fanotifyMark(w.mountpoint.Name(), unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, uint64(action))
}

// Remove removes / clears the current event mask
func (w *FanotifyWatcher) Remove() error {
	if w == nil {
		panic("nil watcher")
	}
	if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_FLUSH, 0, -1, ""); err != nil {
		return err
	}
	return nil
}

// Allow sends an "allowed" response to the permission request event.
func (w *FanotifyWatcher) Allow(e FanotifyEvent) {
	var response unix.FanotifyResponse
	response.Fd = int32(e.Fd)
	response.Response = unix.FAN_ALLOW
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &response)
	unix.Write(w.fd, buf.Bytes())
}

// Deny sends an "denied" response to the permission request event.
func (w *FanotifyWatcher) Deny(e FanotifyEvent) {
	var response unix.FanotifyResponse
	response.Fd = int32(e.Fd)
	response.Response = unix.FAN_DENY
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &response)
	unix.Write(w.fd, buf.Bytes())
}
