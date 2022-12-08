//go:build linux && !appengine
// +build linux,!appengine

package fsnotify

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var (
	// ErrCapSysAdmin indicates caller is missing CAP_SYS_ADMIN permissions
	ErrCapSysAdmin = errors.New("require CAP_SYS_ADMIN capability")
	// ErrInvalidFlagCombination indicates the bit/combination of flags are invalid
	ErrInvalidFlagCombination = errors.New("invalid flag bits")
	// ErrNilWatcher indicates the watcher is nil
	ErrNilWatcher = errors.New("nil watcher")
	// ErrUnsupportedOnKernelVersion indicates the feature/flag is unavailable for the current kernel version
	ErrUnsupportedOnKernelVersion = errors.New("feature unsupported on current kernel version")
)

// FanotifyEvent represents a notification from the kernel for the file, directory
// or a filesystem marked for watching.
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

	// fd returned by fanotify_init
	fd int
	// flags passed to fanotify_init
	flags uint
	// mount fd is the file descriptor of the mountpoint
	mountpoint         *os.File
	kernelMajorVersion int
	kernelMinorVersion int
	stopper            struct {
		r *os.File
		w *os.File
	}
}

// NewFanotifyWatcher returns a fanotify listener from which events
// can be read. Each listener supports listening to events
// under a single mount point.
//
// For cases where multiple mountpoints need to be monitored
// multiple listener instances need to be used.
//
// `mountpointPath` can be any file/directory under the mount point being watched.
// `maxEvents` defines the length of the buffered channel which holds the notifications. The minimum length is 4096.
// `withName` setting this to true populates the file name under the watched parent.
//
// NOTE that this call requires CAP_SYS_ADMIN privilege
func NewFanotifyWatcher(mountpointPath string) (*FanotifyWatcher, error) {
	capSysAdmin, err := checkCapSysAdmin()
	if err != nil {
		return nil, err
	}
	if !capSysAdmin {
		return nil, ErrCapSysAdmin
	}
	var flags, eventFlags uint
	flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_DIR_FID | unix.FAN_REPORT_NAME
	eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	w, err := newFanotifyWatcher(mountpointPath, flags, eventFlags)
	go w.start()
	return w, err
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
	unix.Close(w.fd)
}

// Add watches the specified directory for specified actions
func (w *FanotifyWatcher) Add(name string) error {
	var action fanotifyAction
	action = fanotifyAction(unix.FAN_ACCESS | unix.FAN_MODIFY |
		unix.FAN_OPEN |
		unix.FAN_OPEN_EXEC |
		unix.FAN_ATTRIB |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_DELETE_SELF |
		unix.FAN_MOVED_FROM |
		unix.FAN_MOVED_TO |
		unix.FAN_MOVE_SELF)
	return w.fanotifyMark(name, unix.FAN_MARK_ADD, uint64(action|unix.FAN_EVENT_ON_CHILD), false)
}

// AddMountPoint watches the entire mount point for specified actions
func (w *FanotifyWatcher) AddMountPoint() error {
	var action fanotifyAction
	// all actions except FAN_ACCESS
	action = fanotifyAction(unix.FAN_DELETE |
		unix.FAN_MODIFY | unix.FAN_MOVE_SELF |
		unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO |
		unix.FAN_DELETE_SELF | unix.FAN_ATTRIB |
		unix.FAN_CLOSE_WRITE | unix.FAN_CLOSE_NOWRITE |
		unix.FAN_OPEN_EXEC)
	return w.fanotifyMark(w.mountpoint.Name(), unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, uint64(action), false)
}

func (w *FanotifyWatcher) Remove() error {
	if w == nil {
		return ErrNilWatcher
	}
	if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_FLUSH, 0, -1, ""); err != nil {
		return err
	}
	return nil
}
