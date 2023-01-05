//go:build linux && !appengine
// +build linux,!appengine

package fsnotify

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/fsnotify/fsnotify/internal"
	"golang.org/x/sys/unix"
)

const (
	sizeOfFanotifyEventMetadata = uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
)

var (
	// errInvalidFlagCombination indicates the bit/combination of flags are invalid
	errInvalidFlagCombination = errors.New("invalid flag bitmask")
)

// fanotifyEventType represents an event / operation on a particular file/directory
type fanotifyEventType uint64

// These fanotify structs are not defined in golang.org/x/sys/unix
type fanotifyEventInfoHeader struct {
	InfoType uint8
	pad      uint8
	Len      uint16
}

type kernelFSID struct {
	val [2]int32
}

// fanotifyEventInfoFID represents a unique file identifier info record.
// This structure is used for records of types FAN_EVENT_INFO_TYPE_FID,
// FAN_EVENT_INFO_TYPE_DFID and FAN_EVENT_INFO_TYPE_DFID_NAME.
// For FAN_EVENT_INFO_TYPE_DFID_NAME there is additionally a null terminated
// name immediately after the file handle.
type fanotifyEventInfoFID struct {
	Header     fanotifyEventInfoHeader
	fsid       kernelFSID
	fileHandle byte
}

// returns major, minor, patch version of the kernel
// upon error the string values are empty and the error
// indicates the reason for failure
func kernelVersion() (maj, min, patch int, err error) {
	var sysinfo unix.Utsname
	err = unix.Uname(&sysinfo)
	if err != nil {
		return
	}
	re := regexp.MustCompile(`([0-9]+)`)
	version := re.FindAllString(string(sysinfo.Release[:]), -1)
	if maj, err = strconv.Atoi(version[0]); err != nil {
		return
	}
	if min, err = strconv.Atoi(version[1]); err != nil {
		return
	}
	if patch, err = strconv.Atoi(version[2]); err != nil {
		return
	}
	return maj, min, patch, nil
}

// return true if process has CAP_SYS_ADMIN privilege
// else return false
func checkCapSysAdmin() (bool, error) {
	c, err := internal.CapInit()
	if err != nil {
		return false, err
	}
	return c.IsSet(unix.CAP_SYS_ADMIN, internal.CapEffective)
}

func flagsValid(flags uint) error {
	isSet := func(n, k uint) bool {
		return n&k == k
	}
	if isSet(flags, unix.FAN_REPORT_FID|unix.FAN_CLASS_CONTENT) {
		return errors.New("FAN_REPORT_FID cannot be set with FAN_CLASS_CONTENT")
	}
	if isSet(flags, unix.FAN_REPORT_FID|unix.FAN_CLASS_PRE_CONTENT) {
		return errors.New("FAN_REPORT_FID cannot be set with FAN_CLASS_PRE_CONTENT")
	}
	if isSet(flags, unix.FAN_REPORT_NAME) {
		if !isSet(flags, unix.FAN_REPORT_DIR_FID) {
			return errors.New("FAN_REPORT_NAME must be set with FAN_REPORT_DIR_FID")
		}
	}
	return nil
}

func isFanotifyMarkMaskValid(flags uint, mask uint64) error {
	isSet := func(n, k uint64) bool {
		return n&k == k
	}
	if isSet(uint64(flags), unix.FAN_MARK_MOUNT) {
		if isSet(mask, unix.FAN_CREATE) ||
			isSet(mask, unix.FAN_ATTRIB) ||
			isSet(mask, unix.FAN_MOVE) ||
			isSet(mask, unix.FAN_DELETE_SELF) ||
			isSet(mask, unix.FAN_DELETE) {
			return errors.New("mountpoint cannot be watched for create, attrib, move or delete self event types")
		}
	}
	return nil
}

func checkMask(mask uint64, validEventTypes []fanotifyEventType) error {
	flags := mask
	for _, v := range validEventTypes {
		if flags&uint64(v) == uint64(v) {
			flags = flags ^ uint64(v)
		}
	}
	if flags != 0 {
		return errInvalidFlagCombination
	}
	return nil
}

// Returns the entry from /etc/fstab and Device ID of the file
// where the unix.Stat(path).Dev matches unix.Stat(fields[1]).Dev;
// Returns error if there are permission or other errors
func getMountPointForPath(path string) (string, uint64, error) {
	var pathStat unix.Stat_t
	var fsFileStat unix.Stat_t
	var fsErr error

	fstab := "/etc/fstab"
	f, err := os.Open(fstab)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if err := unix.Stat(path, &pathStat); err != nil {
		return "", 0, fmt.Errorf("cannot stat %s: %w", path, err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimLeft(scanner.Text(), " \t")
		if strings.HasPrefix(line, "#") {
			continue // skip comment lines
		}
		if line == "" {
			continue // skip empty lines
		}
		fields := strings.Fields(line)
		if fields[2] == "swap" {
			continue // skip swap partition
		}
		// TODO fields[1] can contain spaces; deal with \011 or \040
		// characters in fields[1] (man 5 fstab)
		if err := unix.Stat(fields[1], &fsFileStat); err != nil {
			// continue on other entries return an error at the ends
			// if none was found
			fsErr = err
			continue
		}
		if pathStat.Dev == fsFileStat.Dev {
			return fields[1], pathStat.Dev, nil
		}
	}
	if scanner.Err() != nil {
		return "", 0, fmt.Errorf("error reading fstab: %w", err)
	}
	if fsErr != nil {
		return "", 0, fmt.Errorf("cannot stat paths in fstab: %w", fsErr)
	}
	return "", 0, fmt.Errorf("cannot stat paths in fstab")
}

// Check if specified fanotify_init flags are supported for the given
// kernel version. If none of the defined flags are specified
// then the basic option works on any kernel version.
func fanotifyInitFlagsKernelSupport(flags uint, maj, min int) bool {
	type kernelVersion struct {
		maj int
		min int
	}
	// fanotify init flags
	var flagPerKernelVersion = map[uint]kernelVersion{
		unix.FAN_ENABLE_AUDIT:     {4, 15},
		unix.FAN_REPORT_FID:       {5, 1},
		unix.FAN_REPORT_DIR_FID:   {5, 9},
		unix.FAN_REPORT_NAME:      {5, 9},
		unix.FAN_REPORT_DFID_NAME: {5, 9},
	}

	check := func(n, k uint, w, x int) (bool, error) {
		if n&k == k {
			if maj > w {
				return true, nil
			} else if maj == w && min >= x {
				return true, nil
			}
			return false, nil
		}
		return false, errors.New("flag not set")
	}
	for flag, ver := range flagPerKernelVersion {
		if v, err := check(flags, flag, ver.maj, ver.min); err != nil {
			continue // flag not set; check other flags
		} else {
			return v
		}
	}
	// if none of these flags were specified then the basic option
	// works on any kernel version
	return true
}

// Check if specified fanotify_mark flags are supported for the given
// kernel version. If none of the defined flags are specified
// then the basic option works on any kernel version.
func fanotifyMarkFlagsKernelSupport(flags uint64, maj, min int) bool {
	type kernelVersion struct {
		maj int
		min int
	}
	// fanotify mark flags
	var fanotifyMarkFlags = map[uint64]kernelVersion{
		unix.FAN_OPEN_EXEC:   {5, 0},
		unix.FAN_ATTRIB:      {5, 1},
		unix.FAN_CREATE:      {5, 1},
		unix.FAN_DELETE:      {5, 1},
		unix.FAN_DELETE_SELF: {5, 1},
		unix.FAN_MOVED_FROM:  {5, 1},
		unix.FAN_MOVED_TO:    {5, 1},
	}

	check := func(n, k uint64, w, x int) (bool, error) {
		if n&k == k {
			if maj > w {
				return true, nil
			} else if maj == w && min >= x {
				return true, nil
			}
			return false, nil
		}
		return false, errors.New("flag not set")
	}
	for flag, ver := range fanotifyMarkFlags {
		if v, err := check(flags, flag, ver.maj, ver.min); err != nil {
			continue // flag not set; check other flags
		} else {
			return v
		}
	}
	// if none of these flags were specified then the basic option
	// works on any kernel version
	return true
}

func fanotifyEventOK(meta *unix.FanotifyEventMetadata, n int) bool {
	return (n >= int(sizeOfFanotifyEventMetadata) &&
		meta.Event_len >= sizeOfFanotifyEventMetadata &&
		int(meta.Event_len) <= n)
}

func newFanotifyWatcher() (*Watcher, error) {

	var flags, eventFlags uint

	maj, min, _, err := kernelVersion()
	if err != nil {
		return nil, err
	}
	switch {
	case maj < 5:
		flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC
	case maj == 5:
		if min < 1 {
			flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC
		}
		if min >= 1 && min < 9 {
			flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_FID
		}
		if min >= 9 {
			flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_DIR_FID | unix.FAN_REPORT_NAME
		}
	case maj > 5:
		flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_DIR_FID | unix.FAN_REPORT_NAME
	}
	eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	if err := flagsValid(flags); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidFlagCombination, err)
	}
	if !fanotifyInitFlagsKernelSupport(flags, maj, min) {
		panic("some of the flags specified are not supported on the current kernel; refer to the documentation")
	}
	fd, err := unix.FanotifyInit(flags, eventFlags)
	if err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("cannot create stopper pipe: %v", err)
	}
	rfdFlags, err := unix.FcntlInt(r.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return nil, fmt.Errorf("stopper error: cannot read fd flags: %v", err)
	}
	_, err = unix.FcntlInt(r.Fd(), unix.F_SETFL, rfdFlags|unix.O_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("stopper error: cannot set fd to non-blocking: %v", err)
	}
	watcher := &Watcher{
		fd:                 fd,
		flags:              flags,
		kernelMajorVersion: maj,
		kernelMinorVersion: min,
		done:               make(chan struct{}),
		stopper: struct {
			r *os.File
			w *os.File
		}{r, w},
		Events:           make(chan FanotifyEvent),
		PermissionEvents: make(chan FanotifyEvent),
		Errors:           make(chan error),
		isFanotify:       true,
	}
	return watcher, nil
}

func getFileHandle(metadataLen uint16, buf []byte, i int) *unix.FileHandle {
	var fhSize uint32 // this is unsigned int handle_bytes; but Go uses uint32
	var fhType int32  // this is int handle_type; but Go uses int32

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(fanotifyEventInfoHeader{}))
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(kernelFSID{}))
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize))
	j := uint32(i) + uint32(metadataLen) + sizeOfFanotifyEventInfoHeader + sizeOfKernelFSIDType
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhSize)
	j += sizeOfUint32
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhType)
	j += sizeOfUint32
	handle := unix.NewFileHandle(fhType, buf[j:j+fhSize])
	return &handle
}

func getFileHandleWithName(metadataLen uint16, buf []byte, i int) (*unix.FileHandle, string) {
	var fhSize uint32
	var fhType int32
	var fname string
	var nameBytes bytes.Buffer

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(fanotifyEventInfoHeader{}))
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(kernelFSID{}))
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize))
	j := uint32(i) + uint32(metadataLen) + sizeOfFanotifyEventInfoHeader + sizeOfKernelFSIDType
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhSize)
	j += sizeOfUint32
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhType)
	j += sizeOfUint32
	handle := unix.NewFileHandle(fhType, buf[j:j+fhSize])
	j += fhSize
	// stop when NULL byte is read to get the filename
	for i := j; i < j+unix.NAME_MAX; i++ {
		if buf[i] == 0 {
			break
		}
		nameBytes.WriteByte(buf[i])
	}
	if nameBytes.Len() != 0 {
		fname = nameBytes.String()
	}
	return &handle, fname
}

// start starts the listener and polls the fanotify event notification group for marked events.
// The events are pushed into the Listener's Events channel.
func (w *Watcher) start() {
	var fds [2]unix.PollFd
	if w == nil {
		panic("nil listener")
	}
	defer func() {
		w.closeFanotify()
	}()
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
				if !w.sendError(err) {
					return
				}
				continue
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
				w.readFanotifyEvents() // blocks when the channel bufferred is full
			}
		}
	}
}

func (w *Watcher) closeFanotify() {
	w.closeOnce.Do(func() {
		close(w.done)
		unix.Write(int(w.stopper.w.Fd()), []byte("stop"))
		if err := unix.Close(w.fd); err != nil {
			w.Errors <- err
		}
		w.isClosed = true
		w.mountPointFile.Close()
		w.stopper.r.Close()
		w.stopper.w.Close()
		close(w.Events)
		close(w.PermissionEvents)
		close(w.Errors)
	})
}

// checkPathUnderMountPoint returns true if the path belongs to
// the mountPoint being watched else returns false.
func (w *Watcher) checkPathUnderMountPoint(path string) (bool, error) {
	var pathStat unix.Stat_t
	if err := unix.Stat(path, &pathStat); err != nil {
		return false, fmt.Errorf("cannot stat %s: %w", path, err)
	}
	return pathStat.Dev == w.mountDeviceID, nil
}

// fanotifyAddWith adds or modifies the fanotify mark for the specified path.
// The events are only raised for the specified directory and does raise events
// for subdirectories. Calling AddWatch to mark the entire mountpoint results in
// [os.ErrInvalid]. To watch the entire mount point use [WatchMount] method.
// Certain flag combinations are known to cause issues.
//  - [FileCreated] cannot be or-ed / combined with [FileClosed]. The fanotify system does not generate any event for this combination.
//  - [FileOpened] with any of the event types containing OrDirectory causes an event flood for the directory and then stopping raising any events at all.
//  - [FileOrDirectoryOpened] with any of the other event types causes an event flood for the directory and then stopping raising any events at all.
func (w *Watcher) fanotifyAddPath(path string) error {
	if w.isClosed {
		return ErrClosed
	}
	w.findMountPoint.Do(func() {
		mountPointPath, devID, err := getMountPointForPath(path)
		if err != nil {
			return
		}
		f, err := os.Open(mountPointPath)
		if err != nil {
			return
		}
		w.mountPointFile = f
		w.mountDeviceID = devID
	})
	// TODO if w.mountPointFile is nil then return error
	// indicating invalid watcher
	inMount, err := w.checkPathUnderMountPoint(path)
	if err != nil {
		return err
	}
	if !inMount {
		return ErrMountPoint
	}
	eventTypes := fileAccessed |
		fileOrDirectoryAccessed |
		fileModified |
		fileOpenedForExec |
		fileAttribChanged |
		fileOrDirectoryAttribChanged |
		fileCreated |
		fileOrDirectoryCreated |
		fileDeleted |
		fileOrDirectoryDeleted |
		watchedFileDeleted |
		watchedFileOrDirectoryDeleted |
		fileMovedFrom |
		fileOrDirectoryMovedFrom |
		fileMovedTo |
		fileOrDirectoryMovedTo |
		watchedFileMoved |
		watchedFileOrDirectoryMoved
	return w.fanotifyMark(path, unix.FAN_MARK_ADD, uint64(eventTypes|unix.FAN_EVENT_ON_CHILD))
}

func (w *Watcher) fanotifyRemove(path string) error {
	eventTypes := fileAccessed |
		fileOrDirectoryAccessed |
		fileModified |
		fileOpenedForExec |
		fileAttribChanged |
		fileOrDirectoryAttribChanged |
		fileCreated |
		fileOrDirectoryCreated |
		fileDeleted |
		fileOrDirectoryDeleted |
		watchedFileDeleted |
		watchedFileOrDirectoryDeleted |
		fileMovedFrom |
		fileOrDirectoryMovedFrom |
		fileMovedTo |
		fileOrDirectoryMovedTo |
		watchedFileMoved |
		watchedFileOrDirectoryMoved
	return w.fanotifyMark(path, unix.FAN_MARK_REMOVE, uint64(eventTypes|unix.FAN_EVENT_ON_CHILD))
}

func (w *Watcher) fanotifyMark(path string, flags uint, mask uint64) error {
	if !fanotifyMarkFlagsKernelSupport(mask, w.kernelMajorVersion, w.kernelMinorVersion) {
		panic("some of the mark mask combinations specified are not supported on the current kernel; refer to the documentation")
	}
	if err := isFanotifyMarkMaskValid(flags, mask); err != nil {
		return fmt.Errorf("%v: %w", err, errInvalidFlagCombination)
	}
	if err := unix.FanotifyMark(w.fd, flags, mask, -1, path); err != nil {
		return err
	}
	return nil
}

func (w *Watcher) clearWatch() error {
	if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_FLUSH, 0, -1, ""); err != nil {
		return err
	}
	w.markMask = 0
	return nil
}

func (w *Watcher) readFanotifyEvents() error {
	var fid *fanotifyEventInfoFID
	var metadata *unix.FanotifyEventMetadata
	var buf [4096 * sizeOfFanotifyEventMetadata]byte
	var name [unix.PathMax]byte
	var fileHandle *unix.FileHandle
	var fileName string

	for {
		n, err := unix.Read(w.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if !w.sendError(err) {
				return err
			}
		}
		if n == 0 || n < int(sizeOfFanotifyEventMetadata) {
			break
		}
		i := 0
		metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		for fanotifyEventOK(metadata, n) {
			// fmt.Println("Processing event", metadata, n)
			if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
				// fmt.Println("metadata.Vers", metadata.Vers, "FANOTIFY_METADATA_VERSION", unix.FANOTIFY_METADATA_VERSION, "metadata:", metadata)
				panic("metadata structure from the kernel does not match the structure definition at compile time")
			}
			if metadata.Fd != unix.FAN_NOFD {
				// fmt.Println("non FID")
				// no fid (applicable to kernels 5.0 and earlier)
				procFdPath := fmt.Sprintf("/proc/self/fd/%d", metadata.Fd)
				n1, err := unix.Readlink(procFdPath, name[:])
				if err != nil {
					if !w.sendError(err) {
						return err
					}
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				mask := metadata.Mask
				if mask&unix.FAN_ONDIR == unix.FAN_ONDIR {
					mask = mask ^ unix.FAN_ONDIR
				}
				event := FanotifyEvent{
					Event: Event{
						Name: string(name[:n1]),
						Op:   fanotifyEventType(mask).toOp(),
					},
					Fd:  int(metadata.Fd),
					Pid: int(metadata.Pid),
				}
				if mask&unix.FAN_ACCESS_PERM == unix.FAN_ACCESS_PERM ||
					mask&unix.FAN_OPEN_PERM == unix.FAN_OPEN_PERM ||
					mask&unix.FAN_OPEN_EXEC_PERM == unix.FAN_OPEN_EXEC_PERM {
					if !w.sendPermissionEvent(event) {
						return nil
					}
				} else {
					if !w.sendNotificationEvent(event) {
						return nil
					}
				}
				i += int(metadata.Event_len)
				n -= int(metadata.Event_len)
				metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
			} else {
				// fid (applicable to kernels 5.1+)
				fid = (*fanotifyEventInfoFID)(unsafe.Pointer(&buf[i+int(metadata.Metadata_len)]))
				// fmt.Println("FID", fid)
				withName := false
				switch {
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID:
					withName = false
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID:
					withName = false
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID_NAME:
					withName = true
				default:
					// fmt.Println("default case continue: fid.Header.InfoType", fid.Header.InfoType)
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				if withName {
					fileHandle, fileName = getFileHandleWithName(metadata.Metadata_len, buf[:], i)
					i += len(fileName) // advance some to cover the filename
				} else {
					fileHandle = getFileHandle(metadata.Metadata_len, buf[:], i)
				}
				fd, errno := unix.OpenByHandleAt(int(w.mountPointFile.Fd()), *fileHandle, unix.O_RDONLY)
				if errno != nil {
					if !w.sendError(errno) {
						// fmt.Println("oops something wrong. returning:", errno)
						return errno
					}
					// fmt.Println("something wrong wrote error to Errors channel:", errno)
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
				n1, _ := unix.Readlink(fdPath, name[:]) // TODO handle err case
				pathName := string(name[:n1])
				mask := metadata.Mask
				if mask&unix.FAN_ONDIR == unix.FAN_ONDIR {
					mask = mask ^ unix.FAN_ONDIR
				}
				event := FanotifyEvent{
					Event: Event{
						Name: path.Join(pathName, fileName),
						Op:   fanotifyEventType(mask).toOp(),
					},
					Fd:  fd,
					Pid: int(metadata.Pid),
				}
				// As of the kernel release (6.0) permission events cannot have FID flags.
				// So the event here is always a notification event
				// fmt.Println("Sending Event:", event)
				if !w.sendNotificationEvent(event) {
					return nil
				}
				i += int(metadata.Event_len)
				n -= int(metadata.Event_len)
				metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
			}
		}
	}
	return nil
}

func (w *Watcher) sendNotificationEvent(event FanotifyEvent) bool {
	if w.isClosed {
		return false
	}
	select {
	case w.Events <- event:
		return true
	case <-w.done:
	}
	return false
}

func (w *Watcher) sendPermissionEvent(event FanotifyEvent) bool {
	if w.isClosed {
		return false
	}
	select {
	case w.PermissionEvents <- event:
		return true
	case <-w.done:
	}
	return false
}

func (w *Watcher) sendError(err error) bool {
	if w.isClosed {
		// fmt.Println("sendError: isClosed is true; returning false")
		return false
	}
	select {
	case w.Errors <- err:
		return true
	case <-w.done:
		// fmt.Println("done was closed; returning false")
	}
	return false
}

// Has returns true if event types (e) contains the passed in event type (et).
func (e fanotifyEventType) Has(et fanotifyEventType) bool {
	return e&et == et
}

// Or appends the specified event types to the set of event types to watch for
func (e fanotifyEventType) Or(et fanotifyEventType) fanotifyEventType {
	return e | et
}

func (e fanotifyEventType) toOp() Op {
	var op Op
	if e.Has(unix.FAN_CREATE) || e.Has(unix.FAN_MOVED_TO) {
		op |= Create
	}
	if e.Has(unix.FAN_DELETE) || e.Has(unix.FAN_DELETE_SELF) {
		op |= Remove
	}
	if e.Has(unix.FAN_MODIFY) || e.Has(unix.FAN_CLOSE_WRITE) {
		op |= Write
	}
	if e.Has(unix.FAN_MOVE_SELF) || e.Has(unix.FAN_MOVED_FROM) {
		op |= Rename
	}
	if e.Has(unix.FAN_ATTRIB) {
		op |= Chmod
	}
	if e.Has(unix.FAN_ACCESS) {
		op |= Read
	}
	if e.Has(unix.FAN_CLOSE_NOWRITE) {
		op |= Close
	}
	if e.Has(unix.FAN_OPEN) {
		op |= Open
	}
	if e.Has(unix.FAN_OPEN_EXEC) {
		op |= Execute
	}
	if e.Has(unix.FAN_OPEN_PERM) {
		op |= PermissionToOpen
	}
	if e.Has(unix.FAN_OPEN_EXEC_PERM) {
		op |= PermissionToExecute
	}
	if e.Has(unix.FAN_ACCESS_PERM) {
		op |= PermissionToRead
	}
	return op
}

func (e FanotifyEvent) String() string {
	return fmt.Sprintf("Fd:(%d), Pid:(%d), Op:(%v), Path:(%s)", e.Fd, e.Pid, e.Op, e.Name)
}