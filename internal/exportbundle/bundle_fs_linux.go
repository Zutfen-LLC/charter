//go:build linux

package exportbundle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type bundleFS struct{ root int }

// Linux O_PATH returns an inode descriptor without opening a device, FIFO,
// socket or other untrusted member for IO.
const oPath = 0x200000
const dirFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW

func openBundleFS(dir string) (*bundleFS, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(fd, part, dirFlags, 0)
		_ = syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return &bundleFS{root: fd}, nil
}
func (fs *bundleFS) close() {
	if fs != nil && fs.root >= 0 {
		_ = syscall.Close(fs.root)
		fs.root = -1
	}
}

func safeParts(p string) ([]string, error) {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return nil, errors.New("unsafe bundle path")
	}
	parts := strings.Split(p, "/")
	for _, x := range parts {
		if x == "" || x == "." || x == ".." {
			return nil, errors.New("unsafe bundle path")
		}
	}
	return parts, nil
}

func (fs *bundleFS) openParent(parts []string) (int, error) {
	fd, err := syscall.Dup(fs.root)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)
	for _, part := range parts {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

func (fs *bundleFS) read(p string, max int64) ([]byte, error) {
	parts, err := safeParts(p)
	if err != nil {
		return nil, err
	}
	parent, err := fs.openParent(parts[:len(parts)-1])
	if err != nil {
		return nil, err
	}
	defer syscall.Close(parent)
	inode, err := syscall.Openat(parent, parts[len(parts)-1], oPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(inode)
	var st syscall.Stat_t
	if err = syscall.Fstat(inode, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("non-regular file rejected")
	}
	if st.Nlink != 1 {
		return nil, errors.New("hard-linked file rejected")
	}
	if st.Size < 0 || st.Size > max {
		return nil, errors.New("file size limit exceeded")
	}
	// Reopen the same pinned inode, not a potentially substituted filename.
	fd, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(inode), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var check syscall.Stat_t
	if err = syscall.Fstat(fd, &check); err != nil {
		return nil, err
	}
	if check.Dev != st.Dev || check.Ino != st.Ino || check.Mode&syscall.S_IFMT != syscall.S_IFREG || check.Nlink != 1 {
		return nil, errors.New("bundle inode identity changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("file size limit exceeded during read")
	}
	return b, nil
}

func (fs *bundleFS) members(limit int) ([]string, error) {
	var out []string
	root, err := syscall.Openat(fs.root, ".", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(root)
	err = fs.walk(root, "", &out, limit)
	_ = syscall.Close(root)
	return out, err
}
func (fs *bundleFS) walk(fd int, base string, out *[]string, limit int) error {
	dup, err := syscall.Openat(fd, ".", dirFlags, 0)
	if err != nil {
		return err
	}
	syscall.CloseOnExec(dup)
	d := os.NewFile(uintptr(dup), base)
	defer d.Close()
	for {
		entries, e := d.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			full := name
			if base != "" {
				full = base + "/" + name
			}
			if len(*out) >= limit {
				return errors.New("bundle member count limit exceeded")
			}
			child, oe := syscall.Openat(fd, name, oPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
			if oe != nil {
				return fmt.Errorf("cannot safely open bundle member %q: %w", full, oe)
			}
			var st syscall.Stat_t
			if oe = syscall.Fstat(child, &st); oe != nil {
				syscall.Close(child)
				return oe
			}
			switch st.Mode & syscall.S_IFMT {
			case syscall.S_IFDIR:
				if base != "" || (full != "events" && full != "objects") {
					syscall.Close(child)
					return fmt.Errorf("unexpected directory: %s", full)
				}
				oe = fs.walk(child, full, out, limit)
				syscall.Close(child)
				if oe != nil {
					return oe
				}
			case syscall.S_IFREG:
				if st.Nlink != 1 {
					syscall.Close(child)
					return fmt.Errorf("hard link rejected: %s", full)
				}
				*out = append(*out, full)
				syscall.Close(child)
			default:
				syscall.Close(child)
				return fmt.Errorf("special file rejected: %s", full)
			}
		}
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if len(entries) == 0 {
			return nil
		}
	}
}
