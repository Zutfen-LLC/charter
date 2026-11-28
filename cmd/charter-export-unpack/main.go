// charter-export-unpack materializes an authenticated directory from the
// supported HTTP package transfer representation. It is not an archive reader.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/exportbundle"
)

const transferLimit = 32 << 20

func unpack(src io.Reader, dest, profile, digest string) (exportbundle.Result, error) {
	var zero exportbundle.Result
	raw, err := io.ReadAll(io.LimitReader(src, transferLimit+1))
	if err != nil {
		return zero, err
	}
	if len(raw) > transferLimit {
		return zero, errors.New("transfer size limit exceeded")
	}
	v, err := evidence.ParseJSON(raw)
	if err != nil {
		return zero, err
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) > exportbundle.MaxFiles {
		return zero, errors.New("invalid transfer member map")
	}
	files := make(map[string][]byte, len(m))
	for path, raw := range m {
		s, ok := raw.(string)
		if !ok {
			return zero, errors.New("transfer member must be a base64 string")
		}
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || base64.StdEncoding.EncodeToString(b) != s {
			return zero, errors.New("transfer member has invalid base64")
		}
		files[path] = b
	}
	result, err := exportbundle.VerifyMembers(files, profile, digest)
	if err != nil {
		return zero, err
	}
	// VerifyMembers enforces exact fixed names and membership before we create
	// anything. The destination parent is selected and trusted by the reviewer.
	if err = os.Mkdir(dest, 0700); err != nil {
		return zero, err
	}
	written := false
	defer func() {
		if !written {
			_ = os.RemoveAll(dest)
		}
	}()
	for p, b := range files {
		full := filepath.Join(dest, filepath.FromSlash(p))
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return zero, err
		}
		f, e := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return zero, e
		}
		_, e = f.Write(b)
		closeErr := f.Close()
		if e != nil {
			return zero, e
		}
		if closeErr != nil {
			return zero, closeErr
		}
	}
	written = true
	return result, nil
}

func main() {
	dest := flag.String("out", "", "new output directory in a trusted parent")
	profile := flag.String("profile", "", "required independent evidence profile")
	digest := flag.String("manifest-sha256", "", "trusted expected sha256:<hex>")
	flag.Parse()
	if *dest == "" || *profile == "" || *digest == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "required flags: -out, -profile, -manifest-sha256; read package on stdin")
		os.Exit(5)
	}
	result, err := unpack(os.Stdin, *dest, *profile, *digest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unpack refused:", err)
		os.Exit(5)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(5)
	}
	if result.Status == exportbundle.DeclaredGap {
		os.Exit(2)
	}
}
