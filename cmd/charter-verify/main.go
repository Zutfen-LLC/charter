package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Zutfen-LLC/charter/internal/exportbundle"
)

func main() {
	dir := flag.String("bundle", "", "bundle directory")
	profile := flag.String("profile", "", "required independently selected evidence profile")
	digest := flag.String("manifest-sha256", "", "expected sha256:<hex> obtained independently")
	flag.Parse()
	code := 5
	var result exportbundle.Result
	var err error
	if *dir == "" || *profile == "" || *digest == "" || flag.NArg() != 0 {
		err = fmt.Errorf("bundle, profile, and manifest-sha256 are required; no positional arguments accepted")
	} else {
		result, err = exportbundle.Verify(*dir, *profile, *digest)
	}
	if err == nil {
		if result.Status == exportbundle.DeclaredGap {
			code = 2
		} else {
			code = 0
		}
	} else if f, ok := err.(*exportbundle.Failure); ok {
		switch f.Kind {
		case "integrity":
			code = 3
		case "unsupported":
			code = 4
		default:
			code = 5
		}
	}
	out := struct {
		OK     bool                 `json:"ok"`
		Code   int                  `json:"exit_code"`
		Result *exportbundle.Result `json:"result,omitempty"`
		Error  string               `json:"error,omitempty"`
	}{Code: code}
	if err == nil {
		out.OK = true
		out.Result = &result
	} else {
		out.Error = err.Error()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if e := enc.Encode(out); e != nil {
		fmt.Fprintln(os.Stderr, "JSON output failure:", e)
		os.Exit(5)
	}
	os.Exit(code)
}
