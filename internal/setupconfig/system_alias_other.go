//go:build !darwin

package setupconfig

import "os"

func macSystemAlias(string, os.FileInfo) bool { return false }
