//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import "os"

func lockFileExclusive(_ *os.File) (func() error, error) {
	return func() error { return nil }, nil
}
