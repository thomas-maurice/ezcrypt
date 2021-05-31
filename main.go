package main

import (
	"os"

	"github.com/thomas-maurice/ezcrypt/cmd"
)

func main() {
	cmd.InitRootCmd()

	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
