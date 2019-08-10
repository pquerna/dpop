package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

const (
	appName = "demo-dpop"
)

func main() {
	app := cli.NewApp()
	app.Name = appName

	app.Commands = cli.Commands{
		listEnclaveKeysCommand,
		createKeyCommand,
		signProof,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
