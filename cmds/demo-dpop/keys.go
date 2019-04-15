package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/pquerna/dpop/enclave"
	"github.com/urfave/cli"
	"gopkg.in/square/go-jose.v2"
)

var listEnclaveKeysCommand = cli.Command{
	Name:    "list-enclave-keys",
	Aliases: []string{"c"},
	Usage:   "List-enclave keys",
	Action: func(c *cli.Context) error {
		available := enclave.Available()
		fmt.Printf("Encalve Available: %v\n", available)
		keys, err := enclave.List(appName)
		if err != nil {
			return err
		}

		for i, key := range keys {
			fmt.Printf("[%d]: LABEL='%s' ID='%s' PUBLIC_KEY='%v'\n", i, key.Label(), key.ID(), key.Public())
		}
		return nil
	},
}

var keyNamePattern = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

var createKeyCommand = cli.Command{
	Name:    "create-key",
	Aliases: []string{"c"},
	Usage:   "Create a new signing key",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "key-name",
		},
		cli.BoolFlag{
			Name: "enclave",
		},
	},
	Action: func(c *cli.Context) error {
		keyName := c.String("key-name")
		if keyName == "" {
			return fmt.Errorf("--key-name is required")
		}

		tryEnclave := c.Bool("enclave")
		if tryEnclave {
			available := enclave.Available()
			fmt.Printf("Encalve Available: %v\n", available)

			if !available {
				return fmt.Errorf("--enclave requested, but support is not available")
			}

			kp, err := enclave.Generate(appName, keyName)
			if err != nil {
				return err
			}
			op := enclave.OpaqueSigner(kp)
			pubData, err := json.MarshalIndent(op.Public(), "", "  ")
			if err != nil {
				return err
			}
			fmt.Printf("Key generated on enclave: \n%s\n", string(pubData))
			return nil
		}

		keyId := keyNamePattern.ReplaceAllString(keyName, "_")
		fn := keyId + ".jwk.key"
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		k := &jose.JSONWebKey{
			Key:   privateKey,
			KeyID: keyId,
		}

		fullData, err := json.MarshalIndent(k, "", "  ")
		if err != nil {
			return err
		}

		pubData, err := json.MarshalIndent(k.Public(), "", "  ")
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(fn, fullData, 0600)
		if err != nil {
			return err
		}
		fmt.Printf("Key saved to '%s': \n%s\n", fn, string(pubData))
		return nil
	},
}
