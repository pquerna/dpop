package main

import (
	"fmt"
	"net/http"

	"github.com/pquerna/dpop"
	"github.com/urfave/cli"
	"gopkg.in/square/go-jose.v2"
)

var signProof = cli.Command{
	Name:    "proof",
	Aliases: []string{"c"},
	Usage:   "Signs a DPOP-Proof header",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "key-name",
		},
		cli.StringFlag{
			Name: "url",
		},
		cli.StringFlag{
			Name:  "method",
			Value: "POST",
		},
	},
	Action: func(c *cli.Context) error {
		reqUrl := c.String("url")
		if reqUrl == "" {
			return fmt.Errorf("--url is required")
		}
		wk, err := getKey(c)
		if err != nil {
			return err
		}

		p, err := dpop.NewProof(jose.SigningKey{
			Key:       wk.Key,
			Algorithm: jose.ES256,
		})
		if err != nil {
			return err
		}

		req, err := http.NewRequest(c.String("method"), reqUrl, nil)
		if err != nil {
			return err
		}

		err = p.ForRequest(req, nil)
		if err != nil {
			return err
		}

		cmd, err := req2curl(req)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", cmd)
		return nil
	},
}
