package main

import (
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/partitio/dex/dex"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

func commandServe() *cobra.Command {
	return &cobra.Command{
		Use:     "serve [ config file ]",
		Short:   "Connect to the storage and begin serving requests.",
		Long:    ``,
		Example: "dex serve config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		},
	}
}

func serve(cmd *cobra.Command, args []string) error {
	switch len(args) {
	default:
		return errors.New("surplus arguments")
	case 0:
		// TODO(ericchiang): Consider having a default config file location.
		return errors.New("no arguments provided")
	case 1:
	}

	configFile := args[0]
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	var c dex.Config
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return fmt.Errorf("error parse config file %s: %v", configFile, err)
	}

	d, err := dex.NewDex(c)
	if err != nil {
		return err
	}
	return d.Run()
}
