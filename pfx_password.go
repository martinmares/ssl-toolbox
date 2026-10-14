package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

func newPFXChangePasswordCommand(stdout, stderr io.Writer) *cobra.Command {
	var inEnv, inFile, outEnv, outFile string
	cmd := &cobra.Command{Use: "change-password <file.pfx>", Short: "Replace a PFX in place with one new password for the store and private key", Args: cobra.ExactArgs(1),
		Example: "  ssl-toolbox pfx change-password client.pfx\n  ssl-toolbox pfx change-password client.pfx --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD\n  ssl-toolbox pfx change-password client.pfx --in-pass-file old-password.txt --out-pass-file new-password.txt",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			path := args[0]
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("read PFX file information: %w", err)
			}
			if !info.Mode().IsRegular() {
				return errors.New("PFX password change requires a regular file, not a symlink or directory")
			}
			original, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read input PFX: %w", err)
			}
			oldPassword, err := readPasswordSource(inEnv, inFile, "Input PFX password: ", stderr)
			if err != nil {
				return err
			}
			if _, err := pkcs12.Inspect(original, oldPassword); err != nil {
				return fmt.Errorf("decode input PFX (check password and format): %w", err)
			}
			newPassword, err := readNewPassword(outEnv, outFile, stderr)
			if err != nil {
				return err
			}
			updated, err := pkcs12.Modern2023.ChangePassword(original, oldPassword, newPassword)
			if err != nil {
				return err
			}
			if err := replacePFXPasswordFile(path, info, original, updated, newPassword); err != nil {
				return err
			}
			_, err = fmt.Fprintf(stdout, "Updated %s (same new password for PFX and private key; modern AES-256/SHA-256 protection)\n", path)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&inEnv, "in-pass-env", "", "Environment variable containing the current PFX password; otherwise prompt")
	f.StringVar(&inFile, "in-pass-file", "", "File containing the current PFX password")
	f.StringVar(&outEnv, "out-pass-env", "", "Environment variable containing the new PFX/key password; otherwise prompt twice")
	f.StringVar(&outFile, "out-pass-file", "", "File containing the new PFX/key password")
	cmd.MarkFlagsMutuallyExclusive("in-pass-env", "in-pass-file")
	cmd.MarkFlagsMutuallyExclusive("out-pass-env", "out-pass-file")
	return cmd
}

func replacePFXPasswordFile(path string, info os.FileInfo, original, updated []byte, password string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".ssl-toolbox-pfx-*")
	if err != nil {
		return fmt.Errorf("prepare PFX replacement: %w", err)
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err := temp.Write(updated); err != nil {
		return fmt.Errorf("write temporary PFX: %w", err)
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary PFX: %w", err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	stored, err := os.ReadFile(temp.Name())
	if err != nil {
		return fmt.Errorf("read temporary PFX: %w", err)
	}
	if !bytes.Equal(stored, updated) {
		return errors.New("temporary PFX does not match the generated data")
	}
	if _, err := pkcs12.Inspect(stored, password); err != nil {
		return fmt.Errorf("verify temporary PFX: %w", err)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || !currentInfo.Mode().IsRegular() || !os.SameFile(info, currentInfo) {
		return errors.New("PFX file changed while preparing replacement; retry")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return errors.New("PFX file changed while preparing replacement; retry")
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return fmt.Errorf("replace PFX: %w", err)
	}
	return nil
}
