package main

import (
	"context"
	"testing"

	"github.com/tektoncd/experimental/pipelines/trusted-resources/pkg/trustedtask"
)

const (
	password = "hello"
)

func TestSignTaskRunYaml(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()

	privateKeyPath, _, err := trustedtask.GenerateKeyFile(tmpDir, pass(password))
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name           string
		tr             string
		ts             string
		password       string
		privateKeyPath string
		wantErr        bool
	}{{
		name:           "Sign TaskRun",
		tr:             "testdata/taskrun.yaml",
		ts:             "",
		password:       password,
		privateKeyPath: privateKeyPath,
		wantErr:        false,
	}, {
		name:           "Sign TaskRun OCIBundle",
		tr:             "testdata/taskrun-oci-bundle.yaml",
		ts:             "",
		password:       password,
		privateKeyPath: privateKeyPath,
		wantErr:        false,
	}, {
		name:           "Sign TaskRun TaskRef",
		tr:             "testdata/taskrun-taskref.yaml",
		ts:             "testdata/task.yaml",
		password:       password,
		privateKeyPath: privateKeyPath,
		wantErr:        false,
	}, {
		name:           "Empty TaskRun",
		tr:             "",
		ts:             "",
		password:       password,
		privateKeyPath: privateKeyPath,
		wantErr:        true,
	}, {
		name:           "Wrong Password",
		tr:             "",
		ts:             "",
		password:       "wrong password",
		privateKeyPath: privateKeyPath,
		wantErr:        true,
	}, {
		name:           "Wrong keypath",
		tr:             "",
		ts:             "",
		password:       password,
		privateKeyPath: "wrong keypath",
		wantErr:        true,
	},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := signTaskRunYaml(ctx, tc.tr, tc.ts, tmpDir, pass(tc.password), tc.privateKeyPath); (err != nil) != tc.wantErr {
				t.Errorf("SignTaskSpec() get err %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}
