/*
Copyright 2022 The Tekton Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package trustedtask

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

func TestSignTaskSpec(t *testing.T) {
	ctx := context.Background()
	sv, err := GetSignerVerifier(password)
	if err != nil {
		t.Fatalf("failed to get signerverifier %v", err)
	}

	tcs := []struct {
		name     string
		signer   signature.SignerVerifier
		taskSpec *v1beta1.TaskSpec
		wantErr  bool
	}{{
		name:     "Sign TaskSpec",
		signer:   sv,
		taskSpec: taskSpecTest,
		wantErr:  false,
	}, {
		name:     "Empty TaskSpec",
		signer:   sv,
		taskSpec: nil,
		wantErr:  false,
	}, {
		name:     "Empty Signer",
		signer:   nil,
		taskSpec: taskSpecTest,
		wantErr:  true,
	},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := SignTaskSpec(tc.signer, taskSpecTest)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SignTaskSpec() get err %v, wantErr %t", err, tc.wantErr)
			}
			if !tc.wantErr {
				signature, err := base64.StdEncoding.DecodeString(sig)
				if err != nil {
					t.Fatalf("error decoding signature: %v", err)
				}
				if err := VerifyTaskSpec(ctx, taskSpecTest, tc.signer, signature); err != nil {
					t.Fatalf("SignTaskSpec() generate wrong signature: %v", err)
				}
			}
		})
	}
}

func TestSignRawPayload(t *testing.T) {
	sv, err := GetSignerVerifier(password)
	if err != nil {
		t.Fatalf("failed to get signerverifier %v", err)
	}

	tcs := []struct {
		name    string
		signer  signature.SignerVerifier
		payload []byte
		wantErr bool
	}{{
		name:    "Sign raw payload",
		signer:  sv,
		payload: []byte("payload"),
		wantErr: false,
	}, {
		name:    "Empty payload",
		signer:  sv,
		payload: nil,
		wantErr: false,
	}, {
		name:    "Empty Signer",
		signer:  nil,
		payload: []byte("payload"),
		wantErr: true,
	},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := SignRawPayload(tc.signer, tc.payload)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SignRawPayload() get err %v, wantErr %t", err, tc.wantErr)
			}
			if !tc.wantErr {
				sig, err := base64.StdEncoding.DecodeString(signature)
				if err != nil {
					t.Fatal("failed to decode signature")
				}
				if err := sv.VerifySignature((bytes.NewReader(sig)), bytes.NewReader(tc.payload)); err != nil {
					t.Fatalf("SignRawPayload() get wrong signature %v:", err)
				}
			}

		})
	}
}

func TestDigest(t *testing.T) {
	ctx := context.Background()

	// Create registry server
	s := httptest.NewServer(registry.New())
	defer s.Close()
	u, _ := url.Parse(s.URL)

	// Push OCI bundle
	if _, err := pushOCIImage(t, u, ts); err != nil {
		t.Fatal(err)
	}

	kc, err := k8schain.NewNoClient(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name     string
		imageRef string
		wantErr  bool
	}{{
		name:     "OCIBundle Pass Verification",
		imageRef: u.Host + "/task/" + ts.Name,
		wantErr:  false,
	}, {
		name:     "OCIBundle Fail Verification with empty signature",
		imageRef: u.Host + "/task/" + tsTampered.Name,
		wantErr:  true,
	}, {
		name:     "OCIBundle Fail Verification with empty Bundle",
		imageRef: "",
		wantErr:  true,
	},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err = Digest(ctx, tc.imageRef, remote.WithAuthFromKeychain(kc)); (err != nil) != tc.wantErr {
				t.Fatalf("Digest() get err %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestGenerateKeyFile(t *testing.T) {
	tmpDir := t.TempDir()

	tcs := []struct {
		name     string
		dir      string
		password string
		wantErr  bool
	}{{
		name:     "Generate key files",
		dir:      tmpDir,
		password: password,
		wantErr:  false,
	}, {
		name:     "Empty directory",
		dir:      "",
		password: password,
		wantErr:  false,
	}, {
		name:     "Empty password",
		dir:      tmpDir,
		password: "",
		wantErr:  false,
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := GenerateKeyFile(tmpDir, pass(password)); (err != nil) != tc.wantErr {
				t.Fatalf("GenerateKeyFile() get err %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}
