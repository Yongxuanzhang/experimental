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
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	fakek8s "k8s.io/client-go/kubernetes/fake"
)

func TestSign(t *testing.T) {
	sv, err := getSignerVerifier(password)
	if err != nil {
		t.Errorf("failed to get signerverifier %v", err)
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
			if _, err = Sign(tc.signer, taskSpecTest); (err != nil) != tc.wantErr {
				t.Errorf("SignTaskSpec() get err %v, wantErr %t", err, tc.wantErr)
			}
		})
	}

}

func TestSignRawPayload(t *testing.T) {
	sv, err := getSignerVerifier(password)
	if err != nil {
		t.Errorf("failed to get signerverifier %v", err)
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
			if _, err = SignRawPayload(tc.signer, tc.payload); (err != nil) != tc.wantErr {
				t.Errorf("SignRawPayload() get err %v, wantErr %t", err, tc.wantErr)
			}
		})
	}

}

func TestDigest(t *testing.T) {
	ctx := context.Background()

	k8sclient := fakek8s.NewSimpleClientset(sa)

	// Create registry server
	s := httptest.NewServer(registry.New())
	defer s.Close()
	u, _ := url.Parse(s.URL)

	// Push OCI bundle
	if _, err := pushOCIImage(t, u, ts); err != nil {
		t.Error(err)
	}

	kc, err := k8schain.New(ctx, k8sclient, k8schain.Options{
		Namespace:          nameSpace,
		ServiceAccountName: serviceAccount,
	})
	if err != nil {
		t.Error(err)
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
				t.Errorf("Digest() get err %v, wantErr %t", err, tc.wantErr)
			}
		})
	}

}
