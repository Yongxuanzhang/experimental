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
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	"knative.dev/pkg/webhook/json"
)

// TODO: change taskspec to inferface{} in next pr
// Sign taskspec and return encoded signature
func Sign(signer signature.Signer, object interface{}) (string, error) {
	b, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(b)
	return SignRawPayload(signer, h.Sum(nil))
}

// Sign RawPayload and return encoded signature
func SignRawPayload(signer signature.Signer, rawPayload []byte) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("signer is nil")
	}

	sig, err := signer.SignMessage(bytes.NewReader(rawPayload))
	if err != nil {
		return "", err
	}
	se := base64.StdEncoding.EncodeToString(sig)
	return se, nil
}

// Get digest
func Digest(ctx context.Context, imageReference string, opt ...remote.Option) (v1.Hash, error) {
	imgRef, err := name.ParseReference(imageReference)
	if err != nil {
		return v1.Hash{}, err
	}

	img, err := remote.Image(imgRef, opt...)
	if err != nil {
		return v1.Hash{}, err
	}

	dgst, err := img.Digest()
	if err != nil {
		return v1.Hash{}, err
	}
	return dgst, nil
}

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func getSignerVerifier(password string) (signature.SignerVerifier, error) {
	keys, err := cosign.GenerateKeyPair(pass(password))
	if err != nil {
		return nil, err
	}
	sv, err := cosign.LoadPrivateKey(keys.PrivateBytes, []byte(password))
	if err != nil {
		return nil, err
	}
	return sv, nil
}
