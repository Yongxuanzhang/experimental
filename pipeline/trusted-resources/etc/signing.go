package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/tektoncd/experimental/pipelines/trusted-resources/pkg/trustedtask"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"sigs.k8s.io/yaml"
)

var (
	password   = flag.String("pw", "", "cosign private key password")
	privateKey = flag.String("pk", "", "cosign private key path")
	taskRun    = flag.String("tr", "", "YAML file path for tekton taskrun")
	task       = flag.String("ts", "", "YAML file path for tekton task")
)

// This is a demo of how to generate signed files, just for reference
func main() {
	ctx := context.Background()

	flag.Parse()

	err := signTaskRunYaml(ctx, *taskRun, *task, *password, *privateKey)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

}

// signTaskRunYaml wil read taskrun's yaml file and generate signed yaml file
func signTaskRunYaml(ctx context.Context, taskRun string, task string, password string, privateKey string) error {
	tr := v1beta1.TaskRun{}
	buf, err := ioutil.ReadFile(taskRun)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(buf, &tr); err != nil {
		return err
	}
	s, err := signature.SignerFromKeyRef(ctx, privateKey, pass(password))
	if err != nil {
		return err
	}

	sig := ""
	if tr.Spec.TaskSpec != nil {
		sig, err = trustedtask.SignTaskSpec(s, tr.Spec.TaskSpec)
		if err != nil {
			return err
		}
	}

	if tr.Spec.TaskRef != nil {
		if tr.Spec.TaskRef.Bundle != "" {
			timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*60)
			defer cancel()

			dig, err := trustedtask.Digest(ctx, tr.Spec.TaskRef.Bundle, remote.WithContext(timeoutCtx))
			if err = yaml.Unmarshal(buf, &tr); err != nil {
				log.Fatalf("error: %v", err)
			}

			sig, err = trustedtask.SignRawPayload(s, []byte(dig.String()))
			if err != nil {
				return err
			}
		}
		if task != "" {
			ts := v1beta1.Task{}
			buf, err := ioutil.ReadFile(task)
			if err != nil {
				return err
			}

			if err = yaml.Unmarshal(buf, &ts); err != nil {
				return err
			}

			sig, err = trustedtask.SignTaskSpec(s, &ts.Spec)
			if err != nil {
				return err
			}
		}
	}
	tr.Annotations = map[string]string{trustedtask.SignatureAnnotation: sig}
	signed, err := yaml.Marshal(tr)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(strings.Split(taskRun, ".")[0]+"-signed.yaml", signed, 0644); err != nil {
		return err
	}
	return nil
}

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}
