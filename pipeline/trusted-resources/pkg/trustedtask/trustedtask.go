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

	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"knative.dev/pkg/apis"
)

//go:generate deepcopy-gen -O zz_generated.deepcopy --go-header-file ./../../hack/boilerplate/boilerplate.go.txt  -i ./
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TrustedTask wraps the Task and verify if it is tampered or not.
type TrustedTask struct {
	v1beta1.Task
}

// Verify that TrustedTaskRun adheres to the appropriate interfaces.
var (
	_ apis.Defaultable = (*TrustedTaskRun)(nil)
	_ apis.Validatable = (*TrustedTaskRun)(nil)
)

// Validate the TaskRun is tampered or not.
func (tr *TrustedTask) Validate(ctx context.Context) (errs *apis.FieldError) {
	if !apis.IsInCreate(ctx){
		return nil
	}
 /*
	k8sclient := kubeclient.Get(ctx)
	config, err := rest.InClusterConfig()
	if err != nil {
		return apis.ErrGeneric(err.Error())
	}
	tektonClient, err := versioned.NewForConfig(config)
	if err != nil {
		return apis.ErrGeneric(err.Error())
	}


	cp := copyTrustedTaskRun(tr)
	if errs := errs.Also(cp.verifyTask(ctx, k8sclient, tektonClient)); errs != nil {
		return errs
	}*/
	return nil
}

// SetDefaults is not used.
func (tr *TrustedTask) SetDefaults(ctx context.Context) {
}
