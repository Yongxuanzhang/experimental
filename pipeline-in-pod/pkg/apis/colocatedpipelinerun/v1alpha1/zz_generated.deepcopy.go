//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2020 The Knative Authors

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	v1beta1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ChildStatus) DeepCopyInto(out *ChildStatus) {
	*out = *in
	if in.Spec != nil {
		in, out := &in.Spec, &out.Spec
		*out = new(v1beta1.TaskSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.StepStatuses != nil {
		in, out := &in.StepStatuses, &out.StepStatuses
		*out = make([]v1beta1.StepState, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.TaskRunResults != nil {
		in, out := &in.TaskRunResults, &out.TaskRunResults
		*out = make([]v1beta1.TaskRunResult, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ChildStatus.
func (in *ChildStatus) DeepCopy() *ChildStatus {
	if in == nil {
		return nil
	}
	out := new(ChildStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ColocatedPipelineRun) DeepCopyInto(out *ColocatedPipelineRun) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ColocatedPipelineRun.
func (in *ColocatedPipelineRun) DeepCopy() *ColocatedPipelineRun {
	if in == nil {
		return nil
	}
	out := new(ColocatedPipelineRun)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ColocatedPipelineRun) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ColocatedPipelineRunList) DeepCopyInto(out *ColocatedPipelineRunList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ColocatedPipelineRun, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ColocatedPipelineRunList.
func (in *ColocatedPipelineRunList) DeepCopy() *ColocatedPipelineRunList {
	if in == nil {
		return nil
	}
	out := new(ColocatedPipelineRunList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ColocatedPipelineRunList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ColocatedPipelineRunSpec) DeepCopyInto(out *ColocatedPipelineRunSpec) {
	*out = *in
	if in.PipelineRef != nil {
		in, out := &in.PipelineRef, &out.PipelineRef
		*out = new(v1beta1.PipelineRef)
		(*in).DeepCopyInto(*out)
	}
	if in.PipelineSpec != nil {
		in, out := &in.PipelineSpec, &out.PipelineSpec
		*out = new(v1beta1.PipelineSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Timeouts != nil {
		in, out := &in.Timeouts, &out.Timeouts
		*out = new(v1beta1.TimeoutFields)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ColocatedPipelineRunSpec.
func (in *ColocatedPipelineRunSpec) DeepCopy() *ColocatedPipelineRunSpec {
	if in == nil {
		return nil
	}
	out := new(ColocatedPipelineRunSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ColocatedPipelineRunStatus) DeepCopyInto(out *ColocatedPipelineRunStatus) {
	*out = *in
	in.Status.DeepCopyInto(&out.Status)
	in.ColocatedPipelineRunStatusFields.DeepCopyInto(&out.ColocatedPipelineRunStatusFields)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ColocatedPipelineRunStatus.
func (in *ColocatedPipelineRunStatus) DeepCopy() *ColocatedPipelineRunStatus {
	if in == nil {
		return nil
	}
	out := new(ColocatedPipelineRunStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ColocatedPipelineRunStatusFields) DeepCopyInto(out *ColocatedPipelineRunStatusFields) {
	*out = *in
	if in.StartTime != nil {
		in, out := &in.StartTime, &out.StartTime
		*out = (*in).DeepCopy()
	}
	if in.CompletionTime != nil {
		in, out := &in.CompletionTime, &out.CompletionTime
		*out = (*in).DeepCopy()
	}
	if in.PipelineSpec != nil {
		in, out := &in.PipelineSpec, &out.PipelineSpec
		*out = new(v1beta1.PipelineSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.ChildStatuses != nil {
		in, out := &in.ChildStatuses, &out.ChildStatuses
		*out = make([]ChildStatus, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ColocatedPipelineRunStatusFields.
func (in *ColocatedPipelineRunStatusFields) DeepCopy() *ColocatedPipelineRunStatusFields {
	if in == nil {
		return nil
	}
	out := new(ColocatedPipelineRunStatusFields)
	in.DeepCopyInto(out)
	return out
}
