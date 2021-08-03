# Copyright 2021 The Tekton Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# coding: utf-8

"""
    Tekton

    Tekton Pipeline  # noqa: E501

    The version of the OpenAPI document: v0.17.2
    Generated by: https://openapi-generator.tech
"""


from __future__ import absolute_import

import unittest
import datetime

import tekton_pipeline
from tekton_pipeline.models.v1beta1_pipeline_run_status import V1beta1PipelineRunStatus  # noqa: E501
from tekton_pipeline.rest import ApiException

class TestV1beta1PipelineRunStatus(unittest.TestCase):
    """V1beta1PipelineRunStatus unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test V1beta1PipelineRunStatus
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # model = tekton_pipeline.models.v1beta1_pipeline_run_status.V1beta1PipelineRunStatus()  # noqa: E501
        if include_optional :
            return V1beta1PipelineRunStatus(
                annotations = {
                    'key' : '0'
                    }, 
                completion_time = None, 
                conditions = [
                    None
                    ], 
                observed_generation = 56, 
                pipeline_results = [
                    tekton_pipeline.models.v1beta1/pipeline_run_result.v1beta1.PipelineRunResult(
                        name = '0', 
                        value = '0', )
                    ], 
                pipeline_spec = tekton_pipeline.models.v1beta1/pipeline_spec.v1beta1.PipelineSpec(
                    description = '0', 
                    finally = [
                        tekton_pipeline.models.v1beta1/pipeline_task.v1beta1.PipelineTask(
                            conditions = [
                                tekton_pipeline.models.v1beta1/pipeline_task_condition.v1beta1.PipelineTaskCondition(
                                    condition_ref = '0', 
                                    params = [
                                        tekton_pipeline.models.v1beta1/param.v1beta1.Param(
                                            name = '0', 
                                            value = tekton_pipeline.models.v1beta1/array_or_string.v1beta1.ArrayOrString(
                                                array_val = [
                                                    '0'
                                                    ], 
                                                string_val = '0', 
                                                type = '0', ), )
                                        ], 
                                    resources = [
                                        tekton_pipeline.models.v1beta1/pipeline_task_input_resource.v1beta1.PipelineTaskInputResource(
                                            from = [
                                                '0'
                                                ], 
                                            name = '0', 
                                            resource = '0', )
                                        ], )
                                ], 
                            name = '0', 
                            params = [
                                tekton_pipeline.models.v1beta1/param.v1beta1.Param(
                                    name = '0', 
                                    value = tekton_pipeline.models.v1beta1/array_or_string.v1beta1.ArrayOrString(
                                        array_val = [
                                            '0'
                                            ], 
                                        string_val = '0', 
                                        type = '0', ), )
                                ], 
                            resources = tekton_pipeline.models.v1beta1/pipeline_task_resources.v1beta1.PipelineTaskResources(
                                inputs = [
                                    tekton_pipeline.models.v1beta1/pipeline_task_input_resource.v1beta1.PipelineTaskInputResource(
                                        name = '0', 
                                        resource = '0', )
                                    ], 
                                outputs = [
                                    tekton_pipeline.models.v1beta1/pipeline_task_output_resource.v1beta1.PipelineTaskOutputResource(
                                        name = '0', 
                                        resource = '0', )
                                    ], ), 
                            retries = 56, 
                            run_after = [
                                '0'
                                ], 
                            task_ref = tekton_pipeline.models.v1beta1/task_ref.v1beta1.TaskRef(
                                api_version = '0', 
                                bundle = '0', 
                                kind = '0', 
                                name = '0', ), 
                            task_spec = tekton_pipeline.models.v1beta1/embedded_task.v1beta1.EmbeddedTask(
                                description = '0', 
                                metadata = tekton_pipeline.models.v1beta1/pipeline_task_metadata.v1beta1.PipelineTaskMetadata(
                                    annotations = {
                                        'key' : '0'
                                        }, 
                                    labels = {
                                        'key' : '0'
                                        }, ), 
                                results = [
                                    tekton_pipeline.models.v1beta1/task_result.v1beta1.TaskResult(
                                        description = '0', 
                                        name = '0', )
                                    ], 
                                sidecars = [
                                    tekton_pipeline.models.v1beta1/sidecar.v1beta1.Sidecar(
                                        args = [
                                            '0'
                                            ], 
                                        command = [
                                            '0'
                                            ], 
                                        env = [
                                            None
                                            ], 
                                        env_from = [
                                            None
                                            ], 
                                        image = '0', 
                                        image_pull_policy = '0', 
                                        lifecycle = None, 
                                        liveness_probe = None, 
                                        name = '0', 
                                        ports = [
                                            None
                                            ], 
                                        readiness_probe = None, 
                                        script = '0', 
                                        security_context = None, 
                                        startup_probe = None, 
                                        stdin = True, 
                                        stdin_once = True, 
                                        termination_message_path = '0', 
                                        termination_message_policy = '0', 
                                        tty = True, 
                                        volume_devices = [
                                            None
                                            ], 
                                        volume_mounts = [
                                            None
                                            ], 
                                        working_dir = '0', )
                                    ], 
                                step_template = None, 
                                steps = [
                                    tekton_pipeline.models.v1beta1/step.v1beta1.Step(
                                        image = '0', 
                                        image_pull_policy = '0', 
                                        lifecycle = None, 
                                        liveness_probe = None, 
                                        name = '0', 
                                        readiness_probe = None, 
                                        script = '0', 
                                        security_context = None, 
                                        startup_probe = None, 
                                        stdin = True, 
                                        stdin_once = True, 
                                        termination_message_path = '0', 
                                        termination_message_policy = '0', 
                                        timeout = None, 
                                        tty = True, 
                                        working_dir = '0', )
                                    ], 
                                volumes = [
                                    None
                                    ], 
                                workspaces = [
                                    tekton_pipeline.models.v1beta1/workspace_declaration.v1beta1.WorkspaceDeclaration(
                                        description = '0', 
                                        mount_path = '0', 
                                        name = '0', 
                                        optional = True, 
                                        read_only = True, )
                                    ], ), 
                            timeout = None, 
                            when = [
                                tekton_pipeline.models.v1beta1/when_expression.v1beta1.WhenExpression(
                                    input = '0', 
                                    operator = '0', 
                                    values = [
                                        '0'
                                        ], 
                                    input = '0', 
                                    operator = '0', 
                                    values = [
                                        '0'
                                        ], )
                                ], 
                            workspaces = [
                                tekton_pipeline.models.v1beta1/workspace_pipeline_task_binding.v1beta1.WorkspacePipelineTaskBinding(
                                    name = '0', 
                                    sub_path = '0', 
                                    workspace = '0', )
                                ], )
                        ], 
                    params = [
                        tekton_pipeline.models.v1beta1/param_spec.v1beta1.ParamSpec(
                            default = tekton_pipeline.models.v1beta1/array_or_string.v1beta1.ArrayOrString(
                                array_val = [
                                    '0'
                                    ], 
                                string_val = '0', 
                                type = '0', ), 
                            description = '0', 
                            name = '0', 
                            type = '0', )
                        ], 
                    resources = [
                        tekton_pipeline.models.v1beta1/pipeline_declared_resource.v1beta1.PipelineDeclaredResource(
                            name = '0', 
                            optional = True, 
                            type = '0', )
                        ], 
                    results = [
                        tekton_pipeline.models.v1beta1/pipeline_result.v1beta1.PipelineResult(
                            description = '0', 
                            name = '0', 
                            value = '0', )
                        ], 
                    tasks = [
                        tekton_pipeline.models.v1beta1/pipeline_task.v1beta1.PipelineTask(
                            name = '0', 
                            retries = 56, 
                            timeout = None, )
                        ], 
                    workspaces = [
                        tekton_pipeline.models.v1beta1/pipeline_workspace_declaration.v1beta1.PipelineWorkspaceDeclaration(
                            description = '0', 
                            name = '0', 
                            optional = True, )
                        ], ), 
                skipped_tasks = [
                    tekton_pipeline.models.v1beta1/skipped_task.v1beta1.SkippedTask(
                        name = '0', 
                        when_expressions = [
                            tekton_pipeline.models.v1beta1/when_expression.v1beta1.WhenExpression(
                                input = '0', 
                                operator = '0', 
                                values = [
                                    '0'
                                    ], 
                                input = '0', 
                                operator = '0', 
                                values = [
                                    '0'
                                    ], )
                            ], )
                    ], 
                start_time = None, 
                task_runs = {
                    'key' : tekton_pipeline.models.v1beta1/pipeline_run_task_run_status.v1beta1.PipelineRunTaskRunStatus(
                        condition_checks = {
                            'key' : tekton_pipeline.models.v1beta1/pipeline_run_condition_check_status.v1beta1.PipelineRunConditionCheckStatus(
                                condition_name = '0', 
                                status = tekton_pipeline.models.v1beta1/condition_check_status.v1beta1.ConditionCheckStatus(
                                    annotations = {
                                        'key' : '0'
                                        }, 
                                    check = None, 
                                    completion_time = None, 
                                    conditions = [
                                        None
                                        ], 
                                    observed_generation = 56, 
                                    pod_name = '0', 
                                    start_time = None, ), )
                            }, 
                        pipeline_task_name = '0', 
                        status = tekton_pipeline.models.v1beta1/task_run_status.v1beta1.TaskRunStatus(
                            cloud_events = [
                                tekton_pipeline.models.v1beta1/cloud_event_delivery.v1beta1.CloudEventDelivery(
                                    target = '0', )
                                ], 
                            completion_time = None, 
                            observed_generation = 56, 
                            pod_name = '0', 
                            resources_result = [
                                tekton_pipeline.models.v1beta1/pipeline_resource_result.v1beta1.PipelineResourceResult(
                                    key = '0', 
                                    resource_name = '0', 
                                    resource_ref = tekton_pipeline.models.v1beta1/pipeline_resource_ref.v1beta1.PipelineResourceRef(
                                        api_version = '0', 
                                        name = '0', ), 
                                    type = '0', 
                                    value = '0', )
                                ], 
                            retries_status = [
                                tekton_pipeline.models.v1beta1/task_run_status.v1beta1.TaskRunStatus(
                                    completion_time = None, 
                                    observed_generation = 56, 
                                    pod_name = '0', 
                                    sidecars = [
                                        tekton_pipeline.models.v1beta1/sidecar_state.v1beta1.SidecarState(
                                            container = '0', 
                                            image_id = '0', 
                                            name = '0', 
                                            running = None, 
                                            terminated = None, 
                                            waiting = None, )
                                        ], 
                                    start_time = None, 
                                    steps = [
                                        tekton_pipeline.models.v1beta1/step_state.v1beta1.StepState(
                                            container = '0', 
                                            image_id = '0', 
                                            name = '0', 
                                            running = None, 
                                            terminated = None, 
                                            waiting = None, )
                                        ], 
                                    task_results = [
                                        tekton_pipeline.models.v1beta1/task_run_result.v1beta1.TaskRunResult(
                                            name = '0', 
                                            value = '0', )
                                        ], 
                                    task_spec = tekton_pipeline.models.v1beta1/task_spec.v1beta1.TaskSpec(
                                        description = '0', 
                                        params = [
                                            tekton_pipeline.models.v1beta1/param_spec.v1beta1.ParamSpec(
                                                default = tekton_pipeline.models.v1beta1/array_or_string.v1beta1.ArrayOrString(
                                                    array_val = [
                                                        '0'
                                                        ], 
                                                    string_val = '0', 
                                                    type = '0', ), 
                                                description = '0', 
                                                name = '0', 
                                                type = '0', )
                                            ], 
                                        resources = tekton_pipeline.models.v1beta1/task_resources.v1beta1.TaskResources(
                                            inputs = [
                                                tekton_pipeline.models.v1beta1/task_resource.v1beta1.TaskResource(
                                                    description = '0', 
                                                    name = '0', 
                                                    optional = True, 
                                                    target_path = '0', 
                                                    type = '0', )
                                                ], 
                                            outputs = [
                                                tekton_pipeline.models.v1beta1/task_resource.v1beta1.TaskResource(
                                                    description = '0', 
                                                    name = '0', 
                                                    optional = True, 
                                                    target_path = '0', 
                                                    type = '0', )
                                                ], ), 
                                        results = [
                                            tekton_pipeline.models.v1beta1/task_result.v1beta1.TaskResult(
                                                description = '0', 
                                                name = '0', )
                                            ], 
                                        step_template = None, 
                                        volumes = [
                                            None
                                            ], 
                                        workspaces = [
                                            tekton_pipeline.models.v1beta1/workspace_declaration.v1beta1.WorkspaceDeclaration(
                                                description = '0', 
                                                mount_path = '0', 
                                                name = '0', 
                                                optional = True, 
                                                read_only = True, )
                                            ], ), )
                                ], 
                            sidecars = [
                                tekton_pipeline.models.v1beta1/sidecar_state.v1beta1.SidecarState(
                                    container = '0', 
                                    image_id = '0', 
                                    name = '0', 
                                    running = None, 
                                    terminated = None, 
                                    waiting = None, )
                                ], 
                            start_time = None, 
                            steps = [
                                tekton_pipeline.models.v1beta1/step_state.v1beta1.StepState(
                                    container = '0', 
                                    image_id = '0', 
                                    name = '0', 
                                    running = None, 
                                    terminated = None, 
                                    waiting = None, )
                                ], 
                            task_results = [
                                tekton_pipeline.models.v1beta1/task_run_result.v1beta1.TaskRunResult(
                                    name = '0', 
                                    value = '0', )
                                ], 
                            task_spec = tekton_pipeline.models.v1beta1/task_spec.v1beta1.TaskSpec(
                                description = '0', 
                                step_template = None, ), ), 
                        when_expressions = [
                            tekton_pipeline.models.v1beta1/when_expression.v1beta1.WhenExpression(
                                input = '0', 
                                operator = '0', 
                                values = [
                                    '0'
                                    ], 
                                input = '0', 
                                operator = '0', 
                                values = [
                                    '0'
                                    ], )
                            ], )
                    }
            )
        else :
            return V1beta1PipelineRunStatus(
        )

    def testV1beta1PipelineRunStatus(self):
        """Test V1beta1PipelineRunStatus"""
        inst_req_only = self.make_instance(include_optional=False)
        inst_req_and_optional = self.make_instance(include_optional=True)


if __name__ == '__main__':
    unittest.main()
