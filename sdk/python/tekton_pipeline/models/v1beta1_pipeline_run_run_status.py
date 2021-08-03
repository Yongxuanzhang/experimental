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


import pprint
import re  # noqa: F401

import six

from tekton_pipeline.configuration import Configuration


class V1beta1PipelineRunRunStatus(object):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    """
    Attributes:
      openapi_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    openapi_types = {
        'pipeline_task_name': 'str',
        'status': 'GithubComTektoncdPipelinePkgApisRunV1alpha1RunStatus',
        'when_expressions': 'list[V1beta1WhenExpression]'
    }

    attribute_map = {
        'pipeline_task_name': 'pipelineTaskName',
        'status': 'status',
        'when_expressions': 'whenExpressions'
    }

    def __init__(self, pipeline_task_name=None, status=None, when_expressions=None, local_vars_configuration=None):  # noqa: E501
        """V1beta1PipelineRunRunStatus - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._pipeline_task_name = None
        self._status = None
        self._when_expressions = None
        self.discriminator = None

        if pipeline_task_name is not None:
            self.pipeline_task_name = pipeline_task_name
        if status is not None:
            self.status = status
        if when_expressions is not None:
            self.when_expressions = when_expressions

    @property
    def pipeline_task_name(self):
        """Gets the pipeline_task_name of this V1beta1PipelineRunRunStatus.  # noqa: E501

        PipelineTaskName is the name of the PipelineTask.  # noqa: E501

        :return: The pipeline_task_name of this V1beta1PipelineRunRunStatus.  # noqa: E501
        :rtype: str
        """
        return self._pipeline_task_name

    @pipeline_task_name.setter
    def pipeline_task_name(self, pipeline_task_name):
        """Sets the pipeline_task_name of this V1beta1PipelineRunRunStatus.

        PipelineTaskName is the name of the PipelineTask.  # noqa: E501

        :param pipeline_task_name: The pipeline_task_name of this V1beta1PipelineRunRunStatus.  # noqa: E501
        :type: str
        """

        self._pipeline_task_name = pipeline_task_name

    @property
    def status(self):
        """Gets the status of this V1beta1PipelineRunRunStatus.  # noqa: E501


        :return: The status of this V1beta1PipelineRunRunStatus.  # noqa: E501
        :rtype: GithubComTektoncdPipelinePkgApisRunV1alpha1RunStatus
        """
        return self._status

    @status.setter
    def status(self, status):
        """Sets the status of this V1beta1PipelineRunRunStatus.


        :param status: The status of this V1beta1PipelineRunRunStatus.  # noqa: E501
        :type: GithubComTektoncdPipelinePkgApisRunV1alpha1RunStatus
        """

        self._status = status

    @property
    def when_expressions(self):
        """Gets the when_expressions of this V1beta1PipelineRunRunStatus.  # noqa: E501

        WhenExpressions is the list of checks guarding the execution of the PipelineTask  # noqa: E501

        :return: The when_expressions of this V1beta1PipelineRunRunStatus.  # noqa: E501
        :rtype: list[V1beta1WhenExpression]
        """
        return self._when_expressions

    @when_expressions.setter
    def when_expressions(self, when_expressions):
        """Sets the when_expressions of this V1beta1PipelineRunRunStatus.

        WhenExpressions is the list of checks guarding the execution of the PipelineTask  # noqa: E501

        :param when_expressions: The when_expressions of this V1beta1PipelineRunRunStatus.  # noqa: E501
        :type: list[V1beta1WhenExpression]
        """

        self._when_expressions = when_expressions

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.openapi_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, V1beta1PipelineRunRunStatus):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, V1beta1PipelineRunRunStatus):
            return True

        return self.to_dict() != other.to_dict()
