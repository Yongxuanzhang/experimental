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
from tekton_pipeline.models.v1beta1_param_spec import V1beta1ParamSpec  # noqa: E501
from tekton_pipeline.rest import ApiException

class TestV1beta1ParamSpec(unittest.TestCase):
    """V1beta1ParamSpec unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test V1beta1ParamSpec
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # model = tekton_pipeline.models.v1beta1_param_spec.V1beta1ParamSpec()  # noqa: E501
        if include_optional :
            return V1beta1ParamSpec(
                default = tekton_pipeline.models.v1beta1/array_or_string.v1beta1.ArrayOrString(
                    array_val = [
                        '0'
                        ], 
                    string_val = '0', 
                    type = '0', ), 
                description = '0', 
                name = '0', 
                type = '0'
            )
        else :
            return V1beta1ParamSpec(
                name = '0',
        )

    def testV1beta1ParamSpec(self):
        """Test V1beta1ParamSpec"""
        inst_req_only = self.make_instance(include_optional=False)
        inst_req_and_optional = self.make_instance(include_optional=True)


if __name__ == '__main__':
    unittest.main()
