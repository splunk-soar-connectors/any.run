# Copyright (c) 2025 Splunk Inc.
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
import json

from tests.unit.base import BaseTest
from tests.unit.broken.fixtures import *  # pylint: disable=unused-wildcard-import, wildcard-import


class TestBrokenConnector(BaseTest):
    """
    Class for testing the AnyRunConnector
    """

    def test_broken_get_url_reputation(self, test_broken_get_url_reputation: str) -> None:
        """
        Test the broken get_url_reputation action
        """
        in_json = json.loads(test_broken_get_url_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_get_file_reputation(self, test_broken_get_file_reputation: str) -> None:
        """
        Test the broken get_file_reputation action
        """
        in_json = json.loads(test_broken_get_file_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_get_domain_reputation(self, test_broken_get_domain_reputation: str) -> None:
        """
        Test the broken get_domain_reputation action
        """
        in_json = json.loads(test_broken_get_domain_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_get_ip_reputation(self, test_broken_get_ip_reputation: str) -> None:
        """
        Test the broken get_ip_reputation action
        """
        in_json = json.loads(test_broken_get_ip_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_get_report(self, test_broken_get_report: str) -> None:
        """
        Test the broken get_report action
        """
        in_json = json.loads(test_broken_get_report)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_get_ioc(self, test_broken_get_ioc: str) -> None:
        """
        Test the broken get_ioc action
        """
        in_json = json.loads(test_broken_get_ioc)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_detonate_url(self, test_broken_detonate_url: str) -> None:
        """
        Test the broken detonate_url action
        """
        in_json = json.loads(test_broken_detonate_url)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_detonate_url_with_android_os(self, test_broken_detonate_url_with_android_os: str) -> None:
        """
        Test the broken detonate_url action with android os
        """
        in_json = json.loads(test_broken_detonate_url_with_android_os)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None

    def test_broken_detonate_file(self, test_broken_detonate_file: str) -> None:
        """
        Test the broken detonate_file action
        """
        in_json = json.loads(test_broken_detonate_file)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "failed"

        assert ret_val is not None
