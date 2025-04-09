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
from tests.unit.normal.fixtures import *  # pylint: disable=unused-wildcard-import, wildcard-import


class TestConnector(BaseTest):
    """
    Class for testing the AnyRunConnector
    """

    def test_connectivity(self, test_connectivity: str) -> None:
        """
        Test the connection to AnyRun API
        """
        in_json = json.loads(test_connectivity)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None
        # assert summary.get("total_objects") == summary.get("total_objects_successful")

    def test_get_url_reputation(self, test_get_url_reputation: str) -> None:
        """
        Test the get_url_reputation action
        """
        in_json = json.loads(test_get_url_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_file_reputation(self, test_get_file_reputation: str) -> None:
        """
        Test the get_file_reputation action
        """
        in_json = json.loads(test_get_file_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_domain_reputation(self, test_get_domain_reputation: str) -> None:
        """
        Test the get_domain_reputation action
        """
        in_json = json.loads(test_get_domain_reputation)
        ret_val = self._execute_action(in_json)

        summary = ret_val.get("result_summary")

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None
        # assert summary.get("total_objects") == summary.get("total_objects_successful")

    def test_get_ip_reputation(self, test_get_ip_reputation: str) -> None:
        """
        Test the get_ip_reputation action
        """
        in_json = json.loads(test_get_ip_reputation)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_report(self, test_get_report: str) -> None:
        """
        Test the get_report action
        """
        in_json = json.loads(test_get_report)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_ioc(self, test_get_ioc: str) -> None:
        """
        Test the get_ioc action
        """
        in_json = json.loads(test_get_ioc)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_detonate_url(self, test_detonate_url: str) -> None:
        """
        Test the detonate_url action
        """
        in_json = json.loads(test_detonate_url)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_detonate_file(self, test_detonate_file: str) -> None:
        """
        Test the detonate_file action
        """
        # This test requires a valid vault_id,
        # which would need to be created during testing
        # pytest.skip("Requires a valid vault_id")
        in_json = json.loads(test_detonate_file)

        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_intelligence(self, test_get_intelligence: str) -> None:
        """
        Test the get_intelligence action
        """
        in_json = json.loads(test_get_intelligence)
        ret_val = self._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None
