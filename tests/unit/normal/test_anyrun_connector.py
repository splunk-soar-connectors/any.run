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

from tests.unit.base import BaseRunner
from tests.unit.normal.fixtures import *  # pylint: disable=unused-wildcard-import, wildcard-import


class TestConnector:
    def test_connectivity(self, test_connectivity: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_connectivity)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_url_reputation(self, test_get_url_reputation: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_url_reputation)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_file_reputation(self, test_get_file_reputation: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_file_reputation)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_domain_reputation(self, test_get_domain_reputation: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_domain_reputation)
        ret_val = runner._execute_action(in_json)

        summary = ret_val.get("result_summary")

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_ip_reputation(self, test_get_ip_reputation: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_ip_reputation)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_report(self, test_get_report: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_report)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_report_html(self, test_get_report_html: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_report_html)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

    def test_get_report_stix(self, test_get_report_stix: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_report_stix)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_get_report_misp(self, test_get_report_misp: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_report_misp)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

    def test_get_ioc(self, test_get_ioc: str) -> None:
        """
        Test the get_ioc action
        """
        runner = BaseRunner()
        in_json = json.loads(test_get_ioc)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_detonate_url_android(self, test_detonate_url_android: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_detonate_url_android)
        ret_val = runner._execute_action(in_json)

        try:
            task_id = ret_val.get("result_data", [])[0].get("data")[0].get("taskid")
        except Exception as e:
            raise Exception(f"Error in detonating file: {e} | {ret_val}")

        runner.stop_task(task_id)

        assert task_id is not None

    def test_detonate_url_windows(self, test_detonate_url_windows: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_detonate_url_windows)
        ret_val = runner._execute_action(in_json)

        try:
            task_id = ret_val.get("result_data", [])[0].get("data")[0].get("taskid")
        except Exception as e:
            raise Exception(f"Error in detonating file: {e} | {ret_val}")

        runner.stop_task(task_id)

        assert task_id is not None

    def test_detonate_url_linux(self, test_detonate_url_linux: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_detonate_url_linux)
        ret_val = runner._execute_action(in_json)

        try:
            task_id = ret_val.get("result_data", [])[0].get("data")[0].get("taskid")
        except Exception as e:
            raise Exception(f"Error in detonating file: {e} | {ret_val}")

        runner.stop_task(task_id)

        assert task_id is not None

    def test_detonate_file_windows(self, test_detonate_file_windows: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_detonate_file_windows)

        ret_val = runner._execute_action(in_json)

        try:
            task_id = ret_val.get("result_data", [])[0].get("data")[0].get("taskid")
        except Exception as e:
            raise Exception(f"Error in detonating file: {e} | {ret_val}")

        runner.stop_task(task_id)

        assert task_id is not None

    def test_detonate_file_linux(self, test_detonate_file_linux: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_detonate_file_linux)
        ret_val = runner._execute_action(in_json)

        try:
            task_id = ret_val.get("result_data", [])[0].get("data")[0].get("taskid")
        except Exception as e:
            raise Exception(f"Error in detonating file: {e} | {ret_val}")

        runner.stop_task(task_id)

        assert task_id is not None

    def test_detonate_file_android(self, test_detonate_file_android: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_detonate_file_android)
        ret_val = runner._execute_action(in_json)

        try:
            task_id = ret_val.get("result_data", [])[0].get("data")[0].get("taskid")
        except Exception as e:
            raise Exception(f"Error in detonating file: {e} | {ret_val}")

        runner.stop_task(task_id)

    def test_get_intelligence(self, test_get_intelligence: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_intelligence)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", {})
        for result in res:
            assert result.get("status") == "success"

        assert ret_val is not None

    def test_download_pcap(self, test_download_pcap_fixture: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_download_pcap_fixture)
        try:
            ret_val = runner._execute_action(in_json)
            res = ret_val.get("result_data", [])[0].get("data")[0]

            assert res.get("vault_id") is not None, "Vault ID is not found"
            assert res.get("taskid") is not None, "Task ID is not found"
            assert res.get("info") is not None, "Info is not found"
        except Exception as e:
            raise Exception(e)

    def test_get_analysis_verdict(self, test_get_analysis_verdict: str) -> None:
        runner = BaseRunner()
        in_json = json.loads(test_get_analysis_verdict)
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", [])[0].get("data")[0]
        assert res.get("verdict") is not None

    def test_delete_submission(self, test_delete_submission: str, test_detonate_file_windows: str) -> None:
        runner = BaseRunner()
        try:
            result = runner._execute_action(json.loads(test_detonate_file_windows))

            task_id = result.get("result_data", [])[0].get("data")[0].get("taskid")

            runner.stop_task(task_id)
        except Exception as e:
            raise Exception(f"Error in getting task id: {e} | {result}")

        runner = BaseRunner()

        in_json = json.loads(test_delete_submission.replace("dummy", task_id))
        ret_val = runner._execute_action(in_json)

        res = ret_val.get("result_data", [])[0]
        status = res.get("status")

        if status == "failed":
            raise Exception(f"Error in deleting submission: {status} | {res.get('message')}")

        data = res.get("data")[0].get("taskid", None)

        assert status == "success", f"Error in deleting submission: {status}"
        assert data is not None, f"Error in deleting submission: {data}"

        assert ret_val is not None
