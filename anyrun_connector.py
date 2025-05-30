# File: anyrun_connector.py
#
# Copyright (c) ANYRUN FZCO, 2025
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# pylint: disable=wildcard-import
# pylint: disable=line-too-long


import json
import os
import time
from typing import Literal

# Phantom App imports
import phantom.app as phantom
import phantom.rules as phantom_rules
import requests

# Usage of the consts file is recommended
from anyrun.connectors import LookupConnector, SandboxConnector
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from anyrun_consts import *
from utils.get_iocs import extract_iocs
from utils.intelligence_processor import IntelligenceProcessor
from utils.reputation import Reputation


class AnyRunConnector(BaseConnector):
    _anyrun_sandbox: SandboxConnector

    def __init__(self):
        super().__init__()
        self._state = None
        self._server = None
        self._api_key = None
        self._timeout = None

    def _get_error_message_from_exception(self, exception: Exception) -> str:
        """This method is used to get appropriate error messages from the exception.
        :param exception: Exception object
        :return: error message
        """
        error_code = ANYRUN_ERROR_CODE_MSG
        error_msg = ANYRUN_ERROR_MSG_UNAVAILABLE

        try:
            if exception.args:
                if len(exception.args) > 1:
                    error_code = exception.args[0]
                    error_msg = exception.args[1]
                elif len(exception.args) == 1:
                    error_msg = exception.args[0]
        except Exception:  # pylint: disable=broad-except
            pass

        try:
            if error_code in ANYRUN_ERROR_CODE_MSG:
                error_text = f"Error Message: {error_msg}"
            else:
                error_text = f"Error Code: {error_code}. Error Message: {error_msg}"
        except Exception:  # pylint: disable=broad-except
            self.debug_print("Error occurred while parsing error message")
            error_text = ANYRUN_PARSE_ERROR_MSG

        return error_text

    def _process_reputation_response(
        self,
        action_result: ActionResult,
        tasks: list[dict],
        action_id: str,
        is_url_file: bool = True,
    ) -> str:
        """
        Process reputation response for URL, file, domain, and IP actions

        :param action_result: ActionResult object to update with data
        :param tasks: List of tasks from reputation lookup
        :param action_id: Action ID for error messages
        :param is_url_file: Boolean to determine if this is URL/file reputation (True) or domain/IP (False)
        :return: phantom.APP_SUCCESS/phantom.APP_ERROR
        """
        try:
            levels = {0: "No threats detected", 1: "Suspicious activity", 2: "Malicious activity"}
            for task in tasks:
                if is_url_file:
                    if "uuid" not in task:
                        task["uuid"] = task["related"].rsplit("/")[-1]
                    if "verdict" not in task:
                        task["verdict"] = levels[task["threatLevel"]]
                    if "mainObject" not in task:
                        task["mainObject"] = {"name": task.pop("name"), "hashes": task.pop("hashes")}
                else:
                    task["verdict"] = levels[task["threatLevel"]]
            action_result.add_data({"tasks": tasks})
            action_result.update_summary({"total_objects": len(tasks)})
            return phantom.APP_SUCCESS
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(action_id, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

    def _get_iocs(self, taskid: str) -> list[dict]:
        return extract_iocs(self._windows_sandbox, taskid, self.get_container_id())

    def _get_reputation(
        self, entity_type: Literal["url", "hash", "domainname", "ip"], param: dict, action_id: str, success_message: str
    ) -> list[dict]:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        entity = param[entity_type]
        search_in_public_tasks = param.get("search_in_public_tasks", False)

        # Making an API call
        self.save_progress(f"Requesting a list of reports for a {entity_type}: {entity}.")

        try:
            error_message = None
            if entity_type == "url":
                tasks = self._reputation.get_url_reputation(entity, search_in_public_tasks)
            elif entity_type == "hash":
                tasks = self._reputation.get_file_reputation(entity, search_in_public_tasks)
            elif entity_type == "domainname":
                tasks = self._reputation.get_domain_reputation(entity)
            elif entity_type == "ip":
                tasks = self._reputation.get_ip_reputation(entity)

        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(action_id, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(success_message.format(entity))

        # Processing server response
        ret_val = self._process_reputation_response(action_result, tasks, action_id, is_url_file=entity_type in ["url", "hash"])

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.set_status(phantom.APP_SUCCESS, success_message.format(entity))

        return action_result.get_status()

    def _normalize_api_key(self) -> str:
        """
        Normalize API key

        :return: Normalized API key
        """
        if "API-Key" in self._api_key:
            return self._api_key

        return "API-Key " + self._api_key

    def _handle_test_connectivity(self, param: dict) -> ActionResult:
        """
        Handle test connectivity

        NOTE: test connectivity does _NOT_ take any parameters
        i.e. the param dictionary passed to this handler will be empty.
        Also typically it does not add any data into an action_result either.
        The status and progress messages are more important.

        :param param: Parameters
        :return: ActionResult object
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        try:
            with self._windows_sandbox as sandbox:
                sandbox.get_user_limits()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = self._get_error_message_from_exception(exc)
            self.save_progress(ANYRUN_ERROR_TEST_CONNECTIVITY.format(error_message))
            return action_result.set_status(phantom.APP_ERROR, f"Could not connect to server. {error_message}")

        self.save_progress(ANYRUN_SUCCESS_TEST_CONNECTIVITY)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_url_reputation(self, param: dict) -> bool:
        """
        Handle get URL reputation

        :param param: Parameters
        :return: bool
        """
        return self._get_reputation(
            "url", param, action_id=ACTION_ID_ANYRUN_GET_URL_REPUTATION, success_message=ANYRUN_SUCCESS_GET_URL_REPUTATION
        )

    def _handle_get_file_reputation(self, param: dict) -> bool:
        """
        Handle get file reputation

        :param param: Parameters
        :return: bool
        """
        return self._get_reputation(
            "hash", param, action_id=ACTION_ID_ANYRUN_GET_FILE_REPUTATION, success_message=ANYRUN_SUCCESS_GET_FILE_REPUTATION
        )

    def _handle_get_domain_reputation(self, param: dict) -> bool:
        """
        Handle get domain reputation

        :param param: Parameters
        :return: bool
        """
        return self._get_reputation(
            "domainname", param, action_id=ACTION_ID_ANYRUN_GET_DOMAIN_REPUTATION, success_message=ANYRUN_SUCCESS_GET_DOMAIN_REPUTATION
        )

    def _handle_get_ip_reputation(self, param: dict) -> bool:
        """
        Handle get IP reputation

        :param param: Parameters
        :return: bool
        """
        return self._get_reputation("ip", param, action_id=ACTION_ID_ANYRUN_GET_IP_REPUTATION, success_message=ANYRUN_SUCCESS_GET_IP_REPUTATION)

    def _handle_get_report(self, param: dict, report_format: str = "summary") -> ActionResult:
        """
        Handle get report

        :param param: Parameters
        :return: ActionResult object
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Making an API call
        taskid = param["taskid"]
        self.save_progress(f"Requesting report for submission: {taskid}")
        try:
            with self._windows_sandbox as sandbox:
                for status in sandbox.get_task_status(taskid):
                    self.debug_print(f"Waiting for task to complete {taskid}: {status}")

                report = sandbox.get_analysis_report(taskid, report_format=report_format)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_REPORT, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_GET_REPORT.format(taskid))

        # Processing server response
        try:
            action_result.add_data(report)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_REPORT, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_GET_REPORT.format(taskid))

    def _handle_get_ioc(self, param: dict) -> ActionResult:
        """
        Handle get IoC

        :param param: Parameters
        :return: ActionResult object
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Making an API call
        taskid = param["taskid"]
        self.save_progress(f"Requesting IoC report for submission: {taskid}.")
        try:
            error_message = None
            with self._windows_sandbox as sandbox:
                for status in sandbox.get_task_status(taskid):
                    self.debug_print(f"Waiting for task to complete {taskid}: {status}")

                iocs = self._get_iocs(taskid)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_IOC, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_GET_IOC.format(taskid))

        # Processing server response
        try:
            action_result.add_data({"ioc": iocs})
            ret_val = self.save_artifacts(iocs)
            action_result.update_summary(
                {
                    "total_objects": len(iocs),
                }
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_IOC, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        if not ret_val[0]:
            return action_result.set_status(phantom.APP_ERROR, ret_val[1])

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_GET_IOC.format(taskid) + str(ret_val[1]))

    def _handle_detonate_url(self, param: dict, sandbox) -> ActionResult:
        """
        Handle detonate URL

        :param param: Parameters
        :return: ActionResult object
        """
        action_id = self.get_action_identifier()
        self.save_progress(f"In action handler for: {action_id}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(f"Detonating URL: {param['obj_url']}")
        param.pop("context", None)
        response = None
        while response is None:
            try:
                error_message = None
                with sandbox:
                    taskid = sandbox.run_url_analysis(**param)
                    response = {"taskid": taskid, "info": "URL detonated successfully."}

            except Exception as exc:  # pylint: disable=broad-exception-caught
                if "Parallel task limit" in str(exc):
                    time.sleep(5)
                    continue

                error_message = ANYRUN_REST_API_ERROR.format(action_id, self._get_error_message_from_exception(exc))
                return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_DETONATE_URL.format(param["obj_url"]))

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_DETONATE_URL.format(param["obj_url"]))

    def _handle_detonate_file(self, param: dict, sandbox) -> ActionResult:
        """
        Handle detonate file

        :param param: Parameters
        :return: ActionResult object
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param.pop("vault_id")
        param.pop("context", None)
        try:
            success, message, vault_meta_info = phantom_rules.vault_info(vault_id=vault_id)
            vault_meta_info = list(vault_meta_info)
            if not success or not vault_meta_info:
                error_message = f"Error Details: {message}" if message else ""
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "{}. {}".format(
                        ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("vault meta info", vault_id),
                        error_message,
                    ),
                )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return action_result.set_status(
                phantom.APP_ERROR,
                "{}. {}".format(
                    ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("vault meta info", vault_id),
                    self._get_error_message_from_exception(exc),
                ),
            )

        if len(vault_meta_info) > 1:
            self.save_progress(ANYRUN_VAULT_MULTIPLE_FILES_ERROR.format(vault_id))
        elif len(vault_meta_info) == 0:
            self.save_progress(ANYRUN_VAULT_NO_FILES_ERROR.format(vault_id))
            return action_result.set_status(phantom.APP_ERROR, ANYRUN_VAULT_NO_FILES_ERROR.format(vault_id))

        try:
            file_path = vault_meta_info[0].get("path")
            if not file_path:
                return action_result.set_status(phantom.APP_ERROR, ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("path", vault_id))
        except:  # pylint: disable=bare-except
            return action_result.set_status(phantom.APP_ERROR, ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("path", vault_id))

        # Making an API call
        self.save_progress(f"Detonating file with vault ID: {vault_id}")
        response = None
        while response is None:
            try:
                error_message = None
                with sandbox:
                    taskid = sandbox.run_file_analysis(file_path, **param)
                    response = {"taskid": taskid, "info": "File detonated successfully."}
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if "Parallel task limit" in str(exc):
                    time.sleep(5)
                    continue

                error_message = ANYRUN_REST_API_ERROR.format(self.get_action_identifier(), self._get_error_message_from_exception(exc))
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_DETONATE_FILE.format(vault_id))

        # Processing server response
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_DETONATE_FILE.format(vault_id))

    def _handle_get_intelligence(self, param: dict) -> ActionResult:
        """
        Handle get intelligence

        :param param: Parameters
        :return: ActionResult object
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Input validation
        try:
            data = {key: str(value) for key, value in param.items() if (key not in ["context"] and value not in ["", 0])}
            if "os" in data:
                data["os"] = data["os"].split()[1]
            if data == {}:
                data = {"query": "*"}
        except (AttributeError, TypeError, ValueError) as exc:
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_TI_PARAMS_VALIDATION_ERROR.format(error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        # Making an API call
        self.save_progress("Initiating Threat Intelligence lookup.")
        try:
            error_message = None
            with self._anyrun_threat_intelligence as lookup:
                response = lookup.get_intelligence(**data)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_INTELLIGENCE, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_GET_INTELLIGENCE)

        # Processing server response
        try:
            action_result.add_data({key: value for key, value in response.items() if value != []})

            processor = IntelligenceProcessor(response)
            summary = processor.summary

            action_result.update_summary(summary)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_INTELLIGENCE, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_GET_INTELLIGENCE)

    def _handle_download_pcap(self, param: dict) -> ActionResult:
        """
        Handle download PCAP
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        taskid = param["taskid"]

        vault_path = phantom_rules.Vault.get_vault_tmp_dir()
        with self._windows_sandbox as sandbox:
            sandbox.download_pcap(taskid, filepath=vault_path)

            if not os.path.exists(vault_path):
                return action_result.set_status(phantom.APP_ERROR, "Failed to download PCAP file.")

            files = os.listdir(vault_path)
            for fl in files:
                if fl.startswith(taskid):
                    file = fl
                    break

            filepath = os.path.join(vault_path, file)

            result, status, vault_id = phantom_rules.vault_add(container=self.get_container_id(), file_location=filepath, file_name=file)
            if not result:
                return action_result.set_status(phantom.APP_ERROR, status)

            action_result.add_data({"taskid": taskid, "vault_id": vault_id, "info": "PCAP downloaded successfully."})

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_DOWNLOAD_PCAP.format(taskid))

    def _handle_delete_submission(self, param: dict) -> ActionResult:
        """
        Handle delete submission
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        taskid = param["taskid"]
        try:
            error_message = None
            with self._windows_sandbox as sandbox:
                sandbox.delete_task(taskid)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_DELETE_SUBMISSION, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_DELETE_SUBMISSION.format(taskid))

        # Processing server response
        try:
            action_result.add_data({"taskid": taskid, "info": "Submission deleted successfully."})
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_IOC, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_DELETE_SUBMISSION.format(taskid))

    def _handle_get_analysis_verdict(self, param: dict) -> ActionResult:
        """
        Handle get analysis verdict
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        taskid = param["taskid"]
        try:
            error_message = None
            with self._windows_sandbox as sandbox:
                for status in sandbox.get_task_status(taskid):
                    self.debug_print(f"Waiting for task to complete {taskid}: {status}")

                verdict = sandbox.get_analysis_verdict(taskid)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_ANALYSIS_VERDICT, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        self.save_progress(ANYRUN_SUCCESS_GET_ANALYSIS_VERDICT.format(taskid))

        # Processing server response
        try:
            action_result.add_data({"verdict": verdict})
        except Exception as exc:  # pylint: disable=broad-exception-caught
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_ANALYSIS_VERDICT, self._get_error_message_from_exception(exc))
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_GET_ANALYSIS_VERDICT.format(taskid))

    def handle_action(self, param: dict) -> ActionResult:
        """
        Handle action

        :param param: Parameters
        :return: ActionResult object
        """
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == ACTION_ID_ANYRUN_GET_URL_REPUTATION:
            ret_val = self._handle_get_url_reputation(param)
        elif action_id == ACTION_ID_ANYRUN_GET_FILE_REPUTATION:
            ret_val = self._handle_get_file_reputation(param)
        elif action_id == ACTION_ID_ANYRUN_GET_DOMAIN_REPUTATION:
            ret_val = self._handle_get_domain_reputation(param)
        elif action_id == ACTION_ID_ANYRUN_GET_IP_REPUTATION:
            ret_val = self._handle_get_ip_reputation(param)
        elif action_id == ACTION_ID_ANYRUN_GET_REPORT:
            ret_val = self._handle_get_report(param)
        elif action_id == ACTION_ID_ANYRUN_GET_REPORT_STIX:
            ret_val = self._handle_get_report(param, report_format="stix")
        elif action_id == ACTION_ID_ANYRUN_GET_REPORT_HTML:
            ret_val = self._handle_get_report(param, report_format="html")
        elif action_id == ACTION_ID_ANYRUN_GET_REPORT_MISP:
            ret_val = self._handle_get_report(param, report_format="misp")
        elif action_id == ACTION_ID_ANYRUN_GET_IOC:
            ret_val = self._handle_get_ioc(param)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_URL_ANDROID:
            ret_val = self._handle_detonate_url(param, self._android_sandbox)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_URL_LINUX:
            ret_val = self._handle_detonate_url(param, self._linux_sandbox)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_URL_WINDOWS:
            ret_val = self._handle_detonate_url(param, self._windows_sandbox)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_FILE_ANDROID:
            ret_val = self._handle_detonate_file(param, self._android_sandbox)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_FILE_LINUX:
            ret_val = self._handle_detonate_file(param, self._linux_sandbox)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_FILE_WINDOWS:
            ret_val = self._handle_detonate_file(param, self._windows_sandbox)
        elif action_id == ACTION_ID_ANYRUN_GET_INTELLIGENCE:
            ret_val = self._handle_get_intelligence(param)
        elif action_id == ACTION_ID_ANYRUN_TEST_CONNECTIVITY:
            ret_val = self._handle_test_connectivity(param)
        elif action_id == ACTION_ID_ANYRUN_DELETE_SUBMISSION:
            ret_val = self._handle_delete_submission(param)
        elif action_id == ACTION_ID_ANYRUN_DOWNLOAD_PCAP:
            ret_val = self._handle_download_pcap(param)
        elif action_id == ACTION_ID_ANYRUN_GET_ANALYSIS_VERDICT:
            ret_val = self._handle_get_analysis_verdict(param)

        return ret_val

    def initialize(self) -> bool:
        """
        Initialize
        """
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        # required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        # optional_config_name = config.get('optional_config_name')

        self._api_key = config.get("anyrun_api_key")
        self._timeout = config.get("anyrun_timeout")

        self._api_key = self._normalize_api_key()

        self._anyrun_sandbox = SandboxConnector()

        generic_sandbox_parameters = {
            "api_key": self._api_key,
            "integration": USER_AGENT,
            "timeout": self._timeout,
        }
        self._windows_sandbox = self._anyrun_sandbox.windows(**generic_sandbox_parameters)
        self._android_sandbox = self._anyrun_sandbox.android(**generic_sandbox_parameters)
        self._linux_sandbox = self._anyrun_sandbox.linux(**generic_sandbox_parameters)

        self._anyrun_threat_intelligence = LookupConnector(
            api_key=self._api_key,
            integration=USER_AGENT,
            timeout=self._timeout,
        )

        self._reputation = Reputation(sandbox=self._windows_sandbox, lookup=self._anyrun_threat_intelligence)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = AnyRunConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AnyRunConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
