# File: anyrun_connector.py
#
# Copyright (c) ANYRUN FZCO, 2024
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

from __future__ import print_function, unicode_literals

import re
import time

# Phantom App imports
import phantom.app as phantom
import phantom.rules as phantom_rules
# Usage of the consts file is recommended
from anyrun import TI, APIError, Configuration, Sandbox, ThreatIntelligence
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from anyrun_consts import *  # pylint: disable=wildcard-import


class AnyRunConnector(BaseConnector):

    def __init__(self):
        super(AnyRunConnector, self).__init__()
        self._state = None
        self._server = None
        self._api_key = None
        self._timeout = None

    def _get_error_message_from_exception(self, exception):
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

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        f"Please provide a valid integer value in the {key}"
                    ), None
                parameter = int(parameter)
            except:  # pylint: disable=bare-except
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a valid integer value in the {key}"
                ), None

            if parameter < 0:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a valid non-negative integer value in the {key}"
                ), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a valid non-zero integer value in the {key}"
                ), None

        return phantom.APP_SUCCESS, parameter

    def _get_configuration(self, action_result, param):
        # convert configuration id to env_os, env_version, env_bitness, env_type
        os = param.pop("os")
        convert_srt = r"(Linux|Windows)([\d\.]+)x(32|64)_(office|clean|complete)"
        env_os, env_version, env_bitness, env_type = (re.search(convert_srt, os)).groups()

        # update params
        param = {
            "env_os": env_os.lower(),
            "env_version": env_version,
            "env_bitness": env_bitness,
            "env_type": env_type
        } | param

        # remove conflicting options
        if env_os == "Windows":
            param.pop("run_as_root", None)
        elif env_os == "Linux":
            param.pop("auto_confirm_uac", None)
            param.pop("obj_ext_elevateprompt", None)

        # convert to Configuration
        try:
            data = {key: value for key, value in param.items()
                    if key not in ["context", "vault_id"]}
            for attr in Configuration.ATTRIBUTES_INT:
                if attr in data:
                    ret_val, data[attr] = self._validate_integer(
                        action_result, data[attr], attr
                    )
                    if phantom.is_fail(ret_val):
                        return action_result.get_status(), None

            return phantom.APP_SUCCESS, Configuration.from_dict(data)
        except (AttributeError, TypeError, ValueError) as exc:
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_SANDBOX_PARAMS_VALIDATION_ERROR.format(error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message), None

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        try:
            self._anyrun_sandbox.get_user_limits()
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            self.save_progress(ANYRUN_ERROR_TEST_CONNECTIVITY.format(error_message))
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Could not connect to server. {error_message}"
            )

        self.save_progress(ANYRUN_SUCCESS_TEST_CONNECTIVITY)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_url_reputation(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param["url"]
        search_in_public_tasks = param["search_in_public_tasks"]

        # Making an API call
        self.save_progress(f"Requesting a list of reports for a URL: {url}.")
        try:
            error_message = None
            tasks = self._anyrun_sandbox.get_url_reputation(url)
            if search_in_public_tasks:
                tasks += self._anyrun_threat_intelligence.get_url_reputation(url)
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_URL_REPUTATION, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_URL_REPUTATION.format(url))

        # Processing server response
        try:
            levels = {
                0: "No threats detected",
                1: "Suspicious activity",
                2: "Malicious activity"
            }
            for task in tasks:
                if "uuid" not in task:
                    task.update({"uuid": task["related"].rsplit("/")[-1]})
                if "verdict" not in task:
                    task.update({"verdict": levels[task["threatLevel"]]})
                if "mainObject" not in task:
                    task.update({"mainObject": {
                        "name": task.pop("name"),
                        "hashes": task.pop("hashes")
                    }})
            action_result.add_data({"tasks": tasks})
            action_result.update_summary({
                'total_objects': len(tasks)
            })
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_URL_REPUTATION, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_GET_URL_REPUTATION.format(url)
        )

    def _handle_get_file_reputation(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param["hash"]
        search_in_public_tasks = param["search_in_public_tasks"]

        # Making an API call
        self.save_progress(f"Requesting a list of reports for a submission with hash: {file_hash}.")
        try:
            error_message = None
            tasks = self._anyrun_sandbox.get_file_reputation(file_hash)
            if search_in_public_tasks:
                tasks += self._anyrun_threat_intelligence.get_file_reputation(file_hash)
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_FILE_REPUTATION, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_FILE_REPUTATION.format(file_hash))

        # Processing server response
        try:
            levels = {
                0: "No threats detected",
                1: "Suspicious activity",
                2: "Malicious activity"
            }
            for task in tasks:
                if "uuid" not in task:
                    task.update({"uuid": task["related"].rsplit("/")[-1]})
                if "verdict" not in task:
                    task.update({"verdict": levels[task["threatLevel"]]})
                if "mainObject" not in task:
                    task.update({"mainObject": {
                        "name": task.pop("name"),
                        "hashes": task.pop("hashes")
                    }})
            action_result.add_data({"tasks": tasks})
            action_result.update_summary({
                'total_objects': len(tasks)
            })
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_FILE_REPUTATION, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_GET_FILE_REPUTATION.format(file_hash)
        )

    def _handle_get_domain_reputation(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param["domainname"]
        data = TI(domainname=domain)

        # Making an API call
        self.save_progress(f"Requesting a list of reports for a submission related to domain: {domain}.")
        try:
            error_message = None
            tasks = self._anyrun_threat_intelligence.get_intelligence(data)["sourceTasks"]
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_DOMAIN_REPUTATION, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_DOMAIN_REPUTATION.format(domain))

        # Processing server response
        try:
            levels = {
                0: "No threats detected",
                1: "Suspicious activity",
                2: "Malicious activity"
            }
            for task in tasks:
                task.update({"verdict": levels[task["threatLevel"]]})
            action_result.add_data({"tasks": tasks})
            action_result.update_summary({
                'total_objects': len(tasks)
            })
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_DOMAIN_REPUTATION, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_GET_DOMAIN_REPUTATION.format(domain)
        )

    def _handle_get_ip_reputation(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param["ip"]
        data = TI(destinationip=ip)

        # Making an API call
        self.save_progress(f"Requesting a list of reports for a submission related to IP: {ip}.")
        try:
            error_message = None
            tasks = self._anyrun_threat_intelligence.get_intelligence(data)["sourceTasks"]
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_IP_REPUTATION, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_IP_REPUTATION.format(ip))

        # Processing server response
        try:
            levels = {
                0: "No threats detected",
                1: "Suspicious activity",
                2: "Malicious activity"
            }
            for task in tasks:
                task.update({"verdict": levels[task["threatLevel"]]})
            action_result.add_data({"tasks": tasks})
            action_result.update_summary({
                'total_objects': len(tasks)
            })
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_IP_REPUTATION, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_GET_IP_REPUTATION.format(ip)
        )

    def _handle_get_report(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Making an API call
        taskid = param['taskid']
        self.save_progress(f"Requesting report for submission: {taskid}")
        try:
            error_message = None
            report = self._anyrun_sandbox.get_analysis_report(taskid)
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_REPORT, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_REPORT.format(taskid))

        # Processing server response
        try:
            action_result.add_data(report)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_REPORT, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_GET_REPORT.format(taskid)
        )

    def _handle_get_ioc(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Making an API call
        taskid = param['taskid']
        self.save_progress(f"Requesting IoC report for submission: {taskid}.")
        try:
            error_message = None
            iocs = self._anyrun_sandbox.get_analysis_iocs(taskid)
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_IOC, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_IOC.format(taskid))

        # Processing server response
        try:
            action_result.add_data({"ioc": iocs})
            action_result.update_summary({
                "total_objects": len(iocs),
                "max_reputation": max(item["reputation"] for item in iocs)
            })
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_IOC, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_GET_IOC.format(taskid))

    def _handle_detonate_url(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        obj_type = param.pop("obj_type")
        obj_url = param.pop("obj_url")

        # Input validation
        ret_val, data = self._get_configuration(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Making an API call
        self.save_progress(f"Detonating URL: {obj_url}")
        response = None
        while response is None:
            try:
                error_message = None
                response = self._anyrun_sandbox.submit_url(obj_url, obj_type, data)
            except APIError as exc:
                if exc.message == "Parallel task limit":
                    time.sleep(5)
                    continue
                error_message = self._get_error_message_from_exception(exc)
            except Exception as exc:  # pylint: disable=broad-except
                error_message = self._get_error_message_from_exception(exc)
                error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_DETONATE_URL, error_message)
            finally:
                if error_message:
                    self.save_progress(error_message)
                    return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_DETONATE_URL.format(obj_url))

        # Processing server response
        try:
            response.update({"permanentUrl": f"https://app.any.run/tasks/{response['taskid']}"})
            action_result.add_data(response)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_DETONATE_URL, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_DETONATE_URL.format(obj_url)
        )

    def _handle_detonate_file(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Input validation
        ret_val, data = self._get_configuration(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vault_id = param['vault_id']
        try:
            success, message, vault_meta_info = phantom_rules.vault_info(vault_id=vault_id)
            vault_meta_info = list(vault_meta_info)
            if not success or not vault_meta_info:
                error_message = f"Error Details: {message}" if message else ''
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(
                    ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("vault meta info", vault_id),
                    error_message
                ))
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(
                ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("vault meta info", vault_id),
                error_message
            ))

        if len(vault_meta_info) > 1:
            self.save_progress(ANYRUN_VAULT_MULTIPLE_FILES_ERROR.format(vault_id))
        elif len(vault_meta_info) == 0:
            self.save_progress(ANYRUN_VAULT_NO_FILES_ERROR.format(vault_id))
            return action_result.set_status(
                phantom.APP_ERROR,
                ANYRUN_VAULT_NO_FILES_ERROR.format(vault_id)
            )

        try:
            file_path = vault_meta_info[0].get('path')
            if not file_path:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("path", vault_id)
                )
        except:  # pylint: disable=bare-except
            return action_result.set_status(
                phantom.APP_ERROR,
                ANYRUN_UNABLE_TO_FETCH_FILE_ERROR.format("path", vault_id)
            )

        # Making an API call
        self.save_progress(f"Detonating file with vault ID: {vault_id}")
        response = None
        while response is None:
            try:
                error_message = None
                with open(file_path, "rb") as file:
                    response = self._anyrun_sandbox.submit_file(file, data)
            except APIError as exc:
                if exc.message == "Parallel task limit":
                    time.sleep(5)
                    continue
                error_message = self._get_error_message_from_exception(exc)
            except Exception as exc:  # pylint: disable=broad-except
                error_message = self._get_error_message_from_exception(exc)
                error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_DETONATE_FILE, error_message)
            finally:
                if error_message:
                    self.save_progress(error_message)
                    return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_DETONATE_FILE.format(vault_id))

        # Processing server response
        try:
            response.update({"permanentUrl": f"https://app.any.run/tasks/{response['taskid']}"})
            action_result.add_data(response)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_DETONATE_FILE, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            ANYRUN_SUCCESS_DETONATE_FILE.format(vault_id)
        )

    def _handle_get_intelligence(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Input validation
        try:
            data = {key: str(value) for key, value in param.items()
                    if (key not in ["context"] and value not in ["", 0])}
            if "os" in data:
                data["os"] = data["os"].split()[1]
            data = TI.from_dict(data)
        except (AttributeError, TypeError, ValueError) as exc:
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_TI_PARAMS_VALIDATION_ERROR.format(error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        # Making an API call
        self.save_progress("Initiating Threat Intelligence lookup.")
        try:
            error_message = None
            response = self._anyrun_threat_intelligence.get_intelligence(data)
        except APIError as exc:
            error_message = self._get_error_message_from_exception(exc)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_REST_API_ERROR.format(ACTION_ID_ANYRUN_GET_INTELLIGENCE, error_message)
        finally:
            if error_message:
                self.save_progress(error_message)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress(ANYRUN_SUCCESS_GET_INTELLIGENCE)

        # Processing server response
        try:
            action_result.add_data({key: value for key, value in response.items() if value != []})
            summary = {
                "MD5": {
                    "str": ', '.join(file["hashes"]["md5"] for file in response["relatedFiles"]),
                    "Count": len(response["relatedFiles"]),
                    "Type": "MD5"
                },
                "SHA1": {
                    "str": ', '.join(file["hashes"]["sha1"] for file in response["relatedFiles"]),
                    "Count": len(response["relatedFiles"]),
                    "Type": "SHA1"
                },
                "SHA256": {
                    "str": ', '.join(file["hashes"]["sha256"] for file in response["relatedFiles"]),
                    "Count": len(response["relatedFiles"]),
                    "Type": "SHA256"
                }
            }

            # (<field_name>, <subfield_name>, <type>)
            fields = [
                ("relatedURLs", "url", "URL"),
                ("destinationIP", "destinationIP", "IP"),
                ("relatedDNS", "domainName", "DomainNames"),
                ("sourceTasks", "related", "Tasks")
            ]
            level = ["unknown", "suspicious", "malicious", "whitelisted", "shared"]
            for field in fields:
                result = {0: [], 1: [], 2: [], 3: [], 4: []}
                # if field exists in response and it's value is not empty
                if field[0] in response and response[field[0]]:
                    for item in response[field[0]]:
                        result[item["threatLevel"]].append(item[field[1]])
                    for key, lst in result.items():
                        if lst:
                            summary.update({
                                f"{field[2]} ({level[key]})": {
                                    "str": ', '.join(item for item in lst),
                                    "Count": len(lst),
                                    "Type": f"{field[2]} ({level[key]})"
                                }
                            })

            cmds = []
            reg_keys = []
            if "relatedIncidents" in response and response["relatedIncidents"]:
                for inc in response["relatedIncidents"]:
                    if ("process" in inc and "commandLine" in inc["process"] and inc["process"]["commandLine"]
                    not in cmds):
                        cmds.append(inc["process"]["commandLine"]
                                    .replace('\\', '\\\\')
                                    .replace('"', '\\"')
                                    .replace('|', '\\|')
                                    )
                    if ("event" in inc and "registryKey" in inc["event"] and inc["event"]["registryKey"]
                    not in reg_keys):
                        reg_keys.append(inc["event"]["registryKey"])
                if cmds:
                    summary.update({
                        "CommandLines": {
                            "str": ', '.join(cmd for cmd in cmds),
                            "Count": len(cmds),
                            "Type": "CommandLines"
                        }
                    })
                if reg_keys:
                    summary.update({
                        "RegistryKeys": {
                            "str": ', '.join(key for key in reg_keys),
                            "Count": len(reg_keys),
                            "Type": "RegistryKeys"
                        }
                    })

            sync_objects = []
            if "relatedSynchronizationObjects" in response and response["relatedSynchronizationObjects"]:
                for sync_obj in response["relatedSynchronizationObjects"]:
                    if sync_obj["syncObjectName"] and sync_obj["syncObjectName"] not in sync_objects:
                        sync_objects.append(sync_obj["syncObjectName"])
            summary.update({
                "SynchronizationObjects": {
                    "str": ', '.join(sync_obj for sync_obj in sync_objects),
                    "Count": len(sync_objects),
                    "Type": "SynchronizationObjects"
                }
            })

            tags = []
            for task in response["sourceTasks"]:
                for tag in task["tags"]:
                    if tag not in tags:
                        tags.append(tag)
            summary.update({
                "Tags": {
                    "str": ', '.join(tag for tag in tags),
                    "Count": len(tags),
                    "Type": "Tags"
                }
            })
            action_result.update_summary(summary)
        except Exception as exc:  # pylint: disable=broad-except
            error_message = self._get_error_message_from_exception(exc)
            error_message = ANYRUN_ADD_DATA_ERROR.format(ACTION_ID_ANYRUN_GET_INTELLIGENCE, error_message)
            self.save_progress(error_message)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, ANYRUN_SUCCESS_GET_INTELLIGENCE)

    def handle_action(self, param):
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
        elif action_id == ACTION_ID_ANYRUN_GET_IOC:
            ret_val = self._handle_get_ioc(param)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_URL:
            ret_val = self._handle_detonate_url(param)
        elif action_id == ACTION_ID_ANYRUN_DETONATE_FILE:
            ret_val = self._handle_detonate_file(param)
        elif action_id == ACTION_ID_ANYRUN_GET_INTELLIGENCE:
            ret_val = self._handle_get_intelligence(param)
        elif action_id == ACTION_ID_ANYRUN_TEST_CONNECTIVITY:
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._server = config.get('anyrun_server')
        self._api_key = config.get('anyrun_api_key')
        self._timeout = config.get('anyrun_timeout')
        self._anyrun_sandbox = Sandbox(
            host=self._server,
            apikey=self._api_key,
            timeout=self._timeout,
            agent="Splunk SOAR"
        )
        self._anyrun_threat_intelligence = ThreatIntelligence(
            host=self._server,
            apikey=self._api_key,
            timeout=self._timeout,
            agent="Splunk SOAR"
        )

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self._anyrun_sandbox.close()
        self._anyrun_threat_intelligence.close()
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

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
            login_url = AnyRunConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
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
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
