# File: anyrun_consts.py
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

VERSION = "1.3.0"
# Action IDs
ACTION_ID_ANYRUN_TEST_CONNECTIVITY = "test_connectivity"
ACTION_ID_ANYRUN_GET_URL_REPUTATION = "get_url_reputation"
ACTION_ID_ANYRUN_GET_FILE_REPUTATION = "get_file_reputation"
ACTION_ID_ANYRUN_GET_DOMAIN_REPUTATION = "get_domain_reputation"
ACTION_ID_ANYRUN_GET_IP_REPUTATION = "get_ip_reputation"
ACTION_ID_ANYRUN_GET_REPORT = "get_report"
ACTION_ID_ANYRUN_GET_IOC = "get_ioc"
ACTION_ID_ANYRUN_DETONATE_URL = "detonate_url"
ACTION_ID_ANYRUN_DETONATE_FILE = "detonate_file"
ACTION_ID_ANYRUN_GET_INTELLIGENCE = "get_intelligence"
# Error messages
ANYRUN_ERROR_CODE_MSG = "Error code unavailable."
ANYRUN_ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
ANYRUN_PARSE_ERROR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters."
ANYRUN_UNABLE_TO_FETCH_FILE_ERROR = "Unable to retrieve the sample from the vault. Key: {}. Vault ID: {}."
ANYRUN_VAULT_MULTIPLE_FILES_ERROR = "Found multiple files for vault_id {}. Using the first one."
ANYRUN_VAULT_NO_FILES_ERROR = "No sample found for vault_id {}."
ANYRUN_SANDBOX_PARAMS_VALIDATION_ERROR = "Error in validating sandbox parameters. {}."
ANYRUN_TI_PARAMS_VALIDATION_ERROR = "Error in validating Threat Intelligence parameters. {}."
ANYRUN_REST_API_ERROR = "Error processing server response in action '{0}'. {1}."
ANYRUN_ADD_DATA_ERROR = "Error constructing action result in action '{0}'. {1}."
# Action specific messages
ANYRUN_ERROR_TEST_CONNECTIVITY = "Connectivity test failed. {}."
ANYRUN_SUCCESS_TEST_CONNECTIVITY = "Connectivity test passed."
ANYRUN_SUCCESS_GET_URL_REPUTATION = "Successfully retrieved list of reports for a URL '{0}'."
ANYRUN_SUCCESS_GET_FILE_REPUTATION = "Successfully retrieved list of reports for a submissions with hash '{0}'."
ANYRUN_SUCCESS_GET_DOMAIN_REPUTATION = "Successfully retrieved list of reports for a submissions related to domain '{0}'."
ANYRUN_SUCCESS_GET_IP_REPUTATION = "Successfully retrieved list of reports for a submissions related to IP '{0}'."
ANYRUN_SUCCESS_GET_REPORT = "Successfully retrieved report for submission: {}."
ANYRUN_SUCCESS_GET_IOC = "Successfully retrieved IoC report for submission: {}."
ANYRUN_SUCCESS_DETONATE_URL = "Successfully detonated URL: {}."
ANYRUN_SUCCESS_DETONATE_FILE = "Successfully detonated file with the vault ID : {}."
ANYRUN_SUCCESS_GET_INTELLIGENCE = "Successfully retrieved threat information via Threat Intelligence lookup."
