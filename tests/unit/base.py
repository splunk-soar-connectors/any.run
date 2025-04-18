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
import os

from dotenv import load_dotenv

from anyrun_connector import AnyRunConnector
from tests.utils import setup_connector


load_dotenv()
connector, session_id = setup_connector(os.getenv("LOGIN"), os.getenv("PASSWORD"))
api_key = os.getenv("API_KEY")


class BaseTest:
    """
    Base test class
    """

    connector: AnyRunConnector
    session_id: str = None

    @property
    def base_config(self) -> dict:
        """
        Base config for the AnyRunConnector
        """
        return {
            "anyrun_server": "https://api.any.run",
            "anyrun_api_key": api_key,
            "anyrun_timeout": 30,
        }

    def _execute_action(self, in_json: str) -> dict:
        """
        Execute the action
        """
        in_json["config"] = self.base_config

        print(json.dumps(in_json, indent=4))

        in_json["user_session_token"] = session_id

        self.connector = connector

        ret_val = self.connector._handle_action(json.dumps(in_json), None)

        print(json.dumps(json.loads(ret_val), indent=4))

        return json.loads(ret_val)
