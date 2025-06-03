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
import time

from dotenv import load_dotenv

from tests.utils import setup_connector


load_dotenv()
connector, session_id = setup_connector(os.getenv("LOGIN"), os.getenv("PASSWORD"))
api_key = os.getenv("API_KEY")

DEFAULT_TASK_ID = "2c9a63ea-a9ae-4806-b1d0-6a8f8562dab0"
DEFAULT_VAULT_ID = "1c7bd3a1d6c7bd4708210db96ec8a37e42a6f8a0"
CONTAINER = 4
ASSET = "anyrun_instance_01"


class BaseRunner:
    def __init__(self):
        self.username = os.getenv("LOGIN")
        self.password = os.getenv("PASSWORD")

        self.connector, _ = setup_connector(session_id=session_id)
        self.api_key = os.getenv("API_KEY")

    @property
    def base_config(self) -> dict:
        return {
            "anyrun_api_key": self.api_key,
            "anyrun_timeout": 30,
        }

    @property
    def base_phantom_settings(self) -> dict:
        return {
            "asset_id": ASSET,
            "container_id": CONTAINER,
        }

    def _execute_action(self, in_json: str) -> dict:
        """
        Execute the action
        """
        in_json["config"] = self.base_config

        in_json["user_session_token"] = session_id

        in_json = {**in_json, **self.base_phantom_settings}

        t1 = time.time()

        ret_val = self.connector._handle_action(json.dumps(in_json), None)
        if not ret_val:
            raise Exception(ret_val)

        t2 = time.time()

        result = json.loads(ret_val)
        result["time_taken"] = t2 - t1

        return result

    def stop_task(self, task_id: str) -> None:
        with self.connector._windows_sandbox as sb:
            for status in sb.get_task_status(task_id):
                if status.get("status", "preparing").lower() == "running":
                    sb.stop_task(task_id)
                    time.sleep(5)

                if status.get("status", "preparing").lower() == "completed":
                    break
