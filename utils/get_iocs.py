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
import requests


def extract_iocs(report_json: dict, api_key: str) -> list[dict]:
    """Get IOCs from the report"""
    if report_json is None:
        return []

    ioc_link = report_json.get("analysis", {}).get("reports", {}).get("IOC", None)
    if ioc_link is None:
        return []

    headers = {"Authorization": api_key}
    response = requests.get(
        ioc_link,
        headers=headers,
        timeout=10,
    )
    if response.status_code != 200:
        return []

    return response.json()
