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

types = {
    "destinationAddress": ["ip"],
    "destinationDnsDomain": ["domain"],
    "requestURL": ["url"],
    "fileHash": ["sha256", "md5", "sha1"],
}


def define_type(raw_type: str) -> str:
    for key, values in types.items():
        if raw_type in values:
            return key
    return "unknown"


def extract_iocs(sandbox, taskid: str, container_id: int) -> list[dict]:
    """
    Get IoCs from AnyRun sandbox

    :param taskid: Task ID
    :return: List of IoCs
    """
    with sandbox:
        raw_iocs = sandbox.get_analysis_report(task_uuid=taskid, report_format="ioc")

    artifacts = list()
    for entry in raw_iocs:
        reputation = entry.pop("reputation")

        if reputation == 1:
            severity = "medium"
        elif reputation == 2:
            severity = "high"
        elif reputation == 0:
            severity = "low"
        else:
            continue

        entry["severity"] = severity
        ioc_type = define_type(entry.pop("type"))

        cef = dict()
        cef[ioc_type] = entry.pop("ioc")
        cef["id"] = entry.pop("discoveringEntryId")
        cef["category"] = entry.pop("category")
        cef["type"] = ioc_type

        artifact = {
            "label": "indicator",
            "name": cef[ioc_type],
            "severity": severity,
            "source": "AnyRun",
            "cef": cef,
            "container_id": container_id,
            "tags": ["anyrun", "ioc", taskid],
        }

        artifacts.append(artifact)

    return artifacts
