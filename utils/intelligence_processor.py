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
"""
Process intelligence data from Any.Run API.
"""

import json


class IntelligenceProcessor:
    """
    Process intelligence data from Any.Run API.
    """

    fields: list[tuple[str, str, str]] = [
        ("relatedURLs", "url", "URL"),
        ("destinationIP", "destinationIP", "IP"),
        ("relatedDNS", "domainName", "DomainNames"),
        ("sourceTasks", "related", "Tasks"),
    ]
    level_names: list[str] = ["unknown", "suspicious", "malicious", "whitelisted", "shared"]

    def __init__(self, response: dict) -> None:
        """Initialize the IntelligenceProcessor with the response from Any.Run API."""
        self.response = response
        self.summary = {}

        # Process file hashes
        self.summary.update(self._process_file_hashes(self.response["relatedFiles"]))

        # Process related fields (URLs, IPs, DNS, Tasks)
        self.summary.update(self._process_related_fields(self.fields, self.level_names))

        # Process related incidents
        self.summary.update(self._process_related_incidents(self.response.get("relatedIncidents", [])))

        # Process synchronization objects
        self.summary.update(self._process_sync_objects(self.response.get("relatedSynchronizationObjects", [])))

        # Process tags
        self.summary.update(self._process_tags(self.response["sourceTasks"]))

    def __repr__(self) -> str:
        return json.dumps(self.summary, indent=4)

    def _process_file_hashes(self, related_files: list[dict]) -> dict:
        """
        Process file hashes.
        Returns a dictionary with the file hashes and their count.

        Args:
            related_files (list[dict]): The related files to process.

        Returns:
            dict: A dictionary with the file hashes and their count.
        """
        return {
            "MD5": {
                "str": ", ".join(file["hashes"]["md5"] for file in related_files),
                "Count": len(related_files),
                "Type": "MD5",
            },
            "SHA1": {
                "str": ", ".join(file["hashes"]["sha1"] for file in related_files),
                "Count": len(related_files),
                "Type": "SHA1",
            },
            "SHA256": {
                "str": ", ".join(file["hashes"]["sha256"] for file in related_files),
                "Count": len(related_files),
                "Type": "SHA256",
            },
        }

    def _process_related_fields(self, fields: list[tuple[str, str, str]], level_names: list[str]) -> dict:
        """
        Process related fields like URLs, IPs, DNS, and Tasks.
        Returns a dictionary with the related fields and their count.

        Args:
            fields (list[tuple[str, str, str]]): The fields to process.
            level_names (list[str]): The level names to use.

        Returns:
            dict: A dictionary with the related fields and their count.
        """
        result = {}

        for field_name, subfield_name, type_name in fields:
            if field_name not in self.response or not self.response[field_name]:
                continue

            # Group items by threat level
            by_level = {level: [] for level in range(5)}
            for item in self.response[field_name]:
                by_level[item["threatLevel"]].append(item[subfield_name])

            # Add non-empty levels to results
            for level, items in by_level.items():
                if items:
                    _key = f"{type_name} ({level_names[level]})"
                    result[_key] = {
                        "str": ", ".join(items),
                        "Count": len(items),
                        "Type": _key,
                    }

        return result

    def _process_related_incidents(self, incidents: list[dict]) -> dict:
        """
        Extract command lines and registry keys from related incidents.
        Returns a dictionary with the command lines and registry keys and their count.

        Args:
            incidents (list[dict]): The incidents to extract command lines and registry keys from.

        Returns:
            dict: A dictionary with the command lines and registry keys and their count.
        """
        if not incidents:
            return {}

        result = {}
        cmds = []
        reg_keys = []

        for inc in incidents:
            if "process" in inc and "commandLine" in inc["process"] and inc["process"]["commandLine"] not in cmds:
                replacements = [("\\", "\\\\"), ('"', '\\"'), ("|", "\\|")]
                for old, new in replacements:
                    inc["process"]["commandLine"] = inc["process"]["commandLine"].replace(old, new)

                cmds.append(inc["process"]["commandLine"])
            if "event" in inc and "registryKey" in inc["event"] and inc["event"]["registryKey"] not in reg_keys:
                reg_keys.append(inc["event"]["registryKey"])

        if cmds:
            result["CommandLines"] = {"str": ", ".join(cmds), "Count": len(cmds), "Type": "CommandLines"}

        if reg_keys:
            result["RegistryKeys"] = {"str": ", ".join(reg_keys), "Count": len(reg_keys), "Type": "RegistryKeys"}

        return result

    def _process_sync_objects(self, sync_objects: list[dict]) -> dict:
        """
        Process synchronization objects.
        Returns a dictionary with the synchronization objects and their count.

        Args:
            sync_objects (list[dict]): The synchronization objects to process.

        Returns:
            dict: A dictionary with the synchronization objects and their count.
        """
        objects = []
        if not sync_objects:
            return {}

        for sync_obj in sync_objects:
            if sync_obj["syncObjectName"] and sync_obj["syncObjectName"] not in objects:
                objects.append(sync_obj["syncObjectName"])

        return {
            "SynchronizationObjects": {
                "str": ", ".join(objects),
                "Count": len(objects),
                "Type": "SynchronizationObjects",
            }
        }

    def _process_tags(self, source_tasks: list[dict]) -> dict:
        """
        Extract unique tags from source tasks.
        Returns a dictionary with the tags and their count.

        Args:
            source_tasks (list[dict]): The source tasks to extract tags from.

        Returns:
            dict: A dictionary with the tags and their count.
        """
        tags = []

        for task in source_tasks:
            for tag in task["tags"]:
                if tag not in tags:
                    tags.append(tag)

        return {"Tags": {"str": ", ".join(tags), "Count": len(tags), "Type": "Tags"}}
