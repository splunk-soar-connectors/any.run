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
import re

from anyrun.connectors.sandbox.sandbox_connector import SandBoxConnector
from anyrun.connectors.threat_intelligence.lookup_connector import LookupConnector


class Reputation:
    """
    Get the reputation of a file, URL, domain, or IP address
    """

    def __init__(self, sandbox: SandBoxConnector = None, lookup: LookupConnector = None) -> None:
        self.sandbox = sandbox
        self.lookup = lookup

    def _get_hash_type(self, file_hash: str) -> str:
        """
        Get the hash type and value in format of {hash_type: hash_value}
        """
        hashes = {32: "md5", 40: "sha1", 64: "sha256"}

        if len(file_hash) not in hashes:
            raise ValueError(
                f"Unsupported hash type: hash length is {len(file_hash)}. ", "Expected lengths are: ['md5':32, 'sha1':40, 'sha256':64]"
            )
        pattern = re.compile(r"^[a-fA-F0-9]+$")
        if not re.fullmatch(pattern, file_hash):
            raise ValueError(f"Unsupported hash type: '{file_hash}. Illegal characters")

        hash_type = hashes[len(file_hash)]

        return hash_type

    def get_file_reputation(self, file_hash: str, search_in_public_tasks: bool = False) -> list[dict]:
        """
        Get the reputation of a file
        """
        hash_type = self._get_hash_type(file_hash)
        with self.sandbox as sandbox:
            tasks = sandbox.get_analysis_history(True, 0, 100)
            tasks = [task for task in tasks if task.get("hashes", {}).get(hash_type) == file_hash]
            # Get history from SandBoxConnector
        if search_in_public_tasks:
            with self.lookup as lookup:
                response = lookup.get_intelligence(**{hash_type: file_hash})

            tasks += response["sourceTasks"]

        return tasks

    def get_url_reputation(self, url: str, search_in_public_tasks: bool = False) -> list[dict]:
        """
        Get the reputation of an URL
        """
        with self.sandbox as sandbox:
            tasks = sandbox.get_analysis_history(True, 0, 100)
            tasks = [task for task in tasks if task["name"] == url]
        if search_in_public_tasks:
            with self.lookup as lookup:
                response = lookup.get_intelligence(url=url)
                tasks += response["sourceTasks"]

        return tasks

    def get_domain_reputation(self, domain: str) -> list[dict]:
        """
        Get the reputation of a domain
        """
        with self.lookup as lookup:
            response = lookup.get_intelligence(domain_name=domain)

        return response["sourceTasks"]

    def get_ip_reputation(self, ip: str) -> list[dict]:
        """
        Get the reputation of an IP address
        """
        with self.lookup as lookup:
            response = lookup.get_intelligence(destination_ip=ip)
        return response["sourceTasks"]
