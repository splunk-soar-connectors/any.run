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
Fixtures for the normal tests
"""

import json

import pytest

from tests.unit.base import DEFAULT_TASK_ID, DEFAULT_VAULT_ID


__all__ = [
    "test_connectivity",
    "test_delete_submission",
    "test_detonate_file_android",
    "test_detonate_file_linux",
    "test_detonate_file_windows",
    "test_detonate_url_android",
    "test_detonate_url_linux",
    "test_detonate_url_windows",
    "test_download_pcap_fixture",
    "test_get_analysis_verdict",
    "test_get_domain_reputation",
    "test_get_file_reputation",
    "test_get_intelligence",
    "test_get_ioc",
    "test_get_ip_reputation",
    "test_get_report",
    "test_get_report_html",
    "test_get_report_misp",
    "test_get_report_stix",
    "test_get_url_reputation",
]


@pytest.fixture
def test_connectivity() -> str:
    return json.dumps(
        {
            "action": "test_connectivity",
            "identifier": "test_connectivity",
            "parameters": [],
        }
    )


@pytest.fixture
def test_get_url_reputation() -> str:
    return json.dumps(
        {
            "action": "get_url_reputation",
            "identifier": "get_url_reputation",
            "parameters": [{"url": "https://google.com", "search_in_public_tasks": True}],
        }
    )


@pytest.fixture
def test_get_file_reputation() -> str:
    return json.dumps(
        {
            "action": "get_file_reputation",
            "identifier": "get_file_reputation",
            "parameters": [
                {
                    "hash": "977c18cb2becc8a82d9c46760218fd1140cc1174ac0f38d151bbb11224ba6bcb",  # pragma: allowlist secret
                    "search_in_public_tasks": True,
                }
            ],
        }
    )


@pytest.fixture
def test_get_domain_reputation() -> str:
    return json.dumps(
        {
            "action": "get_domain_reputation",
            "identifier": "get_domain_reputation",
            "parameters": [{"domainname": "google.com"}],
        }
    )


@pytest.fixture
def test_get_ip_reputation() -> str:
    return json.dumps(
        {
            "action": "get_ip_reputation",
            "identifier": "get_ip_reputation",
            "parameters": [{"ip": "1.1.1.1"}],
        }
    )


@pytest.fixture
def test_get_report() -> str:
    return json.dumps(
        {
            "action": "get_report",
            "identifier": "get_report",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_get_report_html() -> str:
    return json.dumps(
        {
            "action": "get_report_html",
            "identifier": "get_report_html",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_get_report_stix() -> str:
    return json.dumps(
        {
            "action": "get_report_stix",
            "identifier": "get_report_stix",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_get_report_misp() -> str:
    return json.dumps(
        {
            "action": "get_report_misp",
            "identifier": "get_report_misp",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_get_ioc() -> str:
    return json.dumps(
        {
            "action": "get_ioc",
            "identifier": "get_ioc",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_detonate_url_android() -> str:
    return json.dumps(
        {
            "action": "detonate_url_android",
            "identifier": "detonate_url_android",
            "parameters": [{"obj_url": "https://example.com", "opt_timeout": 10}],
        }
    )


@pytest.fixture
def test_detonate_url_linux() -> str:
    return json.dumps(
        {
            "action": "detonate_url_linux",
            "identifier": "detonate_url_linux",
            "parameters": [{"obj_url": "https://example.com", "opt_timeout": 10}],
        }
    )


@pytest.fixture
def test_detonate_url_windows() -> str:
    return json.dumps(
        {
            "action": "detonate_url_windows",
            "identifier": "detonate_url_windows",
            "parameters": [{"obj_url": "https://example.com", "opt_timeout": 10}],
        }
    )


@pytest.fixture
def test_detonate_file_windows() -> str:
    return json.dumps(
        {
            "action": "detonate_file_windows",
            "identifier": "detonate_file_windows",
            "parameters": [
                {
                    "vault_id": DEFAULT_VAULT_ID,
                    "opt_timeout": 10,
                }
            ],
        }
    )


@pytest.fixture
def test_detonate_file_linux() -> str:
    return json.dumps(
        {
            "action": "detonate_file_linux",
            "identifier": "detonate_file_linux",
            "parameters": [
                {
                    "vault_id": DEFAULT_VAULT_ID,
                    "opt_timeout": 10,
                }
            ],
        }
    )


@pytest.fixture
def test_detonate_file_android() -> str:
    return json.dumps(
        {
            "action": "detonate_file_android",
            "identifier": "detonate_file_android",
            "parameters": [
                {
                    "vault_id": DEFAULT_VAULT_ID,
                    "opt_timeout": 10,
                }
            ],
        }
    )


@pytest.fixture
def test_get_intelligence() -> str:
    return json.dumps(
        {
            "action": "get_intelligence",
            "identifier": "get_intelligence",
            "parameters": [
                {
                    "query": "192.168.1.1",
                    "start_date": "2025-05-01",
                    "end_date": "2025-05-31",
                }
            ],
        }
    )


@pytest.fixture
def test_download_pcap_fixture() -> str:
    return json.dumps(
        {
            "action": "download_pcap",
            "identifier": "download_pcap",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_get_analysis_verdict() -> str:
    return json.dumps(
        {
            "action": "get_analysis_verdict",
            "identifier": "get_analysis_verdict",
            "parameters": [{"taskid": DEFAULT_TASK_ID}],
        }
    )


@pytest.fixture
def test_delete_submission() -> str:
    return json.dumps(
        {
            "action": "delete_submission",
            "identifier": "delete_submission",
            "parameters": [{"taskid": "dummy"}],
        }
    )
