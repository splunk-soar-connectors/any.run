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
Fixtures for the broken tests
"""

import json

import pytest


__all__ = [
    "test_broken_detonate_file",
    "test_broken_detonate_url",
    "test_broken_detonate_url_with_android_os",
    "test_broken_get_domain_reputation",
    "test_broken_get_file_reputation",
    "test_broken_get_intelligence",
    "test_broken_get_intelligence_wrong_query",
    "test_broken_get_ioc",
    "test_broken_get_ip_reputation",
    "test_broken_get_report",
    "test_broken_get_url_reputation",
]


@pytest.fixture
def test_broken_get_url_reputation() -> str:
    """
    Broken test of the get_url_reputation action
    """
    return json.dumps(
        {
            "action": "get_url_reputation",
            "identifier": "get_url_reputation",
            "parameters": [{"search_in_public_tasks": False}],
        }
    )


@pytest.fixture
def test_broken_get_file_reputation() -> str:
    """
    Broken test of the get_file_reputation action
    """
    return json.dumps(
        {
            "action": "get_file_reputation",
            "identifier": "get_file_reputation",
            "parameters": [{"search_in_public_tasks": False}],
        }
    )


@pytest.fixture
def test_broken_get_domain_reputation() -> str:
    """
    Broken test of the get_domain_reputation action
    """
    return json.dumps(
        {
            "action": "get_domain_reputation",
            "identifier": "get_domain_reputation",
            "parameters": [{"search_in_public_tasks": False}],
        }
    )


@pytest.fixture
def test_broken_get_ip_reputation() -> str:
    """
    Broken test of the get_ip_reputation action
    """
    return json.dumps(
        {
            "action": "get_ip_reputation",
            "identifier": "get_ip_reputation",
            "parameters": [{"search_in_public_tasks": False}],
        }
    )


@pytest.fixture
def test_broken_get_report() -> str:
    """
    Broken test of the get_report action
    """
    return json.dumps(
        {
            "action": "get_report",
            "identifier": "get_report",
            "parameters": [],
        }
    )


@pytest.fixture
def test_broken_get_ioc() -> str:
    """
    Broken test of the get_ioc action
    """
    return json.dumps(
        {
            "action": "get_ioc",
            "identifier": "get_ioc",
            "parameters": [],
        }
    )


@pytest.fixture
def test_broken_detonate_url() -> str:
    """
    Broken test of the detonate_url action
    """
    return json.dumps(
        {
            "action": "detonate_url",
            "identifier": "detonate_url",
            "parameters": [],
        }
    )


@pytest.fixture
def test_broken_detonate_url_with_android_os() -> str:
    """
    Broken test of the detonate_url action with android os
    """
    return json.dumps(
        {
            "action": "detonate_url_android",
            "identifier": "detonate_url_android",
            "parameters": [
                {
                    "obj_url": "https://example.com",
                    "obj_type": "url",
                    "os": "android",
                    "env_bitness": "64",
                    "env_os": "windows",
                    "env_version": "10",
                    "env_type": "clean",
                }
            ],
        }
    )


@pytest.fixture
def test_broken_detonate_file() -> str:
    """
    Broken test of the detonate_file action
    """
    return json.dumps(
        {
            "action": "detonate_file_windows",
            "identifier": "detonate_file_windows",
            "parameters": [{"vault_id": "dummy"}],
        }
    )


@pytest.fixture
def test_broken_get_intelligence() -> str:
    """
    Broken test of the get_intelligence action
    """
    return json.dumps(
        {
            "action": "get_intelligence",
            "identifier": "get_intelligence",
            "parameters": [{"os": 22}],
        }
    )


@pytest.fixture
def test_broken_get_intelligence_wrong_query() -> str:
    """
    Broken test of the get_intelligence action with wrong query
    """
    return json.dumps(
        {
            "action": "get_intelligence",
            "identifier": "get_intelligence",
            "parameters": [{"query": "wrong(//syntax*"}],
        }
    )
