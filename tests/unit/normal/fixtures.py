"""
Fixtures for the normal tests
"""

import json

import pytest


__all__ = [
    "test_connectivity",
    "test_get_url_reputation",
    "test_get_file_reputation",
    "test_get_domain_reputation",
    "test_get_ip_reputation",
    "test_get_report",
    "test_get_ioc",
    "test_detonate_url",
    "test_detonate_file",
    "test_get_intelligence",
    "test_detonate_url_with_obj_ext_startfolder",
]


@pytest.fixture
def test_connectivity() -> str:
    """
    Basic test of the test_connectivity action
    """
    return json.dumps(
        {
            "action": "test_connectivity",
            "parameters": [],
            "asset_id": "anyrun_instance_01",
            "identifier": "test_connectivity",
        }
    )


@pytest.fixture
def test_get_url_reputation() -> str:
    """
    Basic test of the get_url_reputation action
    """
    return json.dumps(
        {
            "action": "get_url_reputation",
            "parameters": [{"url": "https://google.com", "search_in_public_tasks": True}],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_url_reputation",
        }
    )


@pytest.fixture
def test_get_file_reputation() -> str:
    """
    Basic test of the get_file_reputation action
    """
    return json.dumps(
        {
            "action": "get_file_reputation",
            "parameters": [
                {
                    "hash": "977c18cb2becc8a82d9c46760218fd1140cc1174ac0f38d151bbb11224ba6bcb",
                    "search_in_public_tasks": True,
                }
            ],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_file_reputation",
        }
    )


@pytest.fixture
def test_get_domain_reputation() -> str:
    """
    Basic test of the get_domain_reputation action
    """
    return json.dumps(
        {
            "action": "get_domain_reputation",
            "parameters": [{"domainname": "google.com"}],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_domain_reputation",
        }
    )


@pytest.fixture
def test_get_ip_reputation() -> str:
    """
    Basic test of the get_ip_reputation action
    """
    return json.dumps(
        {
            "action": "get_ip_reputation",
            "parameters": [{"ip": "1.1.1.1"}],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_ip_reputation",
        }
    )


@pytest.fixture
def test_get_report() -> str:
    """
    Basic test of the get_report action
    """
    return json.dumps(
        {
            "action": "get_report",
            "parameters": [{"taskid": "279be11e-0799-4d62-ac47-f1d56e88ee57"}],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_report",
        }
    )


@pytest.fixture
def test_get_ioc() -> str:
    """
    Basic test of the get_ioc action
    """
    return json.dumps(
        {
            "action": "get_ioc",
            "parameters": [{"taskid": "279be11e-0799-4d62-ac47-f1d56e88ee57"}],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_ioc",
        }
    )


@pytest.fixture
def test_detonate_url() -> str:
    """
    Basic test of the detonate_url action
    """
    return json.dumps(
        {
            "action": "detonate_url",
            "parameters": [
                {
                    "obj_url": "https://example.com",
                    "obj_type": "url",
                    "os": "Windows10x64_clean",
                    "env_bitness": "64",
                    "env_os": "windows",
                    "env_version": "10",
                    "env_type": "clean",
                    "opt_timeout": 10,
                }
            ],
            "asset_id": "anyrun_instance_01",
            "identifier": "detonate_url",
        }
    )


@pytest.fixture
def test_detonate_file() -> str:
    """
    Basic test of the detonate_file action
    """
    return json.dumps(
        {
            "action": "detonate_file",
            "parameters": [
                {
                    "vault_id": "1c7bd3a1d6c7bd4708210db96ec8a37e42a6f8a0",
                    "os": "Windows10x64_clean",
                    "env_bitness": "64",
                    "env_os": "windows",
                    "env_version": "10",
                    "env_type": "clean",
                    "opt_timeout": 10,
                }
            ],
            "asset_id": "anyrun_instance_01",
            "identifier": "detonate_file",
        }
    )


@pytest.fixture
def test_get_intelligence() -> str:
    """
    Basic test of the get_intelligence action
    """
    return json.dumps(
        {
            "action": "get_intelligence",
            "parameters": [
                {
                    "os": "Windows 10",
                    "destination_ip": "192.168.1.1",
                    "start_date": "2025-03-14",
                    "end_date": "2025-03-19",
                }
            ],
            "asset_id": "anyrun_instance_01",
            "identifier": "get_intelligence",
        }
    )


@pytest.fixture
def test_detonate_url_with_obj_ext_startfolder() -> str:
    """
    Basic test of the detonate_url action with all allowed parameters
    """
    return json.dumps(
        {
            "action": "detonate_url",
            "parameters": [
                {
                    "url": "https://example.com",
                    "os": "Windows10x64_clean",
                    "env_bitness": "64",
                    "env_os": "windows",
                    "env_version": "10",
                    "obj_ext_startfolder": "temp",
                    "opt_timeout": 10,
                }
            ],
            "asset_id": "anyrun_instance_01",
            "identifier": "detonate_url",
        }
    )
