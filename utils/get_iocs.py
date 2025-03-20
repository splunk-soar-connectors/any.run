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
