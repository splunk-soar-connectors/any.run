import requests

from anyrun_connector import AnyRunConnector


def setup_connector(username: str, password: str) -> tuple[AnyRunConnector, str]:
    """
    Setup the connector and return the connector and the session id
    """
    session_id = None

    connector = AnyRunConnector()
    connector.print_progress_message = True
    try:
        login_url = connector._get_phantom_base_url() + "/login"

        print("Accessing the Login page")
        r = requests.get(login_url, verify=False)
        csrftoken = r.cookies["csrftoken"]

        data = dict()
        data["username"] = username
        data["password"] = password
        data["csrfmiddlewaretoken"] = csrftoken

        headers = dict()
        headers["Cookie"] = "csrftoken=" + csrftoken
        headers["Referer"] = login_url

        print("Logging into Platform to get the session id")
        r2 = requests.post(login_url, verify=False, data=data, headers=headers)
        session_id = r2.cookies["sessionid"]

        connector._set_csrf_info(csrftoken, headers["Referer"])
    except Exception as e:
        print("Unable to get session id from the platform. Error: " + str(e))
        exit(1)

    return connector, session_id
