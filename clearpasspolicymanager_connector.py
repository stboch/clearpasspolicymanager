#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from clearpasspolicymanager_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ClearpassPolicyManagerConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(ClearpassPolicyManagerConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._base_url_oauth = None

        self._client_id = None
        self._client_secret = None
        self._access_token = None

    def initialize(self):
        """ Called by the BaseConnector before calls to the handle_action function"""

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config[CCPM_JSON_BASE_URL]
        self._base_url_oauth = config[CCPM_JSON_BASE_URL]
        self._client_id = config[CPPM_JSON_CLIENT_ID]
        self._client_secret = config[CPPM_JSON_CLIENT_SECRET]

        return phantom.APP_SUCCESS

    def _get_token(self, action_result, from_action=False):
        # Retrieves a new Bearer token

        payload = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret
        }

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        url = "{}{}".format(self._base_url, CPPM_OAUTH_TOKEN_ENDPOINT)
        ret_val, resp_json = self._make_rest_call_oauth2(
            url, action_result, headers=headers, data=json.dumps(payload), method="post"
        )

        if phantom.is_fail(ret_val):
            self._state.pop(CCPM_OAUTH_TOKEN, {})
            return action_result.get_status()

        self._state[CCPM_OAUTH_TOKEN] = resp_json
        self._access_token = resp_json[CCPM_OAUTH_TOKEN]
        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get("verify_server_cert", False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _make_rest_call_oauth2(
        self,
        endpoint,
        action_result,
        headers=None,
        params=None,
        data=None,
        json=None,
        method="get",
    ):
        """Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        try:
            r = request_func(
                endpoint, json=json, data=data, headers=headers, params=params
            )
        except Exception as e:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error connecting to server. Details: {0}".format(
                        self._get_error_message_from_exception(e)
                    ),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _make_rest_call_helper_oauth2(
        self,
        action_result,
        endpoint,
        headers=None,
        params=None,
        data=None,
        json=None,
        method="get",
    ):
        """Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        url = "{0}{1}".format(self._base_url_oauth, endpoint)
        if headers is None:
            headers = {}

        if not self._access_token:
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({"Authorization": "Bearer {0}".format(self._access_token)})

        if not headers.get("Content-Type"):
            headers["Content-Type"] = "application/json"

        ret_val, resp_json = self._make_rest_call_oauth2(
            url, action_result, headers, params, data, json, method
        )

        # If token is expired, generate a new token
        msg = action_result.get_message()
        if (
            msg
            and "token is invalid" in msg
            or "token has expired" in msg
            or "ExpiredAuthenticationToken" in msg
            or "authorization failed" in msg
            or "access denied" in msg
        ):
            ret_val = self._get_token(action_result)

            headers.update({"Authorization": "Bearer {0}".format(self._access_token)})

            ret_val, resp_json = self._make_rest_call_oauth2(
                url, action_result, headers, params, data, json, method
            )

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(
            "Connecting to endpoint, getting information about supplied access token"
        )

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, CPPM_OAUTH_ME_ENDPOINT
        )
        if phantom.is_fail(ret_val):
            self.save_progress(CPPM_ERR_CONNECTIVITY_TEST)
            return phantom.APP_ERROR

        self.save_progress("Test connectivity passed")

        return action_result.set_status(
            phantom.APP_SUCCESS, CPPM_SUCC_CONNECTIVITY_TEST
        )

    def _handle_terminate_session(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        macaddress = param["macaddress"]

        session_filter = {"mac_address": macaddress}

        params = {"filter": json.dumps(session_filter)}

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, CPPM_SESSIONS_ENDPOINT, params=params
        )
        if phantom.is_fail(ret_val):
            self.save_progress(CPPM_ERR_TERMINATE_SESSION_QUERY_SESSIONS)
            return phantom.APP_ERROR

        sessions = resp_json["_embedded"]["items"]

        result = {"num_sessions": len(sessions), "responses": []}

        for session in sessions:
            payload = {"id": session["id"], "confirm_disconnect": True}
            endpoint = CPPM_DISCONNECT_SESSION_ENDPOINT.format(session["id"])
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result, endpoint, headers=headers, json=payload, method="post"
            )
            if phantom.is_fail(ret_val):
                self.save_progress(CPPM_ERR_TERMINATE_SESSION_DISCONNECT_SESSION)
                return phantom.APP_ERROR
            result["responses"].append(resp_json)

        self.save_progress("Disconnected all active sessions")

        action_result.add_data(result)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_endpoint_mac(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        macaddress = param["macaddress"]
        attributes = param.get("attributes_json")
        status = param.get("status")

        payload = {
            "mac_address": macaddress,
        }

        if status:
            payload.update({"status": status})
        if attributes:
            try:
                parsed_attributes = json.loads(attributes)
                payload.update({"attributes": parsed_attributes})
            except Exception:
                self.save_progress(CPPM_ERR_ATTRIBUTES_JSON_PARSE)
                return phantom.APP_ERROR

        headers = {
            "Content-Type": "application/json"
        }
        endpoint = CPPM_ENDPOINT_MAC_ENDPOINT.format(macaddress)
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, endpoint, headers=headers, json=payload, method="patch"
        )
        if phantom.is_fail(ret_val):
            self.save_progress(CPPM_ERR_UPDATE_ENDPOINT)
            return phantom.APP_ERROR

        action_result.add_data(resp_json)

        self.save_progress(CPPM_SUCC_UPDATE_ENDPOINT)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_endpoint_mac(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        macaddress = param["macaddress"]
        headers = {
            "Content-Type": "application/json"
        }

        endpoint = CPPM_ENDPOINT_MAC_ENDPOINT.format(macaddress)
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, endpoint, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress(CPPM_ERR_GET_ENDPOINT)
            return phantom.APP_ERROR

        action_result.add_data(resp_json)

        self.save_progress(CPPM_SUCC_GET_ENDPOINT)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_mac(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        macaddress = param["macaddress"]
        headers = {
            "Content-Type": "application/json"
        }

        endpoint = CPPM_DEVICE_MAC_ENDPOINT.format(macaddress)
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, endpoint, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress(CPPM_ERR_GET_DEVICE)
            return phantom.APP_ERROR

        action_result.add_data(resp_json)

        self.save_progress(CPPM_SUCC_GET_DEVICE)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_guest_user(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param["username"]
        headers = {
            "Content-Type": "application/json"
        }

        endpoint = CPPM_GUEST_USER_ENDPOINT.format(username)
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, endpoint, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress(CPPM_ERR_GET_GUESTUSER)
            return phantom.APP_ERROR

        action_result.add_data(resp_json)

        self.save_progress(CPPM_SUCC_GET_GUESTUSER)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "terminate_session": self._handle_terminate_session,
            "update_endpoint_mac": self._handle_update_endpoint_mac,
            "get_endpoint_mac": self._handle_get_endpoint_mac,
            "get_device_mac": self._handle_get_device_mac,
            "get_guest_user": self._handle_get_guest_user
        }

        action_keys = list(action_mapping.keys())

        if action_id in action_keys:
            action_function = action_mapping[action_id]
            ret_val = action_function(param)

        return ret_val

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = (
                ClearpassPolicyManagerConnector._get_phantom_base_url() + "/login"
            )

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
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ClearpassPolicyManagerConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
