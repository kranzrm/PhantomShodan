# -----------------------------------------
# Shodan Search APP
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from shodan_consts import *

import simplejson as json
import datetime
import urllib


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


# Define the App Class
class ShodanConnector(BaseConnector):

    ACTION_ID_SEARCH_DOMAIN = "query_domain"
    ACTION_ID_SEARCH_IP = "query_ip"

    def _query_shodan(self, url, action_result):
        # TODO: Handle connection errors more gracefuly
        try:
            f = urllib.urlopen(url)
            retstr = f.read()
            self.debug_print("retstr", retstr)
            resp = json.loads(retstr)
        except Exception as e:
            self.set_status(phantom.APP_ERROR, SHODAN_ERR_SERVER_CONNECTION, e)
            self.append_to_message("ERROR")
            # return self.set_status_save_progress(phantom.APP_SUCCESS, SHODAN_ERR_API_TEST)
            return False

        if 'error' in resp:
            self.append_to_message(resp['error'])
            action_result.update_summary({'Results': 0, 'Error': resp['error']})

        return resp

    def _test_connectivity(self, param):

        config = self.get_config()
        # Get and test the API Key
        api_key = config.get(SHODAN_JSON_APIKEY)
        if (not api_key):
            self.save_progress("No API Key set")
            return self.get_status()

        # Add an action result to the App Run
        action_result = ActionResult()
        self.add_action_result(action_result)
        self.save_progress("Testing Shodan API Key")

        try:
            qp = urllib.urlencode({'key': api_key})
            f = urllib.urlopen(SHODAN_BASE_URL + "api-info?%s" % qp)
            retstr = f.read()
            self.debug_print("retstr", retstr)
            resp = json.loads(retstr)
            action_result.add_data(resp)

        except Exception as e:
            self.set_status(phantom.APP_ERROR, SHODAN_ERR_SERVER_CONNECTION, e)
            self.append_to_message(SHODAN_ERR_API_TEST)
            return self.set_status_save_progress(phantom.APP_SUCCESS, SHODAN_ERR_API_TEST)

        return self.set_status_save_progress(phantom.APP_SUCCESS, SHODAN_SUCC_API_TEST)

    def _handle_query_domain(self, param):

        # Get the config
        config = self.get_config()
        self.debug_print("param", param)
        api_key = config.get(SHODAN_JSON_APIKEY)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        self.save_progress("Querying Domain")

        # Setup Rest Query
        target = param[SHODAN_JSON_DOMAIN]
        qp = urllib.urlencode({'key': api_key, 'query': "hostname:{0}".format(target)})
        rest_url = SHODAN_BASE_URL + "shodan/host/search?%s" % qp
        shodan_response = self._query_shodan(rest_url, action_result)
        self.debug_print('resp', shodan_response)

        # Handle response error conditions
        if shodan_response is False:
            # There was an error, no results
            self.append_to_message(SHODAN_ERR_QUERY)
            return self.set_status_save_progress(phantom.APP_ERROR, SHODAN_ERR_QUERY)
        elif 'error' in shodan_response:
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Shodan Error")

        for match in shodan_response['matches']:
            action_result.add_data(match)

        summary = {
            'Results': str(len(shodan_response['matches']))
        }
        action_result.update_summary(summary)
        action_result.set_status(phantom.APP_SUCCESS)
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Query Successfull")

    def _handle_query_ip(self, param):

        # Get the config
        config = self.get_config()
        self.debug_print("param", param)
        api_key = config.get(SHODAN_JSON_APIKEY)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        self.save_progress("Querying IP")

        # Setup Rest Query
        target = param[SHODAN_JSON_IP]
        qp = urllib.urlencode({'key': api_key})
        rest_url = SHODAN_BASE_URL + "shodan/host/{0}?{1}".format(target, qp)
        shodan_response = self._query_shodan(rest_url, action_result)

        # Handle response error conditions
        if shodan_response is False:
            # There was an error, no results
            self.append_to_message(SHODAN_ERR_QUERY)
            return self.set_status_save_progress(phantom.APP_ERROR, SHODAN_ERR_QUERY)
        elif 'error' in shodan_response:
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Shodan Error")

        # Sanitize/Add data and summary
        for record in shodan_response['data']:
            action_result.add_data(record)

        summary = {
            'Results': str(len(shodan_response['data'])),
            'Country': shodan_response['country_name'],
            'Open Ports': ", ".join(str(x) for x in shodan_response['ports']),
            'Hostnames': ", ".join(shodan_response['hostnames'])
        }
        action_result.update_summary(summary)

        action_result.set_status(phantom.APP_SUCCESS)
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Query Successfull")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_SEARCH_DOMAIN):
            ret_val = self._handle_query_domain(param)
        elif (action_id == self.ACTION_ID_SEARCH_IP):
            ret_val = self._handle_query_ip(param)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val

if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ShodanConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
