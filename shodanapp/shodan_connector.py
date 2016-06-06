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
import requests

requests.packages.urllib3.disable_warnings()


# Define the App Class
class ShodanConnector(BaseConnector):

    ACTION_ID_SEARCH_DOMAIN = "query_domain"
    ACTION_ID_SEARCH_IP = "query_ip"

    def __init__(self):

        super(ShodanConnector, self).__init__()

    def _query_shodan(self, endpoint, result, params={}):

        config = self.get_config()

        # Get the API Key, it's marked as required in the json, so the platform/BaseConnector will fail if
        # not found in the input asset config
        api_key = config[SHODAN_JSON_APIKEY]

        params.update({'key': api_key})

        url = SHODAN_BASE_URL + endpoint

        try:
            r = requests.get(url, params=params)
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, SHODAN_ERR_SERVER_CONNECTION, e), None)

        # The result object can be either self (i.e. BaseConnector) or ActionResult
        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        # shodan gives back a json even in case of error, so parse the json before
        # checking for the http
        try:
            resp = r.json()
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, SHODAN_ERR_RESPONSE_IS_NOT_JSON, e), None)

        if 'error' in resp:
            return (result.set_status(phantom.APP_ERROR, resp['error']), resp)

        # Usually should not come here _and_ has encountered an HTTP error, but still look for errors
        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (result.set_status(phantom.APP_ERROR, "REST Api Call returned error, status_code: {0}, data: {1}".format(r.status_code, r.text)), r.text)

        # Success, return the data retrieved
        return (phantom.APP_SUCCESS, resp)

    def _test_connectivity(self, param):

        self.save_progress("Testing Shodan API Key")

        ret_val, resp = self._query_shodan('/api-info', self)

        if (not ret_val):
            self.append_to_message(SHODAN_ERR_API_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, SHODAN_SUCC_API_TEST)

    def _handle_query_domain(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Querying Domain")

        # Setup Rest Query
        target = param[SHODAN_JSON_DOMAIN]
        params = {'query': "hostname:{0}".format(target)}

        endpoint = "shodan/host/search"

        ret_val, shodan_response = self._query_shodan(endpoint, action_result, params)

        if (not ret_val):
            return action_result.get_status()

        if (not shodan_response):
            # There was an error, no results
            action_result.append_to_message(SHODAN_ERR_QUERY)
            return action_result.get_status()

        self.debug_print('resp', shodan_response)

        matches = shodan_response.get('matches', [])

        if (not matches):
            self.save_progress("Did not find any info on the domain, doing a complete search")
            params = {'query': "{0}".format(target)}
            ret_val, shodan_response = self._query_shodan(endpoint, action_result, params)

            if (not ret_val):
                return action_result.get_status()

            if (not shodan_response):
                # There was an error, no results
                action_result.append_to_message(SHODAN_ERR_QUERY)
                return action_result.get_status()

            matches = shodan_response.get('matches', [])

        for match in matches:
            action_result.add_data(match)

        # Create the summary as a normal dictionary, so that parsing it from the playbooks is easy.
        # The BaseConnector does the job of Capitalizing the dictionary keys to display them properly
        # in the UI.
        summary = {
            'results': len(matches)
        }

        action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_ip(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Querying IP")

        # Setup Rest Query
        target = param[SHODAN_JSON_IP]
        endpoint = "shodan/host/{0}".format(target)

        ret_val, shodan_response = self._query_shodan(endpoint, action_result)

        if (not ret_val):
            return action_result.get_status()

        if (not shodan_response):
            # There was an error, no results
            action_result.append_to_message(SHODAN_ERR_QUERY)
            return action_result.get_status()

        # Sanitize/Add data and summary
        data = shodan_response.get('data', [])
        for record in data:
            action_result.add_data(record)

        # Create the summary as a normal dictionary, it helps in parsing it from the playbooks
        # easier. The BaseConnector does the job of Capitalizing the dictionary
        open_ports = shodan_response.get('ports')
        open_ports = ", ".join(str(x) for x in shodan_response.get('ports', [])) if open_ports else None

        hostnames = shodan_response.get('hostnames')
        hostnames = ", ".join(str(x) for x in shodan_response.get('hostnames', [])) if hostnames else None

        summary = {
            'results': len(data),
            'country': shodan_response.get('country_name', ''),
            'open_ports': open_ports,
            'hostnames': hostnames}

        action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

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
