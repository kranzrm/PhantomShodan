import phantom.rules as phantom
import json

def query_ip_cb(action, success, container, results, handle):

    if not success:
        return

    return

def query_ip1_cb(action, success, container, results, handle):

    if not success:
        return

    return


def on_start(container):

    sourceAddress = set(phantom.collect(container, 'artifact:*.cef.sourceAddress'))

    parameters = []

    for ip in sourceAddress:
        parameters.append({"ip": ip,})

    phantom.act("query ip", parameters=parameters, assets=["shodan"]) # callback=query_ip_cb

    destinationAddress = set(phantom.collect(container, 'artifact:*.cef.destinationAddress'))

    parameters = []

    for ip in destinationAddress:
        parameters.append({"ip": ip,})

    phantom.act("query ip", parameters=parameters, assets=["shodan"]) # callback=query_ip1_cb

    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # Summary and/or action results can be collected here.

    # summary_json = phantom.get_summary()
    # summary_results = summary_json['result']
    # for result in summary_results:
            # app_runs = result['app_runs']
            # for app_run in app_runs:
                    # app_run_id = app_run['app_run_id']
                    # action_results = phantom.get_action_results(app_run_id=app_run_id)
    return

