# Shodan.io API connector for Phantom

This App for [Phantom security orchestrator](https://www.phantom.us/product.html) provides access to
information from [Shodan.io](https://www.shodan.io).


## Suggested Use-Cases

This app can be used to check whether or not a given IP address is listening given ports. This allows us to gain information that is: credible, publicly accessible, and does not require a single packet to be sent to the target IP address.

For Example:

*   For alerts about an inbound connection, phantom can validate whether or not the service is publicly accessible.
*   For alerts regarding outbound connections (irc, smtp, ntp, etc.) this can be used to verify whether or not the host is hosting that service and what service is listening on that port.
*   Perform reconnaissance on internet hosts

## Current Actions

* query ip - Query shodan for observed services for a given IP
* query domain - Query shodan for observed services for a given fqdn

## Future Features

Currently, this app performs a lookup against a domain or ip address for open ports and services.

Future areas of expansion include:

*   Implement more specific checks to look for specific IP _and_ Port
*   Implement checks to support IP ranges / CIDR blocks
*   Triggering on-demand scan for paid developer accounts
*   DNS forward and reverse resolution
*   Implement widgets (Webpage Thumbnails, etc.)

## Setup

1. Download a [Phantom](https://www.phantom.us/product.html) appliance from Phantom Cyber.
2. Obtain an API key from [Shodan.io](https://www.shodan.io). A free API key can be obtained from the Shodan.io website by registering and visiting your [account page](https://account.shodan.io)
3. Select "Import App" from the *Administration / Apps* tab.
   * Select the shodan.tgz file.
   * Check "Replace an Existing app" if an older version is installed.

## References

*   Phantom Cyber Product Page [https://www.phantom.us/product.html](https://www.phantom.us/product.html)
*   Shodan Developer Reference: [https://developer.shodan.io/api](https://developer.shodan.io/api)
*   Shodan Search Page: [https://www.shodan.io](https://www.shodan.io)
