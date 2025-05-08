import requests
import ujson

def get_asn_lookup(resource):
    """
    Get advertising ASN data from RIPE RIS.

    Returns:
        JSON response from the RIPEstat Network Info API.
    """
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'resource': resource}
    url = 'https://stat.ripe.net/data/network-info/data.json'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS).content

    return ujson.loads(resources)['data']

def get_reverseripedb_lookup(org):
    """
    Get forward and reverse DNS records from a hostname or IP address using RIPEstat.

    Returns:
        JSON response from the RIPEstat DNS Chain API.
    """
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'inverse-attribute': 'org',
              'query-string': org,
              'type-filter': 'aut-num'}
    url = 'http://rest.db.ripe.net/search.json'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS).content
    resources = ujson.loads(resources)

    if 'errormessages' in resources: # No other objects found
        return []

    resources = resources['objects']['object']
    # This returns a lot more data than needed, filter
    asns = []
    for result in resources:
        if result['type'] == 'aut-num':
            asns.append(result['primary-key']['attribute'][0]['value'])

    return asns
