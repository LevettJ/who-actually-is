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

def get_announced_prefixes(resource):
    """
    Get the prefixes announced by an ASN as seen by RIPE RIS.

    Returns:
        JSON response from the RIPEstat Announced Prefixes API.
    """
    HEADERS = {'content-type': 'application/json'}
    # Default lookup: last two weeks (to current date/time)
    # Default minumum peers to be listed: 10
    # Keeping default lookup values
    PARAMS = {'resource': resource}
    url = 'https://stat.ripe.net/data/announced-prefixes/data.json'

    # Get Data
    prefixes = requests.get(url, headers=HEADERS, params=PARAMS, timeout=10).content
    prefixes = ujson.loads(prefixes)

    prefixes = prefixes.get('data', [])
    if prefixes:
        prefixes = prefixes.get('prefixes')

    return prefixes