import requests
import ujson

def get_dns_lookup(resource):
    """
    Get forward and reverse DNS records from a hostname or IP address using RIPEstat.

    Returns:
        JSON response from the RIPEstat DNS Chain API.
    """
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'resource': resource}
    url = 'https://stat.ripe.net/data/dns-chain/data.json'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS).content

    return ujson.loads(resources)['data']