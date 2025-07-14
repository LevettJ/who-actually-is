import requests
import ujson

# Using live PeeringDB endpoint
# Set up a local (not rate-limited): https://github.com/peeringdb/peeringdb-py/
PEERINGDB_API_TARGET = "https://www.peeringdb.com/api"

def get_pdb_asn_lookup(asn):
    """
    Get information from PeeringDB about a specified ASN.

    Args:
        asn (int): ASN to return information for.
    Returns:
        JSON response from the PeeringDB Net API.
    """
    if asn.startswith('AS'):
            asn = asn[2:]
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'asn': asn}
    url = PEERINGDB_API_TARGET + '/net'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS, timeout=10).content
    
    return ujson.loads(resources)['data']

def get_pdb_org_lookup(org):
    """
    Get information from PeeringDB about a specified organisation.

    Args:
        org (int): OrgID to return information for.
    Returns:
        JSON response from the PeeringDB Org API.
    """
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'id': org,
              'depth': 2}
    url = PEERINGDB_API_TARGET + '/org'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS, timeout=10).content

    return ujson.loads(resources)['data']
