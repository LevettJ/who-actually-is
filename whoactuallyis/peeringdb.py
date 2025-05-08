import requests
import ujson

def get_pdb_asn_lookup(asn):
    """
    Get information from PeeringDB about a specified ASN.

    Args:
        asn (int): ASN to return information for.
    Returns:
        JSON response from the PeeringDB Net API.
    """
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'asn': asn}
    url = 'https://www.peeringdb.com/api/net'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS).content

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
    url = 'https://www.peeringdb.com/api/org'

    # Get Data
    resources = requests.get(url, headers=HEADERS, params=PARAMS).content

    return ujson.loads(resources)['data']
