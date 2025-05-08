"""
Company Data
"""

import requests
import ujson

# UK
def get_company_lookup(key, org=None, address=None):
    """
    Get forward and reverse DNS records from a hostname or IP address using RIPEstat.

    Returns:
        JSON response from the RIPEstat DNS Chain API.
    """
    HEADERS = {'content-type': 'application/json'}
    PARAMS = {'company_name_includes': org,
              'location': address,
              'company_status': 'active'}
    url = 'https://api.company-information.service.gov.uk/advanced-search/companies'

    # Get Data
    resources = requests.get(url, headers=HEADERS, auth=(key,''), params=PARAMS).content

    return ujson.loads(resources)['items']
