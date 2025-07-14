"""
WHOactuallyIS?
This module provides functionality to look up information about IP addresses,
ASNs (Autonomous System Numbers), and domains. It aggregates data from
various sources including DNS, RDAP/WHOIS and PeeringDB.

Authors: Joshua Levett, Poonam Yadav, Vassilios Vassilakis
"""

# Core Imports
import logging
import re
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# External Dependencies
import whoisit
from tld import get_fld, get_tld

from whoactuallyis.dns import get_dns_lookup
from whoactuallyis.matcher import match_entities, determine_best_primary_name
from whoactuallyis.peeringdb import get_pdb_asn_lookup, get_pdb_org_lookup
from whoactuallyis.rdap import get_asn_lookup, get_announced_prefixes
# from whoactuallyis.rdap import get_reverseripedb_lookup

logger = logging.getLogger(__name__)

def _get_rdap_data(
    resource_identifier: str,
    resource_type_label: str,
    rdap_function: callable,
    *args: Any,
    **kwargs: Any
    ) -> Optional[Dict[str, Any]]:
    """
    Helper function to perform an RDAP lookup and format the basic data.

    Args:
        resource_identifier: The resource being looked up (IP, domain, ASN).
        resource_type_label: A label for the type of resource ('ip_owner', 'domain_registrant').
        rdap_function: The whoisit library function to call (whoisit.ip, whoisit.domain).
        *args: Arguments to pass to the rdap_function.
        **kwargs: Keyword arguments to pass to the rdap_function.

    Returns:
        A dictionary with the RDAP data, otherwise None.
        Includes 'type', 'resource', 'entities', and 'source'.
    """
    try:
        rdap_info = rdap_function(*args, **kwargs)
        if rdap_info and 'entities' in rdap_info and rdap_info.get('url'):
            return {
                'type': resource_type_label,
                'resource': resource_identifier,
                'entities': rdap_info.get('entities'),
                'source': rdap_info['url']
            }
        elif rdap_info: # Lookup succeeded but data is incomplete
            logger.warning(
                "RDAP info for %s (%s) was incomplete or missing URL/entities. Raw: %s",
                resource_identifier, resource_type_label, str(rdap_info)[:200]
            )
            # Return data, but may contain None
            return {
                'type': resource_type_label,
                'resource': resource_identifier,
                'entities': rdap_info.get('entities'),
                'source': rdap_info.get('url', 'N/A')
            }
        else: # Lookup failed to return any info
            logger.warning(
                "RDAP lookup via %s for %s (%s) returned no information.",
                rdap_function.__name__, resource_identifier, resource_type_label
            )
            return None
    except Exception as e:
        logger.error(
            "Error during RDAP lookup for %s (%s) using %s: %s",
            resource_identifier, resource_type_label, rdap_function.__name__, e,
            exc_info = False
        )
        return None


class WaiResponse:
    """
    WHOactuallyIS response object.
    """
    def __init__(self, target_input: Optional[str] = None):
        """
        Initializes the WaiResponse object.
        Args:
            target_input: The original target string (IP, ASN, domain) for the lookup.
        """
        self.target: Optional[str] = target_input # The original input target
        self.final_target: Optional[Union[IPv4Address, IPv6Address, str, int]] = None # Processed target
        self.target_type: Optional[str] = None # 'ip', 'asn', 'domain'
        self.recursive: bool = False

        self.raw: Dict[str, Any] = {
            'forward_dns': None,  # List (for IP->FQDNs) or dict (for Domain->Host->IPs)
            'reverse_dns': None,  # Typically a list of PTR records
            'nameservers': None,  # Typically a list of authoritative nameservers
            'parent_zone': [],    # List of First-Level Domains (FLDs)
            'asns': []            # List of ASNs associated with an IP or Domain
        }

        self.resources: List[str] = [] # List of unique resource identifiers (IPs, domains, ASNs) found
        self.users: List[Dict[str, Any]] = [] # Processed and structured entity information
        self.errors: List[str] = [] # List of any errors from processing


def _determine_target_type(target: str) \
      -> Tuple[Optional[str], Union[IPv4Address, IPv6Address, str, int, None]]:
    """
    Determines if the target is an IP, ASN, or domain name.

    Args:
        target: Input target resource.

    Returns:
        A tuple: (target_type, processed_target).
            target_type can be 'ipv4', 'ipv6', 'asn', 'domain', or None if not valid.
            processed_target is the formatted form (IPv4Address for IPv4, int for ASN).
    """
    # Try IPv4
    if '.' in target and target.replace('.', '').isdigit():
        try:
            return 'ipv4', IPv4Address(target)
        except AddressValueError: # Invalid IPv4
            pass # Fall through to next check

    # Try IPv6
    if ':' in target:
        try:
            return 'ipv6', IPv6Address(target)
        except AddressValueError: # Invalid IPv6
            pass # Fall through to next check

    # Try ASN
    # Typically a number, often prefixed with "AS"
    if 'as' in target.lower():
        target = target.lower().replace('as', '')
    if target.isdigit():
        return 'asn', int(target)

    # Assume must be domain or invalid.
    # Basic domain validation: contains a '.' (and is not an IP).
    if '.' in target:
        return 'domain', target.strip()

    # If not valid IPv4, IPv6, ASN or domain, return type as None.
    return None, target


def lookup(target: str, recursive: bool = False) -> WaiResponse:
    """
    Performs a WHOactuallyIS lookup on a target IP, ASN, or domain.

    Args:
        target: The string representation of the IP address, ASN, or domain.
        recursive: (Optional) Performs ASN/prefix lookup recursively. This takes a lot of time.

    Returns:
        A WaiResponse object containing the lookup results.
    """
    r = WaiResponse(target_input=target)
    r.recursive = recursive
    raw_users_data: List[Dict[str, Any]] = [] # Data from _lookup_* functions

    try:
        # Get latest WHOISIT registries
        whoisit.bootstrap(overrides=True)

        target_type, processed_target = _determine_target_type(target)
        r.final_target = processed_target
        
        if target_type is None:
            logger.warning("Target '%s' type is None.", target)
            raise ValueError(f"Invalid target: '{target}'. Could not determine type (IP, ASN, Domain).")

        if target_type == 'asn' and isinstance(processed_target, int):
            r.target_type = 'asn'
            raw_users_data = _lookup_asn(str(processed_target), r)
        elif target_type in ('ipv4', 'ipv6') and processed_target is not None:
            r.target_type = 'ip'
            raw_users_data = _lookup_ip(str(processed_target), r)
        elif target_type == 'domain' and isinstance(processed_target, str):
            r.target_type = 'domain'
            raw_users_data = _lookup_domain(processed_target, r)

    except ValueError as ve: # Catch IP/ASN parsing errors
        r.errors.append(f"Input error: {ve}")
        logger.error("Input error for target '%s': %s", target, ve)
        return r
    except Exception as e: # Catch-all
        msg = f"Unexpected error during lookup for '{target}': {e}"
        r.errors.append(msg)
        logger.exception(msg)
        return r

    collected_resources: Set[str] = set()
    for item_data in raw_users_data:
        if item_data is None: # Skip if a lookup step returned None
            continue

        # Ensure 'entities' key exists; it can be None if lookup found no entities.
        item_entities = item_data.get('entities')
        item_resource = item_data.get('resource')

        if item_resource:
            collected_resources.add(str(item_resource))

        if item_entities is not None: # Process if entities were found
            processed_entity_list = _process_entities(
                raw_rdap_entities=item_entities,
                entity_source_type=item_data.get('type', 'unknown_type'),
                entity_source_resource=str(item_resource) if item_resource else 'unknown_resource'
            )
            r.users.extend(processed_entity_list)
        elif item_data.get('type') == 'peeringdb_org': # Handle PeeringDB entries
            # PeeringDB entries are structured differently with 'name', 'address', 'source'.
            adapted_pdb_entry = {
                'type': item_data.get('type'),
                'resource': str(item_resource) if item_resource else 'unknown_resource',
                'relation': 'organisation',
                'handle': None,
                'name': item_data.get('name'),
                'address': item_data.get('address'),
                'tel': None,
                'email': None,
                'aka': {item_data.get('aka')} if item_data.get('aka', '') != '' else set(),
                'source': item_data.get('source')
            }
            r.users.append(adapted_pdb_entry)

    try:
        match_entities(r)
    except Exception as e:
        msg = f"Error during entity matching for target '{target}': {e}"
        r.errors.append(msg)
        logger.error(msg, exc_info=True)

    r.resources = sorted(list(collected_resources))
    return r


def _lookup_asn(target_asn_str: str, r: WaiResponse) -> List[Dict[str, Any]]:
    """
    Performs a lookup for a target ASN.

    Args:
        target_asn_str: ASN to find information for (as a string).

    Returns:
        A list of dictionaries.
    """
    r.raw['asns'] += target_asn_str
    collected_raw_users: List[Dict[str, Any]] = []
    processed_pdb_org_ids: Set[int] = set() # To avoid duplicate PeeringDB org processing

    # 1. RDAP ASN Lookup
    rdap_asn_data = _get_rdap_data(
        'AS'+target_asn_str, 'advertising_asn', whoisit.asn, 'AS'+target_asn_str
    )
    if rdap_asn_data:
        collected_raw_users.append(rdap_asn_data)

    # 2. RIPE RIS Prefixes Lookup
    # Run only where ASN is the primary target, or when recursion is enabled
    if str(r.final_target) == target_asn_str or r.recursive:
        prefixes = get_announced_prefixes(target_asn_str)

        for prefix in prefixes:
            # Lookup information about containing prefixes
            # Noting that these are of lower confidence as prefixes may not belong to ASN owner
            # Primitive lookup: First IP in prefix range (inc. 0.0)
            target_ip = prefix.get('prefix')[:-3] # Ignore prefix notation
            collected_raw_users.extend(_lookup_ip(target_ip, r))

    # 3. PeeringDB ASN and Organisation Lookup
    try:
        pdb_asn_results = get_pdb_asn_lookup(target_asn_str)
        for pdb_asn_entry in pdb_asn_results:
            org_id = pdb_asn_entry.get('org_id')
            if org_id and org_id not in processed_pdb_org_ids:
                try:
                    pdb_org_details_list = get_pdb_org_lookup(org_id)
                    if pdb_org_details_list:
                        pdb_org_detail = pdb_org_details_list[0] # Assuming first result is primary
                        
                        # Construct address as single string
                        address_parts = [
                            pdb_org_detail.get('address1',''),
                            pdb_org_detail.get('address2',''),
                            pdb_org_detail.get('city',''),
                            pdb_org_detail.get('country','')
                        ]
                        full_address = ' '.join(part for part in address_parts if part and part.strip()).strip()

                        for asn in pdb_org_detail.get('net_set', []):
                            peeringdb_org_data = {
                                'type': 'peeringdb_org',
                                # Resource for PeeringDB org can be the list of ASNs it owns
                                'resource': f"AS{asn.get('asn')}",
                                'org_id': org_id,
                                'name': pdb_org_detail.get('name'),
                                'aka': pdb_org_detail.get('aka', ''),
                                'address': full_address if full_address else None,
                                'source': 'peering_db',
                                'entities': None
                            }
                            collected_raw_users.append(peeringdb_org_data)

                        processed_pdb_org_ids.add(org_id)
                except Exception as e_pdb_org:
                    logger.error("Error looking up PeeringDB org ID %s for ASN %s: %s",
                                 org_id, target_asn_str, e_pdb_org)
    except Exception as e_pdb_asn:
        logger.error("Error looking up PeeringDB ASN %s: %s", target_asn_str, e_pdb_asn)

    collected_resources: Set[str] = set()
    for item_data in collected_raw_users:
        if item_data is None: # Skip if a lookup step returned None
            continue

        # Ensure 'entities' key exists; it can be None if lookup found no entities.
        item_entities = item_data.get('entities')
        item_resource = item_data.get('resource')

        if item_resource:
            collected_resources.add(str(item_resource))

        if item_entities is not None: # Process if entities were found
            processed_entity_list = _process_entities(
                raw_rdap_entities=item_entities,
                entity_source_type=item_data.get('type', 'unknown_type'),
                entity_source_resource=str(item_resource) if item_resource else 'unknown_resource'
            )
            r.users.extend(processed_entity_list)
        elif item_data.get('type') == 'peeringdb_org': # Handle PeeringDB entries
            # PeeringDB entries are structured differently with 'name', 'address', 'source'.
            adapted_pdb_entry = {
                'type': item_data.get('type'),
                'resource': str(item_resource) if item_resource else 'unknown_resource',
                'relation': 'organisation',
                'handle': None,
                'name': item_data.get('name'),
                'address': item_data.get('address'),
                'tel': None,
                'email': None,
                'aka': {item_data.get('aka')} if item_data.get('aka', '') != '' else set(),
                'source': item_data.get('source')
            }
            r.users.append(adapted_pdb_entry)

    try:
        match_entities(r)
    except Exception as e:
        msg = f"Error during entity matching for target '{target_asn_str}': {e}"
        r.errors.append(msg)
        logger.error(msg, exc_info=True)

    r.resources = sorted(list(collected_resources))

    return collected_raw_users


def _lookup_ip(target_ip_str: str, r: WaiResponse) -> List[Dict[str, Any]]:
    """
    Performs WHOIS/RDAP lookups related to a target IP address.
    """
    collected_raw_users: List[Dict[str, Any]] = []

    # 1. Get DNS data (fDNS, rDNS, nameservers)
    try:
        dns_data = get_dns_lookup(target_ip_str)
        r.raw['forward_dns'] = dns_data.get('forward_nodes', [])
        r.raw['reverse_dns'] = dns_data.get('reverse_nodes', [])
        r.raw['nameservers'] = dns_data.get('authoritative_nameservers', [])
    except Exception as e:
        logger.error("Error during DNS lookup for IP %s: %s", target_ip_str, e)
        r.errors.append(f"DNS lookup failed for {target_ip_str}: {e}")
        # Ensure keys exist even if lookup fails
        r.raw.setdefault('forward_dns', [])
        r.raw.setdefault('reverse_dns', [])
        r.raw.setdefault('nameservers', [])

    # 2. Derive Parent Zones
    r.raw['parent_zone'] = list(set(
        get_fld(str(domain), fix_protocol=True, fail_silently=True)
        for domain in r.raw.get('forward_dns', []) if domain # Ensure domain is not None
    ))

    # 3. RDAP/WHOIS Lookup for the target IP
    ip_owner_data = _get_rdap_data(target_ip_str, 'ip_owner', whoisit.ip, target_ip_str)
    if ip_owner_data:
        collected_raw_users.append(ip_owner_data)

    # Keep track of processed FLDs
    processed_flds_domain_owner: Set[str] = set()
    processed_flds_domain_parent: Set[str] = set()

    # 4. RDAP/WHOIS for fDNS
    for fqdn in r.raw.get('forward_dns', []):
        if not isinstance(fqdn, str): continue # Skip if not a string
        try:
            domain_fld = get_fld(fqdn, fix_protocol=True, fail_silently=True)
            if not domain_fld or domain_fld == get_tld(domain_fld, fix_protocol=True, fail_silently=True):
                continue # Skip if FLD is invalid or a TLD itself

            if domain_fld not in processed_flds_domain_owner:
                domain_owner_data = _get_rdap_data(domain_fld, 'domain_owner', whoisit.domain, domain_fld)
                if domain_owner_data:
                    collected_raw_users.append(domain_owner_data)
                processed_flds_domain_owner.add(domain_fld)
        except Exception as e_fld:
            logger.warning("Could not process FLD for fDNS entry '%s': %s", fqdn, e_fld)

    # 5. RDAP for Parent Zone domains
    for parent_fld in r.raw.get('parent_zone', []):
        if not isinstance(parent_fld, str): continue
        domain_to_check = parent_fld.strip('.')
        try:
            if not domain_to_check or domain_to_check == get_tld(domain_to_check, fix_protocol=True, fail_silently=True):
                continue

            if domain_to_check not in processed_flds_domain_parent:
                # This might re-lookup an FLD if it was also a direct fDNS entry's FLD
                # but under a different 'type' ('domain_parent' vs 'domain_owner').
                parent_domain_data = _get_rdap_data(
                    domain_to_check, 'domain_parent', whoisit.domain, domain_to_check
                )
                if parent_domain_data:
                    collected_raw_users.append(parent_domain_data)
                processed_flds_domain_parent.add(domain_to_check)
        except Exception as e_fld_parent:
            logger.warning("Could not process FLD for parent zone entry '%s': %s", parent_fld, e_fld_parent)

    # 6. Get Advertising ASN for the target IP
    new_asns = []
    try:
        asn_lookup_result = get_asn_lookup(target_ip_str)
        asn_lookup_result = asn_lookup_result.get('asns', [])

        for asn in asn_lookup_result: # Prevent recursive ASN lookups
            if asn not in r.raw['asns'] and asn not in new_asns:
                new_asns.append(asn)

        r.raw['asns'].extend(new_asns)

    except Exception as e:
        logger.error("Error during BGP ASN lookup for IP %s: %s", target_ip_str, e)
        r.errors.append(f"BGP ASN lookup failed for {target_ip_str}: {e}")

    # 7. For each ASN found, perform _lookup_asn
    all_asn_related_users: List[Dict[str, Any]] = []
    for asn_val in new_asns:
        asn_num_str = str(asn_val).upper().replace('AS', '')
        if asn_num_str.isdigit():
            try:
                asn_specific_users = _lookup_asn(asn_num_str, r)
                all_asn_related_users.extend(asn_specific_users)
            except Exception as e_asn_detail:
                logger.error("Error in _lookup_asn for ASN %s (from IP %s): %s",
                             asn_num_str, target_ip_str, e_asn_detail)
                r.errors.append(f"ASN detail lookup failed for {asn_val}: {e_asn_detail}")
    collected_raw_users.extend(all_asn_related_users)

    # 8. ORG Entity Lookups (from RDAP IP owner and advertising ASNs)
    for user_entry in collected_raw_users:
        user_type = user_entry.get('type')
        if user_type in ['ip_owner', 'advertising_asn']:
            entities = user_entry.get('entities')
            if isinstance(entities, dict):
                registrants = entities.get('registrant', [])
                if isinstance(registrants, list):
                    for registrant_info in registrants:
                        if isinstance(registrant_info, dict):
                            handle = registrant_info.get('handle')
                            rir = registrant_info.get('rir')
                            if handle and str(handle).upper().startswith('ORG'):
                                try:
                                    org_entity_details = whoisit.entity(handle, rir=rir)
                                    if org_entity_details:
                                        logger.debug("Fetched ORG entity details for %s: %s",
                                                     handle, str(org_entity_details)[:100])
                                    # registrant_info['org_details'] = org_entity_details
                                except Exception as e_org:
                                    logger.warning("Failed ORG entity lookup for %s (RIR %s): %s",
                                                 handle, rir, e_org)
    return collected_raw_users


def _lookup_domain(target_domain_str: str, r: WaiResponse) -> List[Dict[str, Any]]:
    """
    Performs WHOIS/RDAP lookups related to a target domain.
    """
    collected_raw_users: List[Dict[str, Any]] = []
    unique_resolved_ips: Set[str] = set()
    collected_asns_from_ips: Set[str] = set() # ASNs derived from resolved IPs

    # 1. Get DNS data for the target domain
    try:
        dns_data = get_dns_lookup(target_domain_str)
        r.raw['forward_dns'] = dns_data.get('forward_nodes', {})
        r.raw['reverse_dns'] = dns_data.get('reverse_nodes', []) # Usually less relevant
        r.raw['nameservers'] = dns_data.get('authoritative_nameservers', [])
    except Exception as e:
        logger.error("Error during DNS lookup for domain %s: %s", target_domain_str, e)
        r.errors.append(f"DNS lookup failed for {target_domain_str}: {e}")
        r.raw.setdefault('forward_dns', {})
        r.raw.setdefault('reverse_dns', [])
        r.raw.setdefault('nameservers', [])

    # 2. Derive Parent Zones from hostnames found in fDNS
    parent_zone_candidates: Set[str] = set()
    if isinstance(r.raw.get('forward_dns'), dict):
        for hostname_key in r.raw['forward_dns'].keys():
            try:
                fld = get_fld(hostname_key, fix_protocol=True, fail_silently=True)
                if fld:
                    parent_zone_candidates.add(fld)
            except Exception as e_fld_host:
                 logger.warning("Could not get FLD for hostname '%s': %s", hostname_key, e_fld_host)

    try:
        target_fld = get_fld(target_domain_str, fix_protocol=True, fail_silently=True)
        if target_fld:
            parent_zone_candidates.add(target_fld)
    except Exception as e_fld_target:
        logger.warning("Could not get FLD for target domain '%s': %s", target_domain_str, e_fld_target)
    r.raw['parent_zone'] = sorted(list(parent_zone_candidates))

    # 3. Process each hostname and its resolved IPs from fDNS
    if isinstance(r.raw.get('forward_dns'), dict):
        processed_host_flds_owner: Set[str] = set() # Track FLDs for 'domain_owner' type

        for hostname, ip_list in r.raw['forward_dns'].items():
            if not isinstance(ip_list, list):
                logger.warning("IP list for hostname '%s' is not a list: %s. Skipping.", hostname, type(ip_list))
                continue

            # RDAP for the FLD of this hostname
            try:
                host_fld = get_fld(hostname, fix_protocol=True, fail_silently=True)
                if host_fld and host_fld != get_tld(host_fld, fix_protocol=True, fail_silently=True):
                    if host_fld not in processed_host_flds_owner:
                        domain_owner_data = _get_rdap_data(host_fld, 'domain_owner', whoisit.domain, host_fld)
                        if domain_owner_data:
                            collected_raw_users.append(domain_owner_data)
                        processed_host_flds_owner.add(host_fld)
            except Exception as e_fld_host_rdap:
                logger.warning("Error processing RDAP for host FLD '%s' (from %s): %s",
                               host_fld, hostname, e_fld_host_rdap)

            # For each resolved IP of this hostname
            for resolved_ip_str in ip_list:
                if resolved_ip_str not in unique_resolved_ips:
                    unique_resolved_ips.add(resolved_ip_str)

                    # RDAP IP Owner
                    ip_owner_data = _get_rdap_data(resolved_ip_str, 'ip_owner', whoisit.ip, resolved_ip_str)
                    if ip_owner_data:
                        collected_raw_users.append(ip_owner_data)

                    # Advertising ASN for this IP
                    try:
                        asn_lookup_result = get_asn_lookup(resolved_ip_str)
                        asns_for_ip = asn_lookup_result.get('asns', [])
                        for asn_val in asns_for_ip:
                            collected_asns_from_ips.add(str(asn_val).upper().replace('AS',''))
                    except Exception as e_asn:
                        logger.error("Error during BGP ASN lookup for IP %s (from domain %s): %s",
                                     resolved_ip_str, target_domain_str, e_asn)
                        r.errors.append(f"BGP ASN lookup for {resolved_ip_str} failed: {e_asn}")

    # 4. RDAP for the target domain itself
    try:
        target_fld = get_fld(target_domain_str, fix_protocol=True, fail_silently=True)
        if target_fld and target_fld != get_tld(target_fld, fix_protocol=True, fail_silently=True):
            if target_fld not in processed_host_flds_owner:
                target_domain_data = _get_rdap_data(target_fld, 'domain_owner', whoisit.domain, target_fld)
                if target_domain_data:
                    collected_raw_users.append(target_domain_data)
                processed_host_flds_owner.add(target_fld)
    except Exception as e_target_fld_rdap:
        logger.warning("Error processing RDAP for target domain FLD '%s': %s",
                       target_domain_str, e_target_fld_rdap)

    # 5. RDAP for Parent Zone domains
    processed_flds_domain_parent: Set[str] = set()
    for parent_fld in r.raw.get('parent_zone', []):
        if not isinstance(parent_fld, str):
            continue
        domain_to_check = parent_fld.strip('.')
        try:
            if not domain_to_check or domain_to_check == get_tld(domain_to_check, fix_protocol=True, fail_silently=True):
                continue
            if domain_to_check not in processed_flds_domain_parent and domain_to_check not in processed_host_flds_owner:
                # Avoid re-querying if it was already looked up as 'domain_owner'
                parent_domain_data = _get_rdap_data(
                    domain_to_check, 'domain_parent', whoisit.domain, domain_to_check
                )
                if parent_domain_data:
                    collected_raw_users.append(parent_domain_data)
                processed_flds_domain_parent.add(domain_to_check)
        except Exception as e_fld_parent_rdap:
            logger.warning("Error processing RDAP for parent zone FLD '%s': %s",
                           parent_fld, e_fld_parent_rdap)

    # 6. For each unique ASN found from IPs, perform _lookup_asn
    new_asns = []
    for asn in list(collected_asns_from_ips): # Prevent recursive ASN lookups
            if asn not in r.raw['asns'] and asn not in new_asns:
                new_asns.append(asn)

    r.raw['asns'].extend(new_asns)
    all_asn_related_users: List[Dict[str, Any]] = []
    for asn_num_str in new_asns:
        if asn_num_str.isdigit():
            try:
                asn_specific_users = _lookup_asn(asn_num_str, r)
                all_asn_related_users.extend(asn_specific_users)
            except Exception as e_asn_detail:
                 logger.error("Error in _lookup_asn for ASN %s (from domain %s): %s",
                             asn_num_str, target_domain_str, e_asn_detail)
                 r.errors.append(f"ASN detail lookup for AS{asn_num_str} failed: {e_asn_detail}")
    collected_raw_users.extend(all_asn_related_users)

    # 7. ORG Entity Lookups
    for user_entry in collected_raw_users:
        user_type = user_entry.get('type')
        if user_type in ['ip_owner', 'advertising_asn']: # From IPs or their ASNs
            entities = user_entry.get('entities')
            if isinstance(entities, dict):
                registrants = entities.get('registrant', [])
                if isinstance(registrants, list):
                    for registrant_info in registrants:
                        if isinstance(registrant_info, dict):
                            handle = registrant_info.get('handle')
                            rir = registrant_info.get('rir')
                            if handle and str(handle).upper().startswith('ORG'):
                                try:
                                    org_entity_details = whoisit.entity(handle, rir=rir)
                                    if org_entity_details:
                                        logger.debug("Fetched ORG entity for %s (domain context): %s",
                                                     handle, str(org_entity_details)[:100])
                                except Exception as e_org:
                                    logger.warning("Failed ORG entity lookup for %s (RIR %s, domain context): %s",
                                                 handle, rir, e_org)
    return collected_raw_users


def _process_entities(
    raw_rdap_entities: Dict[str, List[Dict[str, Any]]],
    entity_source_type: Optional[str] = None,
    entity_source_resource: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Processes the entities dictionary from an RDAP response

    Args:
        raw_rdap_entities: 'entities' from an RDAP response.
        entity_source_type: The type of lookup.
        entity_source_resource: The resource associated with the lookup.

    Returns:
        A list of dictionaries.
    """
    processed_entities_list: List[Dict[str, Any]] = []
    if not isinstance(raw_rdap_entities, dict):
        logger.warning("raw_rdap_entities is not a dict, cannot process. Type: %s", type(raw_rdap_entities))
        return processed_entities_list

    for entity_role, entity_list in raw_rdap_entities.items(): # e.g. 'registrant'
        if not isinstance(entity_list, list):
            logger.warning("Entity list for role '%s' is not a list. Skipping. Type: %s", entity_role, type(entity_list))
            continue

        for entity_data_item in entity_list:
            if not isinstance(entity_data_item, dict):
                logger.warning("Entity data item for role '%s' is not a dict. Skipping. Item: %s", entity_role, entity_data_item)
                continue

            processed_entity: Dict[str, Any] = {
                'type': entity_source_type,
                'resource': entity_source_resource,
                'relation': entity_role, # e.g. 'registrant', 'administrative', 'technical'
                'handle': entity_data_item.get('handle'),
                'name': entity_data_item.get('name'),
                'address': None,
                'tel': None,
                'email': entity_data_item.get('email'),
                'aka': set(),
                'source_data': entity_data_item
            }

            # Construct address string
            raw_address_info = entity_data_item.get('address')
            if isinstance(raw_address_info, dict):
                address_parts = [
                    raw_address_info.get('street'),
                    raw_address_info.get('city'),
                    raw_address_info.get('postal_code'),
                    raw_address_info.get('country')
                ]
                # Join non-empty parts with a space
                full_address = ' '.join(filter(None, (str(p).strip() for p in address_parts if p))).strip()
                if full_address:
                    processed_entity['address'] = full_address
            elif isinstance(raw_address_info, str): # Or sometimes a simple string
                 processed_entity['address'] = raw_address_info.strip()


            # Clean telephone number
            raw_tel = entity_data_item.get('tel')
            if raw_tel:
                # Keep '+' and numbers. Remove spaces, hyphens, brackets
                processed_entity['tel'] = re.sub(r"[^\+\d]", "", str(raw_tel))

            processed_entities_list.append(processed_entity)
            
    return processed_entities_list


def get_final_names(r: WaiResponse) -> Dict[Any, str]:
    """
    Returns the final determined name(s) for resources.
    """
    logger.info("Attempting to resolve final names for target: %s", r.target)

    if not r.users:
        print(f"No user information found for target: {r.target}")
        return {}

    resolutions = {}
    
    for resource_id in r.resources:
        relevant_users = [u for u in r.users if u.get('resource') == resource_id or resource_id in u.get('resource', [])]

        names_final: str = ""
        names_final_akas: Set[str] = set()
        
        for user in relevant_users:

            # 'abuse' contacts are not considered primary owners.
            # This can reveal information about resource leasing.
            if user.get('relation') == 'abuse':
                continue

            user_akas = set(user.get('aka', [])).union(names_final_akas)

            if names_final:
                user_akas.add(user.get('name'))
            else:
                names_final = user.get('name','')

            names_final, names_final_akas = determine_best_primary_name(names_final, list(user_akas))
            
        resolutions[resource_id] = names_final, names_final_akas
    
    return resolutions


def show_final_name(r: WaiResponse) -> None:
    """
    Prints the final determined name(s) for resources.
    """
    logger.info("Attempting to show final names for target: %s", r.target)

    if not r.users:
        print(f"No user information found for target: {r.target}")
        return

    for resource_id in r.resources:
        relevant_users = [u for u in r.users if u.get('resource') == resource_id or resource_id in u.get('resource', [])]

        names_to_print: str = ""
        names_final: str = ""
        names_final_akas: Set[str] = set()
        
        for user in relevant_users:

            # 'abuse' contacts are not considered primary owners.
            # This can reveal information about resource leasing.
            if user.get('relation') == 'abuse':
                continue

            user_akas = set(user.get('aka', [])).union(names_final_akas)

            if names_final:
                user_akas.add(user.get('name'))
            else:
                names_final = user.get('name','')

            names_final, names_final_akas = determine_best_primary_name(names_final, list(user_akas))
            
        if names_final:
            names_to_print = names_final
        if names_final_akas: # Check if the set is not empty
            # Convert set to sorted list for consistent display
            akas_str = ", ".join(sorted(list(str(a) for a in names_final_akas)))
            names_to_print += f" (AKA: {akas_str})" if names_final else f"AKA: {akas_str}"

        if names_to_print:
            print(f"Resource: {resource_id} -> Name(s): {names_to_print}") # {'; '.join(names_to_print)}
        else:
            print(f"Resource: {resource_id} -> No primary name identified.")
