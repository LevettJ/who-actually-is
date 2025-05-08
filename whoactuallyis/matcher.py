from typing import Any, Dict, List, Optional, Set, Tuple
from thefuzz import fuzz
import re

# Heuristic Values

# For name_matcher
NAME_MIN_LEN_FOR_HIGH_FULL_RATIO: int = 6  # Corresponds to > 5 in original
NAME_FULL_RATIO_THRESHOLD_STRICT: int = 80
NAME_FULL_RATIO_THRESHOLD_LOOSE: int = 40
NAME_PARTIAL_RATIO_THRESHOLD: int = 80

# For address_matcher
ADDRESS_FULL_RATIO_THRESHOLD_STRICT: int = 70
ADDRESS_FULL_RATIO_THRESHOLD_LOOSE: int = 30
ADDRESS_PARTIAL_RATIO_THRESHOLD: int = 70

# Example legal suffixes for companies (English-centric)
# Suggest using Global Legal Entity Identifier Foundation (GLEIF) 'Entity Legal Forms (ELF) Code List'
LEGAL_SUFFIXES: Set[str] = {
    # English
    "LTD", "LTD.", "LIMITED", "PLC", "PLC.", "CORP", "CORP.", "CORPORATION",
    "INC", "INC.", "INCORPORATED", "LLC", "L.L.C.", "LLP", "L.L.P.",
    "LP", "L.P.", "GP", "G.P.", "COMPANY", "CO.", "CO",
    "PARTNERSHIP", "ASSOCIATES", "GROUP", "HOLDINGS", "VENTURES",
    "FOUNDATION", "TRUST", "INSTITUTE", "UNIVERSITY", "COLLEGE",
}

# Generic terms that might be less representative
GENERIC_TERMS_PENALTY: Set[str] = {
    "COMPANY", "BUSINESS", "ENTERPRISE", "SERVICE", "SERVICES", "SOLUTIONS",
    "GROUP", "HOLDING", "CONSULTING", "AGENCY", "TRADING", "INTERNATIONAL"
}

SCORE_HAS_LEGAL_SUFFIX: int = 50
SCORE_IS_ORIGINAL_NAME: int = 20 # Bonus if the name was the initial 'name'
SCORE_TITLE_CASE: int = 10
SCORE_ALL_CAPS_ACRONYM: int = 15 # For short, all-caps names (potential acronyms)
SCORE_ALL_CAPS_LONG_PENALTY: int = -10 # Penalty for long all-caps names
SCORE_ALL_LOWER_PENALTY: int = -20
SCORE_SYMBOLS_PENALTY: int = -10
SCORE_VERY_SHORT_PENALTY: int = -30 # Penalty for names like "A" or "Co" if not suffix
SCORE_GENERIC_TERM_PENALTY_VALUE: int = -25
SCORE_PER_CHAR_LENGTH: float = 0.5 # Small bonus per character

def name_matcher(name1: Optional[str], name2: Optional[str]) -> bool:
    """
    Compares two names using fuzzy matching.

    Args:
        name1: The first name string.
        name2: The second name string.

    Returns:
        True if the names are considered a match based on defined thresholds, False otherwise.
    """
    if name1 is None or name2 is None:
        return False

    n1_lower: str = name1.lower()
    n2_lower: str = name2.lower()

    full_ratio: int = fuzz.ratio(n1_lower, n2_lower)
    partial_ratio: int = fuzz.partial_ratio(n1_lower, n2_lower)

    # Strict match: high full ratio, and names are reasonably long
    if full_ratio > NAME_FULL_RATIO_THRESHOLD_STRICT and \
       (len(n1_lower) >= NAME_MIN_LEN_FOR_HIGH_FULL_RATIO and \
        len(n2_lower) >= NAME_MIN_LEN_FOR_HIGH_FULL_RATIO):
        return True
    
    # Looser match: moderate full ratio but high partial ratio
    if full_ratio > NAME_FULL_RATIO_THRESHOLD_LOOSE and \
       partial_ratio > NAME_PARTIAL_RATIO_THRESHOLD:
        return True
        
    return False


def address_matcher(address1: Optional[str], address2: Optional[str]) -> bool:
    """
    Compares two addresses using fuzzy matching.

    Args:
        address1: The first address string.
        address2: The second address string.

    Returns:
        True if the addresses are considered a match based on defined thresholds, False otherwise.
    """
    if address1 is None or address2 is None:
        return False

    addr1_lower: str = address1.lower()
    addr2_lower: str = address2.lower()
    
    full_ratio: int = fuzz.ratio(addr1_lower, addr2_lower)
    partial_ratio: int = fuzz.partial_ratio(addr1_lower, addr2_lower)

    # Strict match: high full ratio
    if full_ratio > ADDRESS_FULL_RATIO_THRESHOLD_STRICT:
        return True
    
    # Looser match: moderate full ratio but high partial ratio
    if full_ratio > ADDRESS_FULL_RATIO_THRESHOLD_LOOSE and \
       partial_ratio > ADDRESS_PARTIAL_RATIO_THRESHOLD:
        return True
        
    return False


def tel_matcher(tel1: Optional[str], tel2: Optional[str]) -> bool:
    """
    Compares two telephone numbers for equality.

    Args:
        tel1: The first telephone number string.
        tel2: The second telephone number string.

    Returns:
        True if the telephone numbers are identical (and not None), False otherwise.
    """
    if tel1 is None or tel2 is None:
        return False
    return tel1 == tel2


def email_matcher(email1: Optional[str], email2: Optional[str]) -> bool:
    """
    Compares two email addresses.

    Args:
        email1: The first email address string.
        email2: The second email address string.

    Returns:
        True if the emails are considered a match, False otherwise.
    """
    if email1 is None or email2 is None:
        return False

    e1_lower: str = email1.lower()
    e2_lower: str = email2.lower()

    if '@' not in e1_lower or '@' not in e2_lower:
        # Handles cases where malformed "emails" might be present.
        return False 
    
    # Exact match (case-insensitive)
    if e1_lower == e2_lower:
        return True
    
    # Domain match
    # This is a broad match; use with caution or refine if subdomains are important.
    try:
        domain1: str = e1_lower.split('@')[1]
        domain2: str = e2_lower.split('@')[1]
        if domain1 == domain2 and domain1 != "": # Ensure domains are not empty
            return True
    except IndexError:
        # Should not happen if '@' check passed and split correctly, but defensive.
        return False
        
    return False


def match_entities(r) -> None:
    """
    Matches entities within the WaiResponse object's user list.
    The process iterates twice to help propagate matches through chains (A-B, B-C => A-C).

    Args:
        r: The WaiResponse object containing the list of users to process.
    """
    if not r or not r.users:
        return

    # Ensure 'aka' is a set for all users before starting.
    # _process_entities in the main module should initialize 'aka' as a set.
    for user_data in r.users:
        if not isinstance(user_data.get('aka'), set):
            user_data['aka'] = set(user_data.get('aka', []))

    # Iterate twice to allow for transitive matching (A-B and B-C implies A-C)
    for _ in range(2): # Original code iterated twice
        for user_A_data in r.users:
            for user_B_data in r.users:
                if user_A_data is user_B_data:  # Skip self-comparison using object identity
                    continue

                # Extract relevant fields for matching
                user_A_name: Optional[str] = user_A_data.get('name')
                user_B_name: Optional[str] = user_B_data.get('name')
                user_A_address: Optional[str] = user_A_data.get('address')
                user_B_address: Optional[str] = user_B_data.get('address')
                user_A_tel: Optional[str] = user_A_data.get('tel')
                user_B_tel: Optional[str] = user_B_data.get('tel')
                user_A_email: Optional[str] = user_A_data.get('email')
                user_B_email: Optional[str] = user_B_data.get('email')

                # Check if any of the matching criteria are met
                is_match: bool = False
                if name_matcher(user_A_name, user_B_name):
                    is_match = True
                elif address_matcher(user_A_address, user_B_address):
                    is_match = True
                elif tel_matcher(user_A_tel, user_B_tel):
                    is_match = True
                elif email_matcher(user_A_email, user_B_email):
                    is_match = True
                
                if is_match:
                    # If a match is found, update their 'aka' sets.
                    # 'aka' is guaranteed to be a set here due to the initial loop.
                    user_A_aka_set: Set[str] = user_A_data['aka']
                    user_B_aka_set: Set[str] = user_B_data['aka']

                    # If names are different and valid, add B's name to A's akas,
                    # and A's name to B's akas.
                    # This step is crucial for cross-referencing primary names.
                    if user_A_name and user_B_name and user_A_name != user_B_name:
                        user_A_aka_set.add(user_B_name)
                        user_B_aka_set.add(user_A_name)
                    
                    # Merge AKA sets: user_A gets all of user_B's AKAs
                    # Then user_B gets all of user_A's (now updated) AKAs.
                    # This sequence ensures propagation.
                    
                    # Create a temporary union to avoid modifying a set while iterating over related data
                    # or to handle cases where user_A_aka_set and user_B_aka_set might be the same object
                    # (though unlikely with distinct user_data dicts).
                    
                    # Step 1: user_A's akas become the union of its current akas and user_B's akas.
                    combined_for_A = user_A_aka_set.union(user_B_aka_set)
                    
                    # Step 2: user_B's akas become the union of its current akas and user_A's (now updated) akas.
                    combined_for_B = user_B_aka_set.union(combined_for_A) 
                                        # Using combined_for_A here ensures propagation from A to B

                    user_A_data['aka'] = combined_for_A
                    user_B_data['aka'] = combined_for_B


    # Convert sets to sorted lists for consistent output.
    for user_data in r.users:
        if isinstance(user_data.get('aka'), set):
            user_data['aka'] = sorted(list(user_data['aka']))
        elif user_data.get('aka') is None: # Ensure 'aka' key exists as an empty list if it was None
             user_data['aka'] = []

def score_name(name: str, is_original_name: bool) -> float:
    """
    Calculates a score for a given company name.

    Args:
        name: The name.
        is_original_name: Boolean, True if this name was the original primary name.

    Returns:
        A float representing the score of the name. Higher is better.
    """
    score: float = 0.0
    name_upper: str = name.upper() # For case-insensitive checks of suffixes/terms
    name_len: int = len(name)

    # 1. Length bonus
    score += name_len * SCORE_PER_CHAR_LENGTH

    # 2. Legal Suffix Bonus
    # Check if the name ends with a legal suffix
    for suffix in LEGAL_SUFFIXES:
        if name_upper.endswith(f" {suffix}") or name_upper == suffix:
            score += SCORE_HAS_LEGAL_SUFFIX
            if name_upper == suffix and name_len > 3:
                 score -= 10 # Penalty if name is only a suffix
            break # Only apply bonus once

    # 3. Original Name Bonus
    if is_original_name:
        score += SCORE_IS_ORIGINAL_NAME

    # 4. Capitalisation Score
    if name.istitle() and name_len > 1:
        score += SCORE_TITLE_CASE
    elif name.isupper():
        if 2 <= name_len <= 5: # Acronyms
            score += SCORE_ALL_CAPS_ACRONYM
        elif name_len > 5 : # Longer all-caps names are less preferable
            score += SCORE_ALL_CAPS_LONG_PENALTY
    
    if name.islower(): # Company name is unlikely to be fully lowercase
        score += SCORE_ALL_LOWER_PENALTY

    # 5. Penalty for very short names
    if name_len < 3 and not (name.isupper() and 2 <= name_len <= 5):
        is_suffix_only = any(name_upper == s for s in LEGAL_SUFFIXES)
        if not is_suffix_only:
            score += SCORE_VERY_SHORT_PENALTY
    
    # 6. Penalty for generic terms in shorter names
    if name_upper in GENERIC_TERMS_PENALTY and name_len < 15:
        score += SCORE_GENERIC_TERM_PENALTY_VALUE
    
    name_parts = set(re.split(r'[\s,.-]+', name_upper))
    generic_parts_found = name_parts.intersection(GENERIC_TERMS_PENALTY)
    non_suffix_parts = [p for p in name_parts if p not in LEGAL_SUFFIXES]
    if non_suffix_parts and len(generic_parts_found) >= len(non_suffix_parts) * 0.6:
        if len(non_suffix_parts) < 3:
             score += SCORE_GENERIC_TERM_PENALTY_VALUE / 2

    # 7. Penalty for use of hypens
    for symbol in ['-', '#']:
        score += name.count(symbol) * SCORE_SYMBOLS_PENALTY

    return score


def determine_best_primary_name(
    original_name: Optional[str],
    aka_list: List[Optional[str]]
) -> Tuple[Optional[str], List[str]]:
    """
    Determines the most representative primary name.

    Args:
        original_name: The current primary name.
        aka_list: A list of alternative names.

    Returns:
        A tuple containing:
            The chosen best primary name (str).
            An updated list of AKAs (List[str]), containing all other names.
    """
    candidate_names: Set[str] = set()

    # 1. Collect and clean all candidate names
    if original_name and original_name.strip():
        candidate_names.add(original_name.strip())
    
    for aka_name in aka_list:
        if aka_name and aka_name.strip():
            candidate_names.add(aka_name.strip())

    if not candidate_names:
        return None, []

    # 2. Score each candidate name
    scored_names: List[Tuple[float, str]] = [] # List of (score, name)
    for name_candidate in candidate_names:
        is_orig = (name_candidate == original_name.strip()) if original_name else False
        current_score = score_name(name_candidate, is_orig)
        scored_names.append((current_score, name_candidate))

    # 3. Select the best name
    def sort_key(item: Tuple[float, str]) -> Tuple[float, bool, int, str]:
        score_val, name_val = item
        is_orig_val = (name_val == original_name.strip()) if original_name else False
        return (score_val, is_orig_val, len(name_val), name_val)

    scored_names.sort(key=sort_key, reverse=True)

    best_primary_name: Optional[str] = scored_names[0][1] if scored_names else None
    
    # 4. Prepare the new list of AKAs
    new_aka_list: List[str] = []
    if best_primary_name:
        new_aka_list = sorted([name for name in candidate_names if name != best_primary_name])
    else: # Should not happen if candidate_names was not empty, but defensive
        new_aka_list = sorted(list(candidate_names))

    return best_primary_name, new_aka_list