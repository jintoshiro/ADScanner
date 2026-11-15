"""Tiện ích dùng chung cho ADScanner."""
from adscanner.utils.uac import (
    parse_uac,
    describe_uac,
    is_disabled,
    is_dont_expire_password,
    is_password_not_required,
    is_asrep_roastable,
    is_trusted_for_delegation,
    is_sensitive_and_not_delegated,
    is_trusted_to_auth_for_delegation,
    is_smartcard_required,
    ldap_scalar,
    ldap_list,
    ldap_int,
    filetime_to_datetime,
    filetime_age_days,
    format_filetime,
)
from adscanner.utils.sid import (
    normalize_sid,
    get_domain_sid_from_sid,
    get_rid,
    get_privileged_group_name,
    parse_group_type,
)
from adscanner.utils.security_descriptor import (
    extract_aces,
    find_aces_for_guid,
    find_dcsync_aces,
    find_dcsync_trustees,
    default_legit_sids,
    get_sd_owner,
    GUID_DS_REPLICATION_GET_CHANGES_ALL,
    GUID_DS_REPLICATION_GET_CHANGES,
)

__all__ = [
    "parse_uac", "describe_uac",
    "is_disabled", "is_dont_expire_password", "is_password_not_required",
    "is_asrep_roastable", "is_trusted_for_delegation",
    "is_sensitive_and_not_delegated", "is_trusted_to_auth_for_delegation",
    "is_smartcard_required",
    "ldap_scalar", "ldap_list", "ldap_int",
    "filetime_to_datetime", "filetime_age_days", "format_filetime",
    "normalize_sid", "get_domain_sid_from_sid", "get_rid",
    "get_privileged_group_name", "parse_group_type",
    "extract_aces", "find_aces_for_guid", "find_dcsync_aces",
    "find_dcsync_trustees", "default_legit_sids", "get_sd_owner",
    "GUID_DS_REPLICATION_GET_CHANGES_ALL", "GUID_DS_REPLICATION_GET_CHANGES",
]