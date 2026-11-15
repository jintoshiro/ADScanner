"""
ACLCollector — thu thập Security Descriptor của các object quan trọng.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils.security_descriptor import (
    extract_aces,
    find_dcsync_trustees,
    get_sd_owner,
)

logger = logging.getLogger(__name__)

SD_FLAGS_DACL_ONLY = 0x04


@dataclass
class ObjectACL:
    target_dn: str
    target_label: str
    owner_sid: str | None
    aces: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_dn": self.target_dn,
            "target_label": self.target_label,
            "owner_sid": self.owner_sid,
            "aces_count": len(self.aces),
        }


def _collect_object_acl(
    connector: LDAPConnector, 
    ldap_filter: str, 
    search_base: str, 
    label: str, 
    attributes: list[str]
) -> ObjectACL | None:
    try:
        entries = connector.search(
            search_filter=ldap_filter,
            attributes=attributes,
            search_base=search_base,
            search_scope="BASE",
            sd_flags=SD_FLAGS_DACL_ONLY,
            paged=False,
        )
    except Exception as e:
        return None

    if not entries:
        return None

    entry = entries[0]
    raw_sd = entry.get("nTSecurityDescriptor")
    if not raw_sd:
        return None

    aces = extract_aces(raw_sd)
    owner = get_sd_owner(raw_sd)
    
    dn = entry.get("distinguishedName", search_base)
    if isinstance(dn, list): 
        dn = dn[0]

    return ObjectACL(target_dn=str(dn), target_label=label, owner_sid=owner, aces=aces)


def collect_domain_acl(connector: LDAPConnector) -> ObjectACL | None:
    return _collect_object_acl(
        connector, 
        "(objectClass=domainDNS)", 
        connector.base_dn, 
        "domain", 
        ["nTSecurityDescriptor", "distinguishedName"]
    )

def collect_rbcd_objects(connector: LDAPConnector) -> list[dict]:
    """Tìm các object (đặc biệt là Computer) có cấu hình RBCD."""
    logger.info("[%s] Thu thập dữ liệu RBCD ...", connector.config.domain)
    # Lọc các object có thuộc tính msDS-AllowedToActOnBehalfOfOtherIdentity
    ldap_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    entries = connector.search(
        ldap_filter,
        attributes=["sAMAccountName", "distinguishedName", "primaryGroupID", 
                    "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass"]
    )
    
    results = []
    for e in entries:
        sam = e.get("sAMAccountName", "")
        if isinstance(sam, list): sam = sam[0]
        dn = e.get("distinguishedName", "")
        if isinstance(dn, list): dn = dn[0]
        
        raw_sd = e.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not raw_sd: continue
        if isinstance(raw_sd, list): raw_sd = raw_sd[0]

        # Xác định xem đây có phải Domain Controller không
        pgid = e.get("primaryGroupID", 0)
        if isinstance(pgid, list): pgid = pgid[0] if pgid else 0
        is_dc = int(pgid) == 516

        results.append({
            "sam": sam,
            "dn": dn,
            "is_dc": is_dc,
            "rbcd_raw": raw_sd
        })
    
    logger.info("[%s] Đã tìm thấy %d object có cấu hình RBCD.", connector.config.domain, len(results))
    return results

def collect_all_acls(connector: LDAPConnector) -> dict[str, ObjectACL]:
    logger.info("[%s] Thu thập ACL của Domain, Users, Groups, OUs, GPOs ...", connector.config.domain)
    acls = {}

    # 1. Domain
    domain_acl = collect_domain_acl(connector)
    if domain_acl: acls[domain_acl.target_dn] = domain_acl

    # 2. Users
    raw_users = connector.search("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", attributes=["distinguishedName"])
    for u in raw_users:
        dn = u.get("distinguishedName")
        if isinstance(dn, list): dn = dn[0]
        if not dn: continue
        acl = _collect_object_acl(connector, "(objectClass=user)", dn, "user", ["nTSecurityDescriptor", "distinguishedName"])
        if acl: acls[acl.target_dn] = acl

    # 3. Groups
    raw_groups = connector.search("(objectClass=group)", attributes=["distinguishedName"])
    for g in raw_groups:
        dn = g.get("distinguishedName")
        if isinstance(dn, list): dn = dn[0]
        if not dn: continue
        acl = _collect_object_acl(connector, "(objectClass=group)", dn, "group", ["nTSecurityDescriptor", "distinguishedName"])
        if acl: acls[acl.target_dn] = acl

    # 4. OUs
    raw_ous = connector.search("(objectClass=organizationalUnit)", attributes=["distinguishedName"])
    for ou in raw_ous:
        dn = ou.get("distinguishedName")
        if isinstance(dn, list): dn = dn[0]
        if not dn: continue
        acl = _collect_object_acl(connector, "(objectClass=organizationalUnit)", dn, "ou", ["nTSecurityDescriptor", "distinguishedName"])
        if acl: acls[acl.target_dn] = acl

    # 5. GPOs
    gpo_base = f"CN=Policies,CN=System,{connector.base_dn}"
    raw_gpos = connector.search("(objectClass=groupPolicyContainer)", attributes=["distinguishedName", "displayName"], search_base=gpo_base)
    for gpo in raw_gpos:
        dn = gpo.get("distinguishedName")
        if isinstance(dn, list): dn = dn[0]
        if not dn: continue
        acl = _collect_object_acl(connector, "(objectClass=groupPolicyContainer)", dn, "gpo", ["nTSecurityDescriptor", "distinguishedName"])
        if acl: acls[acl.target_dn] = acl

    logger.info("[%s] Đã thu thập ACL của %d object.", connector.config.domain, len(acls))
    return acls