"""
ACLCollector — Thu thập Security Descriptor của các object quan trọng.
Tối ưu: Dùng paged search duy nhất thay vì N+1 query.
"""
import logging
from dataclasses import dataclass, field
from typing import Any

from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils.security_descriptor import (
    extract_aces,
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


def collect_all_acls(connector: LDAPConnector) -> tuple[dict[str, ObjectACL], bool]:
    """
    Thu thập ACL của Domain, Users, Groups, OUs, GPOs.
    Trả về tuple: (dict ACLs, success_bool).
    Nếu success=False, các check ACL sẽ trả NOT_ASSESSED.
    """
    logger.info("[%s] Thu thập ACL (paged search) ...", connector.config.domain)
    acls: dict[str, ObjectACL] = {}

    try:
        # 1. Domain object (riêng)
        domain_entries = connector.search(
            search_filter="(objectClass=domainDNS)",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            search_base=connector.base_dn,
            search_scope="BASE",
            sd_flags=SD_FLAGS_DACL_ONLY,
            paged=False,
        )
        for e in domain_entries:
            dn = e.get("distinguishedName")
            if isinstance(dn, list): dn = dn[0]
            raw_sd = e.get("nTSecurityDescriptor")
            if dn and raw_sd:
                acls[str(dn)] = ObjectACL(
                    target_dn=str(dn),
                    target_label="domain",
                    owner_sid=get_sd_owner(raw_sd),
                    aces=extract_aces(raw_sd),
                )

        # 2. Users, Groups, OUs, GPOs — dùng paged search
        base_gpo = f"CN=Policies,CN=System,{connector.base_dn}"
        
        # 2a. Users (kể cả disabled)
        user_entries = connector.search(
            search_filter="(&(objectClass=user)(objectCategory=person))",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            sd_flags=SD_FLAGS_DACL_ONLY,
            paged=True,
        )
        for e in user_entries:
            dn = e.get("distinguishedName")
            if isinstance(dn, list): dn = dn[0]
            raw_sd = e.get("nTSecurityDescriptor")
            if dn and raw_sd:
                acls[str(dn)] = ObjectACL(
                    target_dn=str(dn), target_label="user",
                    owner_sid=get_sd_owner(raw_sd),
                    aces=extract_aces(raw_sd),
                )

        # 2b. Groups
        group_entries = connector.search(
            search_filter="(objectClass=group)",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            sd_flags=SD_FLAGS_DACL_ONLY,
            paged=True,
        )
        for e in group_entries:
            dn = e.get("distinguishedName")
            if isinstance(dn, list): dn = dn[0]
            raw_sd = e.get("nTSecurityDescriptor")
            if dn and raw_sd:
                acls[str(dn)] = ObjectACL(
                    target_dn=str(dn), target_label="group",
                    owner_sid=get_sd_owner(raw_sd),
                    aces=extract_aces(raw_sd),
                )

        # 2c. OUs
        ou_entries = connector.search(
            search_filter="(objectClass=organizationalUnit)",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            sd_flags=SD_FLAGS_DACL_ONLY,
            paged=True,
        )
        for e in ou_entries:
            dn = e.get("distinguishedName")
            if isinstance(dn, list): dn = dn[0]
            raw_sd = e.get("nTSecurityDescriptor")
            if dn and raw_sd:
                acls[str(dn)] = ObjectACL(
                    target_dn=str(dn), target_label="ou",
                    owner_sid=get_sd_owner(raw_sd),
                    aces=extract_aces(raw_sd),
                )

        # 2d. GPOs
        gpo_entries = connector.search(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            search_base=base_gpo,
            sd_flags=SD_FLAGS_DACL_ONLY,
            paged=True,
        )
        for e in gpo_entries:
            dn = e.get("distinguishedName")
            if isinstance(dn, list): dn = dn[0]
            raw_sd = e.get("nTSecurityDescriptor")
            if dn and raw_sd:
                acls[str(dn)] = ObjectACL(
                    target_dn=str(dn), target_label="gpo",
                    owner_sid=get_sd_owner(raw_sd),
                    aces=extract_aces(raw_sd),
                )

        logger.info("[%s] Đã thu thập ACL của %d object.", connector.config.domain, len(acls))
        return acls, True

    except Exception as e:
        logger.error("[%s] Lỗi thu thập ACL: %s", connector.config.domain, e)
        return acls, False