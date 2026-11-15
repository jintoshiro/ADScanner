"""
GroupCollector — thu thập toàn bộ group trong domain.

Chỉ lấy metadata + SID + memberOf. KHÔNG fetch `member` (danh sách thành viên)
để tránh query nặng trên domain lớn (BadBlood).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, asdict, field
from typing import Any

from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import ldap_scalar, ldap_list, ldap_int
from adscanner.utils.sid import (
    normalize_sid,
    get_domain_sid_from_sid,
    get_privileged_group_name,
    parse_group_type,
)

logger = logging.getLogger(__name__)


GROUP_ATTRIBUTES = [
    "sAMAccountName",
    "distinguishedName",
    "cn",
    "description",
    "objectSid",
    "groupType",
    "adminCount",
    "memberOf",
]


@dataclass
class ADGroup:
    """Đại diện chuẩn hóa cho một group."""
    sam: str
    dn: str
    cn: str
    description: str | None
    sid: str
    scope: str        # Global / Domain Local / Universal
    kind: str         # Security / Distribution
    is_security: bool
    admin_count: int
    is_admin_count_set: bool
    is_privileged: bool
    privileged_match: str | None      # "Domain Admins" nếu là nhóm đặc quyền
    member_of: list[str] = field(default_factory=list)  # nhóm cha (nested)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def collect_groups(connector: LDAPConnector) -> list[ADGroup]:
    """Thu thập tất cả group trong domain."""
    logger.info("[%s] Bắt đầu thu thập groups ...", connector.config.domain)

    ldap_filter = "(objectClass=group)"
    raw_groups = connector.search_subtree(ldap_filter, attributes=GROUP_ATTRIBUTES)

    # Cần domain SID để nhận diện nhóm đặc quyền domain-relative (Domain Admins, ...)
    domain_sid = _detect_domain_sid(raw_groups)
    logger.info("[%s] Domain SID: %s", connector.config.domain, domain_sid or "?")

    groups: list[ADGroup] = []
    for raw in raw_groups:
        try:
            group = _parse_group(raw, domain_sid)
            groups.append(group)
        except Exception as e:
            logger.warning(
                "[%s] Bỏ qua group lỗi parse: %s — %s",
                connector.config.domain,
                raw.get("sAMAccountName", "?"),
                e,
            )

    priv_count = sum(1 for g in groups if g.is_privileged)
    logger.info(
        "[%s] Đã thu thập %d group(s), trong đó %d nhóm đặc quyền.",
        connector.config.domain, len(groups), priv_count,
    )
    return groups


def _detect_domain_sid(raw_groups: list[dict[str, Any]]) -> str | None:
    """
    Dò domain SID từ SID của một group bất kỳ trong domain.
    Không cần query domain object — mọi SID domain đều có cùng prefix.
    """
    for raw in raw_groups:
        sid = normalize_sid(raw.get("objectSid"))
        domain_sid = get_domain_sid_from_sid(sid)
        if domain_sid:
            return domain_sid
    return None


def _parse_group(raw: dict[str, Any], domain_sid: str | None) -> ADGroup:
    """Chuyển một entry LDAP thô thành ADGroup chuẩn hóa."""
    sid = normalize_sid(raw.get("objectSid"))
    scope, kind = parse_group_type(raw.get("groupType"))
    privileged_match = get_privileged_group_name(sid, domain_sid)
    admin_count = ldap_int(raw.get("adminCount"))

    return ADGroup(
        sam=str(ldap_scalar(raw.get("sAMAccountName")) or ""),
        dn=str(ldap_scalar(raw.get("distinguishedName")) or ""),
        cn=str(ldap_scalar(raw.get("cn")) or ""),
        description=ldap_scalar(raw.get("description")),
        sid=sid,
        scope=scope,
        kind=kind,
        is_security=(kind == "Security"),
        admin_count=admin_count,
        is_admin_count_set=(admin_count == 1),
        is_privileged=privileged_match is not None,
        privileged_match=privileged_match,
        member_of=ldap_list(raw.get("memberOf")),
    )