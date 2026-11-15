"""
UserCollector — thu thập toàn bộ user trong một domain.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any

from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import (
    parse_uac,
    ldap_scalar,
    ldap_list,
    ldap_int,
    filetime_to_datetime,
    is_dont_expire_password,
    is_password_not_required,
    is_asrep_roastable,
    is_disabled,
)

logger = logging.getLogger(__name__)

# Đã thêm "whenCreated" để fallback cho check A7
USER_ATTRIBUTES = [
    "sAMAccountName",
    "distinguishedName",
    "cn",
    "displayName",
    "description",
    "userPrincipalName",
    "userAccountControl",
    "adminCount",
    "servicePrincipalName",
    "pwdLastSet",
    "lastLogonTimestamp",
    "memberOf",
    "primaryGroupID",
    "objectSid",
    "sIDHistory",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "whenCreated", # <-- THÊM MỚI
]


@dataclass
class ADUser:
    """Đại diện chuẩn hóa cho một user."""
    # Định danh
    sam: str
    dn: str
    cn: str
    display_name: str | None
    description: str | None
    upn: str | None

    # UAC
    uac_raw: int
    uac_flags: dict[str, bool] = field(default_factory=dict)

    # Đặc quyền
    admin_count: int = 0
    is_admin_count_set: bool = False

    # Kerberos
    spn: list[str] = field(default_factory=list)
    is_kerberoastable: bool = False
    is_asrep_roastable: bool = False

    # Password policy
    pwd_last_set: str | None = None
    pwd_age_days: int | None = None
    dont_expire_password: bool = False
    password_not_required: bool = False

    # Trạng thái
    disabled: bool = False
    last_logon: str | None = None
    last_logon_age_days: int | None = None
    when_created: str | None = None # <-- THÊM MỚI

    # Nhóm & SID
    member_of: list[str] = field(default_factory=list)
    primary_group_id: int = 0
    sid: str = ""
    sid_history: list[str] = field(default_factory=list)

    # Delegation
    allowed_to_delegate_to: list[str] = field(default_factory=list)
    allowed_to_act_on_behalf_of: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def collect_users(connector: LDAPConnector) -> list[ADUser]:
    logger.info("[%s] Bắt đầu thu thập users ...", connector.config.domain)

    ldap_filter = "(&(objectClass=user)(objectCategory=person))"
    raw_users = connector.search_subtree(ldap_filter, attributes=USER_ATTRIBUTES)

    users: list[ADUser] = []
    for raw in raw_users:
        try:
            user = _parse_user(raw)
            users.append(user)
        except Exception as e:
            logger.warning(
                "[%s] Bỏ qua user lỗi parse: %s — %s",
                connector.config.domain,
                raw.get("sAMAccountName", "?"),
                e,
            )

    logger.info("[%s] Đã thu thập %d user(s).", connector.config.domain, len(users))
    return users


def _parse_user(raw: dict[str, Any]) -> ADUser:
    uac_raw = ldap_int(raw.get("userAccountControl"))
    spn = ldap_list(raw.get("servicePrincipalName"))
    admin_count = ldap_int(raw.get("adminCount"))

    pwd_dt = filetime_to_datetime(raw.get("pwdLastSet"))
    last_logon_dt = filetime_to_datetime(raw.get("lastLogonTimestamp"))
    now = datetime.now(timezone.utc)

    rbcd = ldap_scalar(raw.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))

    return ADUser(
        sam=str(ldap_scalar(raw.get("sAMAccountName")) or ""),
        dn=str(ldap_scalar(raw.get("distinguishedName")) or ""),
        cn=str(ldap_scalar(raw.get("cn")) or ""),
        display_name=ldap_scalar(raw.get("displayName")),
        description=ldap_scalar(raw.get("description")),
        upn=ldap_scalar(raw.get("userPrincipalName")),

        uac_raw=uac_raw,
        uac_flags=parse_uac(uac_raw),

        admin_count=admin_count,
        is_admin_count_set=(admin_count == 1),

        spn=spn,
        is_kerberoastable=bool(spn) and not is_disabled(uac_raw),
        is_asrep_roastable=is_asrep_roastable(uac_raw) and not is_disabled(uac_raw),

        pwd_last_set=pwd_dt.isoformat() if pwd_dt else None,
        pwd_age_days=(now - pwd_dt).days if pwd_dt else None,
        dont_expire_password=is_dont_expire_password(uac_raw),
        password_not_required=is_password_not_required(uac_raw),

        disabled=is_disabled(uac_raw),
        last_logon=last_logon_dt.isoformat() if last_logon_dt else None,
        last_logon_age_days=(now - last_logon_dt).days if last_logon_dt else None,
        
        # Lấy giá trị whenCreated (định dạng YYYYMMDDHHMMSS.0Z)
        when_created=ldap_scalar(raw.get("whenCreated")), # <-- THÊM MỚI

        member_of=ldap_list(raw.get("memberOf")),
        primary_group_id=ldap_int(raw.get("primaryGroupID")),
        sid=str(ldap_scalar(raw.get("objectSid")) or ""),
        sid_history=ldap_list(raw.get("sIDHistory")),

        allowed_to_delegate_to=ldap_list(raw.get("msDS-AllowedToDelegateTo")),
        allowed_to_act_on_behalf_of=str(rbcd) if rbcd else None,
    )