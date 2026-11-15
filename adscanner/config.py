"""
Cấu hình cho ADScanner.

Thứ tự ưu tiên (thấp → cao):
  1. Giá trị mặc định trong code
  2. File profile YAML (profiles/<name>.yaml)
  3. Biến môi trường có tiền tố ADSCANNER_*
  4. Tham số CLI (do caller truyền vào)

Nhờ vậy, cùng một code chạy được trên lab, GOAD, BadBlood,...
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Thư mục gốc chứa profiles/
PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"


@dataclass
class DomainConfig:
    """Thông tin kết nối tới một domain."""
    domain: str
    domain_dn: str
    dc_ip: str
    username: str = ""
    password: str = ""
    ldap_port: int = 389
    ldaps_port: int = 636
    use_ldaps: bool = False
    use_ntlm: bool = True


@dataclass
class Profile:
    """Một profile môi trường (lab / goad / badblood / ...)."""
    name: str
    primary: DomainConfig
    extra_domains: list[DomainConfig] = field(default_factory=list)
    adcs_server_ip: str | None = None
    adcs_ca_name: str | None = None

    @property
    def all_domains(self) -> list[DomainConfig]:
        return [self.primary, *self.extra_domains]


# ============================================================
# Hằng số userAccountControl (dùng cho checks + utils)
# ============================================================
UAC = {
    "ACCOUNTDISABLE":          0x00000002,
    "PASSWD_NOTREQD":          0x00000020,
    "PASSWD_CANT_CHANGE":      0x00000040,
    "NORMAL_ACCOUNT":          0x00000200,
    "DONT_EXPIRE_PASSWD":      0x00010000,
    "SMARTCARD_REQUIRED":      0x00040000,
    "TRUSTED_FOR_DELEGATION":  0x00080000,
    "NOT_DELEGATED":           0x00100000,
    "USE_DES_KEY_ONLY":        0x00200000,
    "DONT_REQ_PREAUTH":        0x00400000,
    "PASSWORD_EXPIRED":        0x00800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000,
}


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Ghi đè các field bằng biến môi trường ADSCANNER_*."""
    mapping = {
        "ADSCANNER_DOMAIN": "domain",
        "ADSCANNER_DOMAIN_DN": "domain_dn",
        "ADSCANNER_DC_IP": "dc_ip",
        "ADSCANNER_USERNAME": "username",
        "ADSCANNER_PASSWORD": "password",
        "ADSCANNER_USE_LDAPS": "use_ldaps",
        "ADSCANNER_USE_NTLM": "use_ntlm",
        "ADSCANNER_ADCS_SERVER_IP": "adcs_server_ip",
        "ADSCANNER_ADCS_CA_NAME": "adcs_ca_name",
    }
    for env_key, field_name in mapping.items():
        if env_key in os.environ:
            raw = os.environ[env_key]
            if field_name in ("use_ldaps", "use_ntlm"):
                data[field_name] = raw.lower() in ("1", "true", "yes")
            else:
                data[field_name] = raw
    return data


def _build_domain_config(d: dict[str, Any]) -> DomainConfig:
    """Tạo DomainConfig từ dict, có default cho các field tùy chọn."""
    return DomainConfig(
        domain=d["domain"],
        domain_dn=d["domain_dn"],
        dc_ip=d["dc_ip"],
        username=d.get("username", ""),
        password=d.get("password", ""),
        ldap_port=int(d.get("ldap_port", 389)),
        ldaps_port=int(d.get("ldaps_port", 636)),
        use_ldaps=bool(d.get("use_ldaps", False)),
        use_ntlm=bool(d.get("use_ntlm", True)),
    )


def load_profile(name: str = "lab", profiles_dir: Path | None = None) -> Profile:
    """Đọc profile YAML và áp env override."""
    pdir = profiles_dir or PROFILES_DIR
    path = pdir / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy profile: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Env override chỉ áp dụng cho domain chính (primary)
    primary_data = _apply_env_overrides(dict(data))

    primary = _build_domain_config(primary_data)
    extras = [_build_domain_config(d) for d in data.get("extra_domains", [])]

    return Profile(
        name=data.get("name", name),
        primary=primary,
        extra_domains=extras,
        adcs_server_ip=data.get("adcs_server_ip"),
        adcs_ca_name=data.get("adcs_ca_name"),
    )
