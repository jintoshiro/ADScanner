"""Thu thập chính sách mật khẩu domain và PSO."""
import logging
from dataclasses import dataclass, asdict, field
from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import ldap_scalar, ldap_int
from adscanner.utils.time_utils import interval_to_days

logger = logging.getLogger(__name__)

@dataclass
class DomainConfig:
    min_pwd_length: int = 0
    pwd_properties: int = 0
    pwd_history_length: int = 0
    lockout_threshold: int = 0
    max_pwd_age_days: float | None = None
    machine_account_quota: int = 0
    ds_heuristics: str = ""
    psos: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

def collect_domain_config(connector: LDAPConnector) -> DomainConfig:
    logger.info("[%s] Thu thập Domain Config ...", connector.config.domain)
    config = DomainConfig()
    
    # 1. Domain object
    entries = connector.search(
        "(objectClass=domainDNS)",
        attributes=["minPwdLength", "pwdProperties", "pwdHistoryLength",
                    "lockoutThreshold", "maxPwdAge", "ms-DS-MachineAccountQuota"],
        search_base=connector.base_dn, search_scope="BASE"
    )
    if entries:
        e = entries[0]
        config.min_pwd_length = ldap_int(e.get("minPwdLength"))
        config.pwd_properties = ldap_int(e.get("pwdProperties"))
        config.pwd_history_length = ldap_int(e.get("pwdHistoryLength"))
        config.lockout_threshold = ldap_int(e.get("lockoutThreshold"))
        config.machine_account_quota = ldap_int(e.get("ms-DS-MachineAccountQuota"))
        
        # Xử lý maxPwdAge
        raw_max = e.get("maxPwdAge")
        if isinstance(raw_max, list): raw_max = raw_max[0] if raw_max else None
        config.max_pwd_age_days = interval_to_days(raw_max)

    # 2. dsHeuristics
    try:
        root_dse = connector.get_root_dse()
        config_nc = root_dse.get("configurationNamingContext")
        if isinstance(config_nc, list): config_nc = config_nc[0]
        ds_base = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_nc}"
        
        ds_entries = connector.search(
            "(objectClass=nTDSService)", attributes=["dsHeuristics"],
            search_base=ds_base, search_scope="BASE"
        )
        if ds_entries:
            val = ds_entries[0].get("dsHeuristics")
            if isinstance(val, list): val = val[0] if val else ""
            config.ds_heuristics = str(val or "")
    except Exception as ex:
        logger.warning("Không đọc được dsHeuristics: %s", ex)

    # 3. PSO
    try:
        pso_base = f"CN=Password Settings Container,CN=System,{connector.base_dn}"
        pso_entries = connector.search(
            "(objectClass=msDS-PasswordSettings)",
            attributes=["cn", "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled",
                        "msDS-LockoutThreshold", "msDS-PasswordSettingsPrecedence",
                        "msDS-PSOAppliesTo"],
            search_base=pso_base
        )
        for p in pso_entries:
            applies = p.get("msDS-PSOAppliesTo", [])
            if isinstance(applies, str): applies = [applies]
            config.psos.append({
                "name": ldap_scalar(p.get("cn")),
                "min_length": ldap_int(p.get("msDS-MinimumPasswordLength")),
                "complexity": bool(ldap_int(p.get("msDS-PasswordComplexityEnabled"))),
                "lockout_threshold": ldap_int(p.get("msDS-LockoutThreshold")),
                "precedence": ldap_int(p.get("msDS-PasswordSettingsPrecedence")),
                "applies_to": applies,
            })
    except Exception as ex:
        logger.warning("Không đọc được PSO: %s", ex)
        # Đánh dấu là không đọc được
        config.psos = None

    return config