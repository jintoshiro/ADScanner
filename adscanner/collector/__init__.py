"""Module thu thập dữ liệu từ Active Directory."""
from adscanner.collector.ldap_connector import (
    LDAPConnector,
    LDAPConnectorError,
)
from adscanner.collector.user_collector import ADUser, collect_users
from adscanner.collector.group_collector import ADGroup, collect_groups

# Import hàm ACL mới (đã gộp)
from adscanner.collector.acl_collector import (
    ObjectACL,
    collect_all_acls,

)

from adscanner.collector.trust_collector import collect_trusts
from adscanner.collector.computer_collector import ADComputer, collect_computers
from adscanner.collector.adcs_collector import collect_adcs_templates
from adscanner.collector.gpo_collector import collect_gpos
from adscanner.collector.domain_config_collector import collect_domain_config
from adscanner.collector.smb_probe import smb_signing_required

__all__ = [
    "LDAPConnector", "LDAPConnectorError",
    "ADUser", "collect_users",
    "ADGroup", "collect_groups",
    "ObjectACL", "collect_all_acls",
    "collect_trusts",
    "ADComputer", "collect_computers",
    "collect_adcs_templates",
    "collect_gpos",
    "collect_domain_config",
    "smb_signing_required",
]