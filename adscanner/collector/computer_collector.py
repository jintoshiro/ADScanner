from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import ldap_scalar, ldap_int
from adscanner.utils.uac import is_trusted_for_delegation, is_disabled
from dataclasses import dataclass, field

@dataclass
class ADComputer:
    sam: str
    dn: str
    os_version: str | None
    is_unconstrained: bool
    disabled: bool
    primary_group_id: int = 0 
    uac_raw: int = 0 

def collect_computers(connector: LDAPConnector) -> list[ADComputer]:
    entries = connector.search("(objectClass=computer)", attributes=[
        "sAMAccountName", "distinguishedName", "operatingSystem",
        "userAccountControl", "dNSHostName"
    ])
    computers = []
    for e in entries:
        uac = ldap_int(e.get("userAccountControl", 0))
        pgid = ldap_int(e.get("primaryGroupID", 0)) # <-- THÊM DÒNG NÀY
        
        computers.append(ADComputer(
            sam=str(ldap_scalar(e.get("sAMAccountName")) or ""),
            dn=str(ldap_scalar(e.get("distinguishedName")) or ""),
            os_version=ldap_scalar(e.get("operatingSystem")),
            is_unconstrained=is_trusted_for_delegation(uac),
            disabled=is_disabled(uac),
            primary_group_id=pgid, # <-- Dòng này đã có sẵn
            uac_raw=uac
        ))
    return computers