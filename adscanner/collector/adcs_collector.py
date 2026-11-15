"""
ADCSCollector — Thu thập Certificate Templates và CA đã phát hành.
Chỉ giữ lại các template đã được phát hành trên ít nhất một CA,
tránh báo sai các template không thể request.
"""
import logging
from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import ldap_scalar, ldap_int, ldap_list
from adscanner.utils.security_descriptor import extract_aces

logger = logging.getLogger(__name__)

def get_config_nc(connector: LDAPConnector) -> str:
    return f"CN=Configuration,{connector.base_dn}"

def collect_adcs_templates(connector: LDAPConnector) -> dict:
    logger.info("[%s] Thu thập AD CS Certificate Templates ...", connector.config.domain)
    base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{get_config_nc(connector)}"
    
    # 1. Lấy danh sách template đã phát hành trên CA
    ca_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{get_config_nc(connector)}"
    ca_entries = connector.search(
        "(objectClass=pKIEnrollmentService)",
        attributes=["cn", "certificateTemplates"],
        search_base=ca_base
    )
    
    published_templates = set()
    for ca in ca_entries:
        templates = ca.get("certificateTemplates", [])
        if isinstance(templates, str): templates = [templates]
        for t in templates:
            published_templates.add(str(t).lower())
    
    if not published_templates:
        logger.warning("[%s] Không tìm thấy template nào được phát hành trên CA.", connector.config.domain)
        return {"templates": [], "published_templates": []}

    # 2. Lấy thông tin chi tiết của các template
    entries = connector.search(
        "(objectClass=pKICertificateTemplate)",
        attributes=[
            "cn", "displayName", "distinguishedName",
            "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
            "pKIExtendedKeyUsage", "nTSecurityDescriptor"
        ],
        search_base=base
    )
    
    templates = []
    for e in entries:
        name = str(ldap_scalar(e.get("displayName") or e.get("cn")) or "")
        # Chỉ giữ template đã phát hành
        if name.lower() not in published_templates:
            continue
        
        name_flag = ldap_int(e.get("msPKI-Certificate-Name-Flag", 0))
        enroll_flag = ldap_int(e.get("msPKI-Enrollment-Flag", 0))
        eku = ldap_list(e.get("pKIExtendedKeyUsage"))
        
        raw_sd = e.get("nTSecurityDescriptor")
        aces = extract_aces(raw_sd)
        
        # Tìm ACE cho phép enroll (0x100) - dùng cho D2 (nếu cần)
        enroll_aces = [a for a in aces if a['type'] == 0x00 and a['mask'] & 0x100]
        
        templates.append({
            "name": name,
            "enrollee_supplies_subject": bool(name_flag & 0x1),
            "requires_manager_approval": bool(enroll_flag & 0x2),
            "eku": eku,
            "enroll_aces": enroll_aces,
        })
    
    logger.info("[%s] Đã thu thập %d template (đã phát hành).", connector.config.domain, len(templates))
    return {"templates": templates, "published_templates": list(published_templates)}