"""
TrustCollector — Thu thập thông tin Domain Trusts.
"""
import logging
from adscanner.collector.ldap_connector import LDAPConnector

logger = logging.getLogger(__name__)

def collect_trusts(connector: LDAPConnector) -> list[dict]:
    """Thu thập các Domain Trust từ phân vùng System."""
    logger.info("[%s] Thu thập Domain Trusts ...", connector.config.domain)
    
    # Trusts nằm trong container System
    search_base = f"CN=System,{connector.base_dn}"
    
    try:
        entries = connector.search(
            search_filter="(objectClass=trustedDomain)",
            attributes=["name", "trustDirection", "trustAttributes", "flatName"],
            search_base=search_base,
            search_scope="SUBTREE"
        )
    except Exception as e:
        logger.warning("Không thể lấy dữ liệu Trusts: %s", e)
        return []

    trusts = []
    for e in entries:
        name = e.get("name", "")
        if isinstance(name, list): name = name[0]
        
        direction = e.get("trustDirection", 0)
        if isinstance(direction, list): direction = direction[0]
        
        attributes = e.get("trustAttributes", 0)
        if isinstance(attributes, list): attributes = attributes[0]

        trusts.append({
            "name": str(name),
            "direction": int(direction or 0),
            "trust_attributes": int(attributes or 0)
        })
        
    logger.info("[%s] Đã tìm thấy %d Domain Trust(s).", connector.config.domain, len(trusts))
    return trusts