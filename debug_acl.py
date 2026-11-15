"""Debug chi tiết ACL — xem raw bytes và kết quả parse của impacket."""
from adscanner.config import load_profile
from adscanner.collector import LDAPConnector
from adscanner.utils.security_descriptor import parse_security_descriptor, extract_aces

profile = load_profile("lab")
with LDAPConnector(profile.primary) as conn:
    entries = conn.search(
        search_filter="(objectClass=domainDNS)",
        attributes=["nTSecurityDescriptor", "distinguishedName"],
        search_base=conn.base_dn,
        search_scope="BASE",
        sd_flags=0x04,
        paged=False,
    )
    
    print(f"Số entries trả về: {len(entries)}")
    if not entries:
        print("[-] Không có entry nào. Kiểm tra lại filter hoặc quyền.")
        exit()
        
    entry = entries[0]
    raw_sd = entry.get("nTSecurityDescriptor")
    
    print(f"\n--- Dữ liệu thô ---")
    print(f"Kiểu dữ liệu của raw_sd: {type(raw_sd)}")
    print(f"Giá trị raw_sd: {raw_sd}")
    
    print(f"\n--- Kết quả parse (SecurityDescriptor) ---")
    sd = parse_security_descriptor(raw_sd)
    print(f"sd object: {sd}")
    
    if sd:
        print(f"Owner: {getattr(sd, 'Owner', None)}")
        print(f"Dacl object: {getattr(sd, 'Dacl', None)}")
        
        dacl = getattr(sd, 'Dacl', None)
        if dacl:
            print(f"Các thuộc tính của Dacl: {[a for a in dir(dacl) if not a.startswith('_')]}")
            aces = getattr(dacl, 'aces', None)
            print(f"Số lượng ACE trong Dacl.aces: {len(aces) if aces is not None else 'None'}")
            if aces:
                for i, ace in enumerate(aces[:3]): # In 3 ACE đầu
                    print(f"  ACE {i}: {ace}")
    
    print(f"\n--- Kết quả extract_aces ---")
    aces_list = extract_aces(raw_sd)
    print(f"Số ACE trích xuất được: {len(aces_list)}")