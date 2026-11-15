"""Debug chi tiết impacket parse SD."""
from adscanner.config import load_profile
from adscanner.collector import LDAPConnector
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

profile = load_profile("lab")
with LDAPConnector(profile.primary) as conn:
    entries = conn.search(
        search_filter="(objectClass=domainDNS)",
        attributes=["nTSecurityDescriptor"],
        search_base=conn.base_dn,
        search_scope="BASE",
        sd_flags=0x04,
        paged=False,
    )
    raw_sd = entries[0].get("nTSecurityDescriptor")
    
    if isinstance(raw_sd, list):
        raw_sd = raw_sd[0]
    
    print(f"Độ dài raw_sd: {len(raw_sd)}")
    
    # Cách 1: Truyền data vào constructor (như code hiện tại)
    sd = SR_SECURITY_DESCRIPTOR(data=raw_sd)
    print("\n--- Kết quả parse bằng data= ---")
    print(f"OffsetDacl: {sd['OffsetDacl']}")
    print(f"Dacl: {sd['Dacl']}")
    if sd['Dacl']:
        print(f"AceCount: {sd['Dacl']['AceCount']}")
        print(f"Kiểu của 'aces': {type(sd['Dacl']['aces'])}")
        print(f"Số lượng ACE thực tế: {len(sd['Dacl']['aces']) if sd['Dacl']['aces'] else 0}")

    # Cách 2: Dùng hàm fromString()
    sd2 = SR_SECURITY_DESCRIPTOR()
    sd2.fromString(raw_sd)
    print("\n--- Kết quả parse bằng fromString() ---")
    print(f"OffsetDacl: {sd2['OffsetDacl']}")
    print(f"Dacl: {sd2['Dacl']}")
    if sd2['Dacl']:
        print(f"AceCount: {sd2['Dacl']['AceCount']}")
        print(f"Số lượng ACE thực tế: {len(sd2['Dacl']['aces']) if sd2['Dacl']['aces'] else 0}")