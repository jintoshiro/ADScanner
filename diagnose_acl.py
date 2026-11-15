"""
Chẩn đoán nTSecurityDescriptor — thử nhiều tổ hợp để tìm nguyên nhân
tại sao attribute trả về rỗng.
"""
from ldap3 import Server, Connection, ALL, NONE, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

from adscanner.config import load_profile


def try_read_sd(dc_ip, domain, domain_dn, username, password,
                label, use_control=False, get_info=ALL):
    """Thử đọc nTSecurityDescriptor với một cấu hình cụ thể."""
    print(f"\n{'=' * 70}")
    print(f"[{label}]")
    print(f"  use_control={use_control}, get_info={get_info.__name__ if hasattr(get_info, '__name__') else get_info}")
    print(f"{'=' * 70}")

    try:
        server = Server(dc_ip, get_info=get_info)
        user = f"{domain}\\{username}"
        conn = Connection(
            server, user=user, password=password,
            authentication=NTLM, auto_bind=True,
        )
    except Exception as e:
        print(f"  [!] Không kết nối được: {type(e).__name__}: {e}")
        return

    controls = security_descriptor_control(sdflags=0x04) if use_control else None

    try:
        ok = conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=domainDNS)",
            attributes=["nTSecurityDescriptor"],
            controls=controls,
            size_limit=1,
        )
    except Exception as e:
        print(f"  [!] Search exception: {type(e).__name__}: {e}")
        conn.unbind()
        return

    print(f"  search() returned: {ok}")
    print(f"  conn.result: {conn.result}")

    for i, resp in enumerate(conn.response):
        if resp.get("type") != "searchResEntry":
            continue
        print(f"\n  --- Response entry #{i} ---")
        raw_attrs = resp.get("raw_attributes", {})
        attrs = resp.get("attributes", {})
        print(f"  raw_attributes keys : {list(raw_attrs.keys())}")
        print(f"  attributes keys     : {list(attrs.keys())}")

        if "nTSecurityDescriptor" in raw_attrs:
            raw = raw_attrs["nTSecurityDescriptor"]
            print(f"  RAW  type={type(raw).__name__}, "
                  f"len={len(raw) if hasattr(raw, '__len__') else 'N/A'}")
            if isinstance(raw, (bytes, bytearray)) and len(raw) > 0:
                print(f"  RAW  first 32 bytes: {raw[:32].hex()}")
            if isinstance(raw, list) and raw:
                for j, item in enumerate(raw):
                    print(f"  RAW  [{j}] type={type(item).__name__}, "
                          f"len={len(item) if hasattr(item, '__len__') else 'N/A'}")
                    if isinstance(item, (bytes, bytearray)) and len(item) > 0:
                        print(f"  RAW  [{j}] first 32 bytes: {item[:32].hex()}")

        if "nTSecurityDescriptor" in attrs:
            val = attrs["nTSecurityDescriptor"]
            print(f"  PARSED value: {val!r}")

        if "nTSecurityDescriptor" not in raw_attrs and "nTSecurityDescriptor" not in attrs:
            print(f"  [!] nTSecurityDescriptor KHÔNG có trong response")
            print(f"  [!] Có thể do thiếu quyền READ_CONTROL trên domain object")

    conn.unbind()


def main():
    profile = load_profile("lab")
    dc_ip = profile.primary.dc_ip
    domain = profile.primary.domain
    domain_dn = profile.primary.domain_dn

    print(f"Domain: {domain}")
    print(f"Domain DN: {domain_dn}")
    print(f"DC IP: {dc_ip}")

    # === Test với svc_kerb (user thường) ===
    try_read_sd(dc_ip, domain, domain_dn, "svc_kerb", "Lab@123456!",
                "1. svc_kerb | ALL | no control",
                use_control=False, get_info=ALL)

    try_read_sd(dc_ip, domain, domain_dn, "svc_kerb", "Lab@123456!",
                "2. svc_kerb | ALL | WITH control (sdflags=0x04 DACL)",
                use_control=True, get_info=ALL)

    try_read_sd(dc_ip, domain, domain_dn, "svc_kerb", "Lab@123456!",
                "3. svc_kerb | NONE | no control",
                use_control=False, get_info=NONE)

    # === Test với Administrator (Domain Admin) ===
    try_read_sd(dc_ip, domain, domain_dn, "Administrator", "AD123@",
                "4. Administrator | ALL | no control",
                use_control=False, get_info=ALL)

    try_read_sd(dc_ip, domain, domain_dn, "Administrator", "AD123@",
                "5. Administrator | ALL | WITH control",
                use_control=True, get_info=ALL)


if __name__ == "__main__":
    main()