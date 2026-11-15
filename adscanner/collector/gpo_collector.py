import logging
from impacket.smbconnection import SMBConnection
from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import ldap_scalar

logger = logging.getLogger(__name__)

def collect_gpos(connector: LDAPConnector) -> list[dict]:
    logger.info("[%s] Thu thập GPOs và phân tích qua SMB ...", connector.config.domain)
    
    # 1. Lấy danh sách GPO từ LDAP
    base = f"CN=Policies,CN=System,{connector.base_dn}"
    entries = connector.search(
        "(objectClass=groupPolicyContainer)",
        attributes=["displayName", "gPCFileSysPath", "distinguishedName"],
        search_base=base
    )
    
    gpos = []
    for e in entries:
        gpos.append({
            "name": ldap_scalar(e.get("displayName")),
            "file_path": ldap_scalar(e.get("gPCFileSysPath"))
        })
    
    # 2. Đọc file GptTmpl.inf qua SMB (Sử dụng tài khoản từ config)
    try:
        smb = SMBConnection(connector.config.dc_ip, connector.config.dc_ip)
        smb.login(connector.config.username, connector.config.password, connector.config.domain)
        
        for gpo in gpos:
            # gPCFileSysPath dạng: \\lab.local\SYSVOL\lab.local\Policies\{GUID}
            if not gpo["file_path"]: continue
            
            # Chuyển UNC path sang đường dẫn SMB tương đối
            parts = gpo["file_path"].replace("\\\\", "").split("\\")
            share = parts[1]  # SYSVOL
            rel_path = "\\".join(parts[2:]) + "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
            
            try:
                # Đọc file
                file_obj = smb.getFile(share, rel_path)
                content = file_obj.read().decode('utf-8', errors='ignore')
                
                # Phân tích LmCompatibilityLevel
                for line in content.splitlines():
                    if "LmCompatibilityLevel" in line:
                        level = int(line.split("=")[1].strip())
                        if level < 3: # NTLMv1 hoặc LM
                            gpo["vulnerable_ntlm"] = True
            except Exception:
                pass # File có thể không tồn tại
                
        smb.close()
    except Exception as e:
        logger.warning("Không thể đọc SYSVOL qua SMB: %s", e)
        
    return gpos