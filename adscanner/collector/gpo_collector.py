import io
import logging
from impacket.smbconnection import SMBConnection
from adscanner.collector.ldap_connector import LDAPConnector
from adscanner.utils import ldap_scalar

logger = logging.getLogger(__name__)

def collect_gpos(connector: LDAPConnector) -> list[dict]:
    logger.info("[%s] Thu thập GPOs ...", connector.config.domain)
    base = f"CN=Policies,CN=System,{connector.base_dn}"
    entries = connector.search(
        "(objectClass=groupPolicyContainer)",
        attributes=["displayName", "gPCFileSysPath"],
        search_base=base
    )
    gpos = [{
        "name": ldap_scalar(e.get("displayName")),
        "file_path": ldap_scalar(e.get("gPCFileSysPath")),
        "ntlmv1_allowed": False,
    } for e in entries]

    try:
        smb = SMBConnection(connector.config.dc_ip, connector.config.dc_ip)
        smb.login(connector.config.username, connector.config.password, connector.config.domain)
        
        for gpo in gpos:
            if not gpo["file_path"]: continue
            parts = gpo["file_path"].replace("\\\\", "").split("\\")
            if len(parts) < 3: continue
            share = parts[1]
            rel_path = "\\".join(parts[2:]) + "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
            
            buf = io.BytesIO()
            try:
                smb.getFile(share, rel_path, buf.write)  # Dùng callback
                raw = buf.getvalue()
                # Decode UTF-16 (GptTmpl.inf thường là UTF-16 LE)
                text = raw.decode('utf-16-le', errors='ignore') if raw[:2] == b'\xff\xfe' else raw.decode('utf-8-sig', errors='ignore')
                
                for line in text.splitlines():
                    if "LmCompatibilityLevel" in line:
                        # Định dạng: LmCompatibilityLevel = 4,3
                        try:
                            val_str = line.split("=")[1].strip()
                            # Lấy phần sau dấu phẩy (value), không phải type
                            if "," in val_str:
                                val = int(val_str.split(",")[1])
                            else:
                                val = int(val_str)
                            if val < 3:
                                gpo["ntlmv1_allowed"] = True
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass
        smb.close()
    except Exception as e:
        logger.warning("Không đọc được SYSVOL: %s", e)
    
    return gpos