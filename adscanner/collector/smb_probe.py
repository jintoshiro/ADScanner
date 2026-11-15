"""Kiểm tra SMB Signing mà không cần đăng nhập."""
import logging
from impacket.smbconnection import SMBConnection

logger = logging.getLogger(__name__)

def smb_signing_required(dc_host: str, timeout: int = 10) -> bool | None:
    """Trả về True nếu DC bắt buộc SMB signing, False nếu không, None nếu lỗi."""
    try:
        conn = SMBConnection(dc_host, dc_host, sess_port=445, timeout=timeout)
        try:
            return conn.isSigningRequired()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Không thể kiểm tra SMB signing với %s: %s", dc_host, e)
        return None