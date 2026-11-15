"""
LDAPConnector — lớp quản lý kết nối LDAP tới một domain Active Directory.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from ldap3 import (
    Server, Connection, ALL, NTLM, SIMPLE, Tls,
    BASE, SUBTREE, LEVEL,
)
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.core.exceptions import (
    LDAPException,
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPOperationResult,
)

from adscanner.config import DomainConfig

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF = 2.0
RECEIVE_TIMEOUT = 30
PAGE_SIZE = 1000


class LDAPConnectorError(Exception):
    """Exception gốc cho mọi lỗi của LDAPConnector."""


class LDAPConnector:
    def __init__(self, config: DomainConfig):
        self.config = config
        self.server: Server | None = None
        self.conn: Connection | None = None
        self._base_dn: str | None = None

    @property
    def is_connected(self) -> bool:
        return self.conn is not None and self.conn.bound

    @property
    def base_dn(self) -> str:
        return self._base_dn or self.config.domain_dn

    def connect(self) -> None:
        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._connect_once()
                logger.info(
                    "[%s] Kết nối thành công tới %s:%d (attempt %d)",
                    self.config.domain, self.config.dc_ip,
                    self._port, attempt,
                )
                return
            except LDAPBindError as e:
                logger.error("[%s] Xác thực thất bại: %s", self.config.domain, e)
                raise LDAPConnectorError(f"Xác thực thất bại: {e}") from e
            except (LDAPSocketOpenError, LDAPException, OSError) as e:
                last_error = e
                wait = RETRY_BACKOFF * (2 ** (attempt - 1))
                logger.warning(
                    "[%s] Kết nối thất bại (attempt %d/%d): %s. Thử lại sau %.1fs",
                    self.config.domain, attempt, MAX_RETRIES, e, wait,
                )
                if attempt < MAX_RETRIES:
                    time.sleep(wait)

        raise LDAPConnectorError(
            f"Không thể kết nối tới {self.config.dc_ip} sau {MAX_RETRIES} lần thử: {last_error}"
        )

    @property
    def _port(self) -> int:
        return self.config.ldaps_port if self.config.use_ldaps else self.config.ldap_port

    def _connect_once(self) -> None:
        tls = Tls(validate=0) if self.config.use_ldaps else None
        self.server = Server(
            self.config.dc_ip,
            port=self._port,
            use_ssl=self.config.use_ldaps,
            tls=tls,
            get_info=ALL,
        )

        if self.config.use_ntlm:
            user = f"{self.config.domain}\\{self.config.username}"
            auth = NTLM
        else:
            user = f"{self.config.username}@{self.config.domain}"
            auth = SIMPLE

        self.conn = Connection(
            self.server,
            user=user,
            password=self.config.password,
            authentication=auth,
            auto_bind=True,
            receive_timeout=RECEIVE_TIMEOUT,
            read_only=True,
        )

        try:
            root_dse = self.server.info.other
            if root_dse and "defaultNamingContext" in root_dse:
                self._base_dn = root_dse["defaultNamingContext"][0]
        except (AttributeError, IndexError, KeyError):
            self._base_dn = self.config.domain_dn

    def disconnect(self) -> None:
        if self.conn and self.conn.bound:
            try:
                self.conn.unbind()
                logger.debug("[%s] Đã đóng kết nối", self.config.domain)
            except LDAPException:
                pass
        self.conn = None

    def __enter__(self) -> "LDAPConnector":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    def search(
        self,
        search_filter: str,
        attributes: list[str] | None = None,
        search_base: str | None = None,
        search_scope: str = SUBTREE,
        sd_flags: int | None = None,
        paged: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Tìm kiếm LDAP, xử lý đặc biệt để giữ nguyên raw bytes của nTSecurityDescriptor.
        """
        if not self.is_connected:
            raise LDAPConnectorError("Chưa kết nối. Gọi connect() trước.")

        base = search_base or self.base_dn
        attrs = attributes or ["*"]

        controls = None
        if sd_flags is not None:
            controls = security_descriptor_control(sdflags=sd_flags)

        def _extract_entries(response_list) -> list[dict[str, Any]]:
            """Dùng conn.response thay vì conn.entries để giữ raw_attributes."""
            res = []
            for item in response_list:
                if item.get("type") != "searchResEntry":
                    continue
                
                # Bản sao của attributes (đã được ldap3 parse thành string/int)
                entry_dict = dict(item.get("attributes", {}))
                
                # Cứu nTSecurityDescriptor từ raw_attributes
                raw_attrs = item.get("raw_attributes", {})
                if "nTSecurityDescriptor" in raw_attrs:
                    raw_val = raw_attrs["nTSecurityDescriptor"]
                    if raw_val:
                        entry_dict["nTSecurityDescriptor"] = raw_val
                        
                res.append(entry_dict)
            return res

        try:
            entries: list[dict[str, Any]] = []

            if not paged:
                ok = self.conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attrs,
                    controls=controls,
                )
                if not ok:
                    code = self.conn.result.get("result", -1)
                    if code == 0:
                        return []
                    raise LDAPConnectorError(
                        f"LDAP search thất bại (code {code}): "
                        f"{self.conn.result.get('description')}"
                    )
                entries.extend(_extract_entries(self.conn.response))
            else:
                cookie = None
                page_num = 0
                while True:
                    page_num += 1
                    ok = self.conn.search(
                        search_base=base,
                        search_filter=search_filter,
                        search_scope=search_scope,
                        attributes=attrs,
                        paged_size=PAGE_SIZE,
                        paged_cookie=cookie,
                        controls=controls,
                    )
                    if not ok:
                        code = self.conn.result.get("result", -1)
                        if code == 0:
                            break
                        raise LDAPConnectorError(
                            f"LDAP search thất bại (code {code}): "
                            f"{self.conn.result.get('description')}"
                        )
                    
                    entries.extend(_extract_entries(self.conn.response))

                    paged_ctrl = self.conn.result.get("controls", {}).get(
                        "1.2.840.113556.1.4.319", {}
                    )
                    cookie = paged_ctrl.get("value", {}).get("cookie")
                    if not cookie:
                        break

            logger.info(
                "[%s] Search '%s' → %d entries",
                self.config.domain, search_filter, len(entries),
            )
            return entries

        except LDAPOperationResult as e:
            raise LDAPConnectorError(f"LDAP operation thất bại: {e}") from e
        except LDAPException as e:
            raise LDAPConnectorError(f"LDAP exception: {e}") from e

    # ============================================================
    # HELPERS
    # ============================================================
    def search_subtree(self, search_filter: str,
                       attributes: list[str] | None = None) -> list[dict[str, Any]]:
        return self.search(search_filter, attributes, search_scope=SUBTREE)

    def search_base_level(self, search_filter: str,
                          attributes: list[str] | None = None) -> list[dict[str, Any]]:
        return self.search(search_filter, attributes, search_scope=BASE)
    def get_root_dse(self) -> dict[str, Any]:
        """Trả về thuộc tính rootDSE (dùng cho Configuration NC)."""
        if not self.server or not self.server.info:
            return {}
        result = {}
        if self.server.info.other:
            result.update(dict(self.server.info.other))
        return result