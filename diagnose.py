"""Chẩn đoán kiểu dữ liệu của các thuộc tính thời gian AD."""
from adscanner.config import load_profile
from adscanner.collector import LDAPConnector

profile = load_profile("lab")
with LDAPConnector(profile.primary) as conn:
    entries = conn.search_subtree(
        "(sAMAccountName=Administrator)",
        attributes=["pwdLastSet", "lastLogonTimestamp", "accountExpires"],
    )
    for e in entries:
        for attr in ("pwdLastSet", "lastLogonTimestamp", "accountExpires"):
            val = e.get(attr)
            print(f"{attr:22s} type={type(val).__name__:10s} value={val!r}")