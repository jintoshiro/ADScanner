"""Test UserCollector — kiểm tra việc thu thập và parse user."""
import json
import logging

from adscanner.config import load_profile
from adscanner.collector import LDAPConnector
from adscanner.collector.user_collector import collect_users

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)


def main():
    profile = load_profile("lab")

    with LDAPConnector(profile.primary) as conn:
        users = collect_users(conn)

    print(f"\n=== Đã thu thập {len(users)} user ===\n")

    # 1. In bảng tóm tắt
    print(f"{'sAM':22s} {'Disabled':8s} {'PwdSet':12s} {'PwdAge':>7s} "
          f"{'LogonTS':12s} {'LogonAge':>9s} {'Admin':5s} {'SPN':3s} "
          f"{'Kerber':6s} {'ASREP':5s}")
    print("-" * 110)
    for u in users[:15]:
        pwd_iso = u.pwd_last_set[:10] if u.pwd_last_set else "-"
        llts_iso = u.last_logon[:10] if u.last_logon else "-"
        print(
            f"{u.sam:22s} "
            f"{'YES' if u.disabled else '-':8s} "
            f"{pwd_iso:12s} "
            f"{str(u.pwd_age_days) if u.pwd_age_days is not None else '-':>7s} "
            f"{llts_iso:12s} "
            f"{str(u.last_logon_age_days) if u.last_logon_age_days is not None else '-':>9s} "
            f"{'1' if u.is_admin_count_set else '-':5s} "
            f"{len(u.spn):3d} "
            f"{'YES' if u.is_kerberoastable else '-':6s} "
            f"{'YES' if u.is_asrep_roastable else '-':5s}"
        )

    # 2. Kiểm tra nhanh vài "lỗ hổng" mẫu
    print("\n=== Phát hiện nhanh ===")
    for u in users:
        findings = []
        if u.dont_expire_password:
            findings.append("DONT_EXPIRE_PASSWORD")
        if u.password_not_required:
            findings.append("PASSWD_NOTREQD")
        if u.is_asrep_roastable:
            findings.append("ASREP_ROASTABLE")
        if u.is_kerberoastable:
            findings.append(f"KERBEROASTABLE({len(u.spn)} SPN)")
        if u.is_admin_count_set and not u.disabled:
            findings.append("ADMIN_COUNT=1")
        if u.sid_history:
            findings.append(f"SID_HISTORY({len(u.sid_history)})")
        if u.allowed_to_act_on_behalf_of:
            findings.append("RBCD")
        if u.allowed_to_delegate_to:
            findings.append(f"CONSTRAINED_DELEG({len(u.allowed_to_delegate_to)})")

        if findings:
            print(f"  [{u.sam:20s}] {', '.join(findings)}")

    # 3. Lưu ra JSON để inspect
    with open("users_raw.json", "w", encoding="utf-8") as f:
        json.dump([u.to_dict() for u in users], f, indent=2, ensure_ascii=False)
    print(f"\n[+] Đã lưu dữ liệu vào users_raw.json")


if __name__ == "__main__":
    main()