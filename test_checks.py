"""
Test toàn bộ pipeline: collect + run checks + scoring + report.
"""
import argparse
import logging
import sys

from adscanner.config import load_profile
from adscanner.collector import (
    LDAPConnector,
    collect_users,
    collect_groups,
    collect_trusts,
    collect_computers,
    collect_adcs_templates,
    collect_gpos,
)
from adscanner.collector.acl_collector import collect_all_acls
from adscanner.collector.domain_config_collector import collect_domain_config
from adscanner.collector.smb_probe import smb_signing_required
from adscanner.analysis.graph_builder import build_attack_graph
from adscanner.checks import (
    ScanContext,
    CheckStatus,
    get_all_checks,
    get_check_by_id,
)
from adscanner.scoring.engine import calculate_risk_score
from adscanner.reporting.generator import generate_html_report

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)


def print_result(result, verbose: bool):
    if result.status == CheckStatus.PASS:
        if verbose:
            print(f"  [PASS ] {result.check_id}: {result.check_name} "
                  f"({result.duration_ms:.1f}ms)")
        return

    if result.status == CheckStatus.NOT_ASSESSED:
        print(f"  [SKIP ] {result.check_id}: {result.check_name}")
        print(f"          → Không đánh giá được: {result.note or result.error}")
        return

    if result.status == CheckStatus.ERROR:
        print(f"  [ERROR] {result.check_id}: {result.check_name}")
        print(f"          → {result.error}")
        return

    f = result.finding
    print(f"  [FAIL ] {result.check_id}: {result.check_name}")
    print(f"          Severity: {f.severity.value}")
    print(f"          {f.evidence_summary}")
    print(f"          Remediation: {f.remediation[:100]}...")
    
    for obj in f.affected_objects[:5]:
        name = (obj.get("sam") or obj.get("trustee_name") or obj.get("object") 
                or obj.get("source") or obj.get("resource") or obj.get("template_name") 
                or obj.get("gpo_name") or "?")
        extra = {k: v for k, v in obj.items()
                 if k not in ("sam", "trustee_name", "object", "source", "resource", "template_name", "gpo_name") and v}
        print(f"            - {name}: {extra}")
        
    if f.affected_count > 5:
        print(f"            ... và {f.affected_count - 5} object khác")


def main():
    parser = argparse.ArgumentParser(description="ADScanner — test checks")
    parser.add_argument("--profile", default="lab")
    parser.add_argument("--check", help="Chỉ chạy một check (ID)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print(f"=== ADScanner — Profile: {args.profile} ===\n")

    profile = load_profile(args.profile)
    collection_status = {}

    # 1. Thu thập dữ liệu
    with LDAPConnector(profile.primary) as conn:
        users = collect_users(conn)
        groups = collect_groups(conn)

        # ACL trả về tuple (dict, bool)
        acls, acl_ok = collect_all_acls(conn)
        collection_status["acls"] = "ok" if acl_ok else "failed"

        # Các collector khác
        trusts = collect_trusts(conn)
        computers = collect_computers(conn)
        adcs_data = collect_adcs_templates(conn)
        gpos = collect_gpos(conn)
        domain_cfg = collect_domain_config(conn)

    # 2. SMB Signing (ngoài kết nối LDAP)
    smb_signing = smb_signing_required(profile.primary.dc_ip)
    collection_status["smb"] = "ok" if smb_signing is not None else "failed"

    # 3. In thống kê thu thập
    print(f"[+] Đã thu thập {len(users)} user(s), {len(groups)} group(s).")
    print(f"[+] Đã thu thập ACL của {len(acls)} object (trạng thái: {collection_status['acls']}).")
    print(f"[+] Đã thu thập {len(trusts)} trust(s), {len(computers)} computer(s).")
    print(f"[+] SMB Signing required: {smb_signing}")
    print()

    # 4. Tạo Context
    ctx = ScanContext(
        profile=profile,
        connector=None,
        users=users,
        groups=groups,
        acls=acls,
        trusts=trusts,
        computers=computers,
        adcs_data=adcs_data,
        gpos=gpos,
        domain_config=domain_cfg,
        smb_signing_req=smb_signing,
        collection_status=collection_status,
    )

    # 5. Build đồ thị tấn công
    ctx.graph = build_attack_graph(ctx)

    # 6. Chọn checks
    if args.check:
        check = get_check_by_id(args.check)
        if not check:
            print(f"[!] Không tìm thấy check ID: {args.check}")
            sys.exit(1)
        checks = [check]
    else:
        checks = get_all_checks()

    print(f"[+] Chạy {len(checks)} check(s)...\n")

    # 7. Chạy checks
    stats = {
        CheckStatus.PASS: 0,
        CheckStatus.FAIL: 0,
        CheckStatus.ERROR: 0,
        CheckStatus.NOT_ASSESSED: 0,  # Thêm key này để tránh KeyError
    }
    results_list = []
    
    for check in checks:
        result = check.run(ctx)
        results_list.append(result)
        stats[result.status] += 1
        print_result(result, args.verbose)

    # 8. Tổng kết
    print(f"\n=== Tổng kết ===")
    print(f"  PASS         : {stats[CheckStatus.PASS]}")
    print(f"  FAIL         : {stats[CheckStatus.FAIL]}")
    print(f"  NOT_ASSESSED : {stats[CheckStatus.NOT_ASSESSED]}")
    print(f"  ERROR        : {stats[CheckStatus.ERROR]}")

    # 9. Tính điểm rủi ro
    risk = calculate_risk_score(results_list)
    
    print(f"\n=== ĐÁNH GIÁ RỦI RO (RISK SCORING) ===")
    print(f"  Điểm rủi ro: {risk.total_score:.1f}/100")
    print(f"  Phân loại   : {risk.grade}")
    print(f"  Chi tiết lỗi: {risk.severity_counts['CRITICAL']} Critical, "
          f"{risk.severity_counts['HIGH']} High, "
          f"{risk.severity_counts['MEDIUM']} Medium, "
          f"{risk.severity_counts['LOW']} Low")
    print(f"  Độ phủ      : {risk.passed_checks + risk.failed_checks}/{risk.total_checks} check đã đánh giá")
    if risk.is_lower_bound:
        print(f"  ⚠ CẢNH BÁO    : {risk.not_assessed_checks + risk.error_checks} check chưa đánh giá được")

    # 10. Xuất báo cáo HTML
    generate_html_report(profile, results_list, risk, output_path="adscanner_report.html")


if __name__ == "__main__":
    main()