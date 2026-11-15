"""
Test toàn bộ pipeline: collect + run checks + scoring.
"""
from adscanner.reporting.generator import generate_html_report
import argparse
import logging
import sys
from adscanner.analysis.graph_builder import build_attack_graph
from adscanner.config import load_profile
from adscanner.collector import collect_computers
from adscanner.collector import (
    LDAPConnector,
    collect_users,
    collect_groups,
    collect_all_acls,
    collect_rbcd_objects,
    collect_trusts,
    collect_computers,
    collect_adcs_templates,
    collect_gpos,
)
from adscanner.collector.domain_config_collector import collect_domain_config
from adscanner.collector.smb_probe import smb_signing_required
from adscanner.checks import (
    ScanContext,
    CheckStatus,
    get_all_checks,
    get_check_by_id,
)
from adscanner.scoring.engine import calculate_risk_score

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

    f = result.finding
    print(f"  [FAIL ] {result.check_id}: {result.check_name}")
    print(f"          Severity: {f.severity.value}")
    print(f"          {f.evidence_summary}")
    print(f"          Remediation: {f.remediation[:100]}...")
    
    for obj in f.affected_objects[:5]:
        # Lấy tên hiển thị
        name = obj.get("sam") or obj.get("trustee_name") or obj.get("object") or obj.get("source") or obj.get("resource") or obj.get("template_name") or obj.get("gpo_name") or "?"       
        # Các trường thông tin bổ sung
        extra = {k: v for k, v in obj.items()
                 if k not in ("sam", "trustee_name", "object", "source", "resource") and v}
                 
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
    
    # 1. Thu thập dữ liệu
    with LDAPConnector(profile.primary) as conn:
        users = collect_users(conn)
        groups = collect_groups(conn)
        all_acls = collect_all_acls(conn)
        rbcd_objs = collect_rbcd_objects(conn)
        trusts = collect_trusts(conn)
        computers = collect_computers(conn)
        adcs_data = collect_adcs_templates(conn)
        gpos = collect_gpos(conn) 
        domain_cfg = collect_domain_config(conn)

    print(f"[+] Đã thu thập {len(users)} user(s), {len(groups)} group(s).")
    print(f"[+] Đã thu thập ACL của {len(all_acls)} object.")
    print(f"[+] Đã thu thập {len(trusts)} trust(s).\n") # <-- In ra số lượng trust
    smb_signing = smb_signing_required(profile.primary.dc_ip)
    print(f"[+] SMB Signing required: {smb_signing}")
    # 2. Tạo Context (Đã sửa lại thụt lề)
    ctx = ScanContext(
        profile=profile, 
        connector=None,
        users=users, 
        groups=groups,
        acls=all_acls,
        rbcd_objects=rbcd_objs,
        trusts=trusts,
        computers=computers,
        adcs_data=adcs_data,
        gpos=gpos,
        domain_config=domain_cfg,
        smb_signing_req=smb_signing,
    )

    # 2.1. Build đồ thị tấn công và gán vào context
    ctx.graph = build_attack_graph(ctx)

    # 3. Chọn checks
    if args.check:
        check = get_check_by_id(args.check)
        if not check:
            print(f"[!] Không tìm thấy check ID: {args.check}")
            sys.exit(1)
        checks = [check]
    else:
        checks = get_all_checks()

    print(f"[+] Chạy {len(checks)} check(s)...\n")

    # 4. Chạy và thu thập kết quả
    stats = {CheckStatus.PASS: 0, CheckStatus.FAIL: 0, CheckStatus.ERROR: 0}
    results_list = []  
    
    for check in checks:
        result = check.run(ctx)
        results_list.append(result)
        stats[result.status] += 1
        print_result(result, args.verbose)

    # 5. Tổng kết
    print(f"\n=== Tổng kết ===")
    print(f"  PASS : {stats[CheckStatus.PASS]}")
    print(f"  FAIL : {stats[CheckStatus.FAIL]}")
    print(f"  ERROR: {stats[CheckStatus.ERROR]}")

    # 6. Tính điểm rủi ro
    risk = calculate_risk_score(results_list)
    
    print(f"\n=== ĐÁNH GIÁ RỦI RO (RISK SCORING) ===")
    print(f"  Điểm rủi ro: {risk.total_score:.1f}/100")
    print(f"  Phân loại   : {risk.grade}")
    print(f"  Chi tiết lỗi: {risk.severity_counts['CRITICAL']} Critical, "
          f"{risk.severity_counts['HIGH']} High, "
          f"{risk.severity_counts['MEDIUM']} Medium, "
          f"{risk.severity_counts['LOW']} Low")
          
    # 7. Xuất báo cáo HTML
    generate_html_report(profile, results_list, risk, output_path="adscanner_report.html")

if __name__ == "__main__":
    main()