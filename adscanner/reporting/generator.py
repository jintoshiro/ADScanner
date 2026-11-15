"""
Report Generator — Kết xuất báo cáo HTML bằng Jinja2.
"""
import os
from jinja2 import Environment, FileSystemLoader
from adscanner.checks import CheckResult
from adscanner.scoring.engine import RiskScore
from adscanner.config import Profile

def generate_html_report(
    profile: Profile,
    results: list[CheckResult],
    risk: RiskScore,
    output_path: str = "adscanner_report.html"
):
    # Xác định đường dẫn thư mục chứa template
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(current_dir, "templates")
    
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")
    
    # Render HTML
    html_out = template.render(
        profile=profile,
        results=results,
        risk=risk
    )
    
    # Ghi ra file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_out)
        
    print(f"\n[+] Đã xuất báo cáo HTML tại: {os.path.abspath(output_path)}")