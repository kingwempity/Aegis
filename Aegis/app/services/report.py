"""
app.services.report
-------------------
报告生成服务：HTML 版 (暂移除 PDF 以保证稳定性)。
"""
import os
from jinja2 import Environment, FileSystemLoader
from app.models.task import ScanTask

TEMPLATE_DIR = "/app/app/templates"
OUTPUT_DIR = "/app/data/reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

    def generate_html(self, task: ScanTask, filename: str) -> str:
        """生成 HTML 报告并返回文件路径"""
        template = self.env.get_template("report.html")
        html_content = template.render(task=task, vulns=task.vulnerabilities)
        
        output_path = os.path.join(OUTPUT_DIR, filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return output_path
