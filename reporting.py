import re
from datetime import datetime
from pathlib import Path

from jinja2 import Template
from llm_interface import LLMInterface

class ReportGenerator:
    def __init__(self, data_store):
        self.data_store = data_store
        self.llm = LLMInterface()
        self.template_path = Path(__file__).parent / "templates" / "report_template.html"

    def generate(self, format="html"):
        # Load data
        state = self.data_store.load_state()
        findings = state.get("findings", [])
        history = state.get("history", [])
        target = state.get("target")

        # Generate executive summary via LLM
        try:
            exec_summary = self.llm.query(self.llm.build_prompt("report_executive", state))
        except Exception:
            exec_summary = self._fallback_summary(findings, history)

        # Load template
        with open(self.template_path, "r", encoding="utf-8") as f:
            template_str = f.read()
        template = Template(template_str)

        # Calculate stats for advanced template
        high_count = len([f for f in findings if f.get("severity") in {"Critical", "High"}])

        # Render
        html_content = template.render(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d"),
            executive_summary=exec_summary,
            findings=findings,
            history=history,
            high_count=high_count
        )
        safe_target = self._safe_name(target or "unknown_target")
        output_dir = Path(self.data_store.data_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if format == "html":
            out_path = output_dir / f"report_{safe_target}.html"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        elif format == "pdf":
            from weasyprint import HTML
            out_path = output_dir / f"report_{safe_target}.pdf"
            HTML(string=html_content).write_pdf(str(out_path))
        else:
            raise ValueError("format must be 'html' or 'pdf'")
        print(f"[+] Report generated: {out_path}")
        return str(out_path)

    def _safe_name(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value)

    def _fallback_summary(self, findings, history):
        total = len(findings)
        high = len([f for f in findings if f.get("severity") in {"Critical", "High"}])
        return (
            f"Assessment executed {len(history)} actions and collected {total} findings. "
            f"High-priority findings: {high}. "
            "Review detailed findings and evidence for remediation planning."
        )
