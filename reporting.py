import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from jinja2 import Template

from llm_interface import LLMInterface


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
NOISE_FINDING_NAMES = {"Browser workflow evidence captured"}
CONFIDENCE_LABELS = [
    (0.9, "Confirmed"),
    (0.75, "Strong"),
    (0.6, "Moderate"),
    (0.0, "Tentative"),
]
WEBAPP_ROUTE_HINTS = [
    "/login",
    "/register",
    "/search",
    "/admin",
    "/api",
    "/upload",
    "/download",
    "/ws",
]


class ReportGenerator:
    def __init__(self, data_store):
        self.data_store = data_store
        self.llm = LLMInterface(role="report")
        self.template_path = self._resolve_template_path()

    def generate(self, format: str = "html") -> str:
        state = self.data_store.load_state()
        history = state.get("history", [])
        raw_findings = state.get("findings", [])
        target = state.get("target") or "unknown_target"
        curated_findings = self._curate_findings(raw_findings)

        try:
            exec_summary = self.llm.query("report_executive", self._report_context(state, curated_findings, history))
        except Exception:
            exec_summary = self._fallback_summary(curated_findings, history)

        summary_text = self._normalize_executive_summary(exec_summary)
        stats = self._build_stats(curated_findings, history)
        tool_summary = self._build_tool_summary(history)
        coverage = self._build_coverage(history)
        coverage_gaps = self._build_coverage_gaps(history)
        category_summary = self._build_category_summary(curated_findings)

        with open(self.template_path, "r", encoding="utf-8") as f:
            template = Template(f.read())

        html_content = template.render(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d"),
            executive_summary=summary_text,
            findings=curated_findings,
            stats=stats,
            tool_summary=tool_summary,
            coverage=coverage,
            coverage_gaps=coverage_gaps,
            category_summary=category_summary,
        )

        safe_target = self._safe_name(target)
        output_dir = Path(self.data_store.data_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if format == "html":
            out_path = output_dir / f"report_{safe_target}.html"
            out_path.write_text(html_content, encoding="utf-8")
        elif format == "pdf":
            from weasyprint import HTML

            out_path = output_dir / f"report_{safe_target}.pdf"
            HTML(string=html_content, base_url=str(Path(__file__).parent)).write_pdf(str(out_path))
        else:
            raise ValueError("format must be 'html' or 'pdf'")

        print(f"[+] Report generated: {out_path}")
        return str(out_path)

    def _report_context(self, state: Dict[str, Any], findings: List[Dict[str, Any]], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        context = dict(state)
        context["findings"] = findings
        context["history"] = history[-20:]
        context["stats"] = self._build_stats(findings, history)
        return context

    def _resolve_template_path(self) -> Path:
        candidates = [
            Path(__file__).resolve().parent / "templates" / "report_template.html",
            Path.cwd() / "templates" / "report_template.html",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        raise FileNotFoundError(
            "Could not locate templates/report_template.html. "
            f"Tried: {', '.join(str(path) for path in candidates)}"
        )

    def _normalize_executive_summary(self, exec_summary: Any) -> str:
        if isinstance(exec_summary, dict):
            result = exec_summary.get("result")
            if isinstance(result, str) and result.strip():
                return self._sanitize_summary_text(result)
        if isinstance(exec_summary, str) and exec_summary.strip():
            return self._sanitize_summary_text(exec_summary)
        return self._sanitize_summary_text(str(exec_summary).strip())

    def _sanitize_summary_text(self, value: str) -> str:
        text = re.sub(r"<think>.*?</think>", "", str(value or ""), flags=re.DOTALL).strip()
        text = re.sub(r"^\s*(the user wants me to|based on the penetration testing[, ]*|hmm[, ]*|bahwa[, ]*).*?(?=[A-Z])", "", text, flags=re.IGNORECASE | re.DOTALL)
        sentences = re.split(r"(?<=[.!?])\s+", text)
        clean_sentences = [sentence.strip() for sentence in sentences if sentence.strip()]
        if clean_sentences:
            return " ".join(clean_sentences[:6]).strip()
        return text

    def _curate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            name = str(finding.get("name") or "").strip()
            if not name or name in NOISE_FINDING_NAMES:
                continue
            key = self._finding_key(finding)
            entry = merged.get(key)
            if entry is None:
                merged[key] = self._normalized_finding(finding)
                continue

            if SEVERITY_ORDER.get(finding.get("severity", "Low"), 99) < SEVERITY_ORDER.get(entry.get("severity", "Low"), 99):
                entry["severity"] = finding.get("severity", entry.get("severity"))
            entry["confidence"] = max(entry.get("confidence", 0.0), float(finding.get("confidence", entry.get("confidence", 0.0))))
            entry["description"] = self._pick_longer(entry.get("description", ""), finding.get("description", ""))
            entry["remediation"] = self._pick_longer(entry.get("remediation", ""), finding.get("remediation", ""))
            new_evidence = str(finding.get("evidence") or "").strip()
            if new_evidence and new_evidence not in entry["evidence_items"]:
                entry["evidence_items"].append(new_evidence)
            affected = str(finding.get("affected_resource") or "").strip()
            if affected and affected not in entry["affected_resources"]:
                entry["affected_resources"].append(affected)
            category = str(finding.get("category") or "").strip()
            if category and category not in entry["categories"]:
                entry["categories"].append(category)

        curated = list(merged.values())
        for item in curated:
            item["evidence"] = "\n\n".join(item["evidence_items"][:3])
            item["confidence_label"] = self._confidence_label(item.get("confidence", 0.0))
        curated.sort(key=lambda finding: (SEVERITY_ORDER.get(finding.get("severity", "Low"), 99), -float(finding.get("confidence", 0.0)), finding.get("name", "")))
        return curated

    def _normalized_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        evidence = str(finding.get("evidence") or "").strip()
        affected = str(finding.get("affected_resource") or "").strip()
        return {
            "name": finding.get("name", "Unnamed finding"),
            "severity": finding.get("severity", "Low"),
            "description": str(finding.get("description") or "").strip(),
            "remediation": str(finding.get("remediation") or "").strip(),
            "affected_resources": [affected] if affected else [],
            "evidence_items": [evidence] if evidence else [],
            "evidence": evidence,
            "confidence": float(finding.get("confidence", 0.6)),
            "categories": [str(finding.get("category"))] if finding.get("category") else [],
        }

    def _finding_key(self, finding: Dict[str, Any]) -> str:
        if finding.get("fingerprint"):
            return str(finding["fingerprint"])
        name = str(finding.get("name") or "").strip().lower()
        affected = str(finding.get("affected_resource") or "").strip().lower()
        if name == "session cookie missing httponly":
            evidence = str(finding.get("evidence") or "")
            cookie_name = evidence.split(" cookie ", 1)[0].strip().lower()
            return f"{name}:{cookie_name}:{self._stable_path(affected or evidence)}"
        return f"{name}:{self._stable_path(affected or str(finding.get('evidence') or ''))}"

    def _stable_path(self, value: str) -> str:
        if not value:
            return ""
        parsed = urlparse(value)
        return parsed.path or value

    def _build_stats(self, findings: List[Dict[str, Any]], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        severities = Counter(f.get("severity", "Low") for f in findings)
        strong_findings = [f for f in findings if float(f.get("confidence", 0.0)) >= 0.75]
        return {
            "total_findings": len(findings),
            "critical_high": severities.get("Critical", 0) + severities.get("High", 0),
            "critical": severities.get("Critical", 0),
            "high": severities.get("High", 0),
            "medium": severities.get("Medium", 0),
            "low": severities.get("Low", 0),
            "actions": len(history),
            "confirmed_or_strong": len(strong_findings),
        }

    def _build_category_summary(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        counts = Counter()
        for finding in findings:
            categories = finding.get("categories") or ["General"]
            counts[categories[0]] += 1
        rows = [{"category": category, "count": count} for category, count in counts.items()]
        rows.sort(key=lambda row: (-row["count"], row["category"]))
        return rows

    def _build_tool_summary(self, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        counts: Dict[str, Dict[str, Any]] = {}
        for action in history:
            tool = action.get("tool", "unknown")
            info = counts.setdefault(tool, {"tool": tool, "count": 0, "errors": 0})
            info["count"] += 1
            if "error" in (action.get("result") or {}):
                info["errors"] += 1
        rows = list(counts.values())
        rows.sort(key=lambda row: (-row["count"], row["tool"]))
        return rows

    def _build_coverage(self, history: List[Dict[str, Any]]) -> List[str]:
        coverage = []
        seen = set()
        for action in history:
            params = action.get("params", {})
            path = params.get("path")
            stable_path = self._stable_path(str(path or ""))
            if stable_path and stable_path not in seen:
                seen.add(stable_path)
                coverage.append(stable_path)
        return coverage

    def _build_coverage_gaps(self, history: List[Dict[str, Any]]) -> List[str]:
        covered = set(self._build_coverage(history))
        return [route for route in WEBAPP_ROUTE_HINTS if route not in covered]

    def _safe_name(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value)

    def _pick_longer(self, current: str, new_value: str) -> str:
        current = str(current or "").strip()
        new_value = str(new_value or "").strip()
        return new_value if len(new_value) > len(current) else current

    def _confidence_label(self, value: float) -> str:
        for threshold, label in CONFIDENCE_LABELS:
            if value >= threshold:
                return label
        return "Tentative"

    def _fallback_summary(self, findings: List[Dict[str, Any]], history: List[Dict[str, Any]]) -> str:
        total = len(findings)
        strong_findings = [f for f in findings if float(f.get("confidence", 0.0)) >= 0.75]
        high = len([f for f in strong_findings if f.get("severity") in {"Critical", "High"}])
        coverage = self._build_coverage(history)
        priority_pool = strong_findings or findings
        top_names = ", ".join(f["name"] for f in priority_pool[:3]) if priority_pool else "no confirmed issues"
        return (
            f"The assessment executed {len(history)} actions and produced {total} curated findings, including {high} strong-confidence Critical or High issues. "
            f"The most important validated results were {top_names}. "
            f"Observed route coverage included {', '.join(coverage[:6]) if coverage else 'no recorded web routes'}, and any routes listed later as coverage gaps should be revisited in a follow-up pass."
        )
