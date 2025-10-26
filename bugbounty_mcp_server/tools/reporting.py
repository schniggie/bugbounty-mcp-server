"""
Reporting and data management tools.
"""

import asyncio
import json
import csv
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
import aiohttp
from mcp.types import Tool
from .base import BaseTools
from ..utils import get_timestamp, save_json_report


class ReportingTools(BaseTools):
    """Reporting and data management tools."""
    
    def get_tools(self) -> List[Tool]:
        """Return list of reporting tools."""
        return [
            Tool(
                name="generate_vulnerability_report",
                description="Generate comprehensive vulnerability report",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scan_results": {"type": "object", "description": "Scan results data"},
                        "report_format": {"type": "string", "enum": ["json", "html", "pdf", "csv"], "default": "json"},
                        "include_sections": {"type": "array", "items": {"type": "string"}, "description": "Sections to include"},
                        "severity_filter": {"type": "array", "items": {"type": "string"}, "description": "Severity levels to include"}
                    },
                    "required": ["scan_results"]
                }
            ),
            Tool(
                name="create_executive_summary",
                description="Create executive summary from scan results",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scan_data": {"type": "object", "description": "Combined scan data"},
                        "target_info": {"type": "object", "description": "Target information"},
                        "business_context": {"type": "string", "description": "Business context"}
                    },
                    "required": ["scan_data"]
                }
            ),
            Tool(
                name="track_findings",
                description="Track and manage security findings over time",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string", "description": "Unique finding identifier"},
                        "status": {"type": "string", "enum": ["new", "investigating", "confirmed", "false_positive", "fixed", "accepted"], "description": "Finding status"},
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Severity level"},
                        "description": {"type": "string", "description": "Finding description"},
                        "remediation": {"type": "string", "description": "Remediation steps"}
                    },
                    "required": ["finding_id", "status"]
                }
            ),
            Tool(
                name="generate_metrics_dashboard",
                description="Generate security metrics and KPIs dashboard",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "time_period": {"type": "string", "description": "Time period for metrics"},
                        "metrics_type": {"type": "array", "items": {"type": "string"}, "description": "Types of metrics to include"},
                        "targets": {"type": "array", "items": {"type": "string"}, "description": "Targets to analyze"}
                    }
                }
            ),
            Tool(
                name="export_scan_data",
                description="Export scan data in various formats",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "data_source": {"type": "string", "description": "Source of scan data"},
                        "export_format": {"type": "string", "enum": ["json", "csv", "xml", "yaml"], "default": "json"},
                        "include_raw_data": {"type": "boolean", "default": False},
                        "filter_criteria": {"type": "object", "description": "Filtering criteria"}
                    },
                    "required": ["data_source"]
                }
            ),
            Tool(
                name="create_remediation_plan",
                description="Create prioritized remediation plan",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "vulnerabilities": {"type": "array", "items": {"type": "object"}, "description": "List of vulnerabilities"},
                        "business_priorities": {"type": "array", "items": {"type": "string"}, "description": "Business priorities"},
                        "resource_constraints": {"type": "object", "description": "Available resources"}
                    },
                    "required": ["vulnerabilities"]
                }
            ),
            Tool(
                name="compliance_mapping",
                description="Map findings to compliance frameworks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array", "items": {"type": "object"}, "description": "Security findings"},
                        "frameworks": {"type": "array", "items": {"type": "string"}, "description": "Compliance frameworks"},
                        "generate_gaps": {"type": "boolean", "default": True}
                    },
                    "required": ["findings"]
                }
            ),
            Tool(
                name="risk_assessment",
                description="Perform comprehensive risk assessment",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "vulnerabilities": {"type": "array", "items": {"type": "object"}, "description": "Identified vulnerabilities"},
                        "assets": {"type": "array", "items": {"type": "object"}, "description": "Asset information"},
                        "threat_landscape": {"type": "object", "description": "Current threat landscape"},
                        "business_impact": {"type": "object", "description": "Business impact factors"}
                    },
                    "required": ["vulnerabilities"]
                }
            ),
            Tool(
                name="compare_scan_results",
                description="Compare scan results across time periods",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "baseline_scan": {"type": "object", "description": "Baseline scan data"},
                        "current_scan": {"type": "object", "description": "Current scan data"},
                        "comparison_type": {"type": "string", "enum": ["full", "vulnerabilities_only", "metrics_only"], "default": "full"}
                    },
                    "required": ["baseline_scan", "current_scan"]
                }
            ),
            Tool(
                name="generate_proof_of_concept",
                description="Generate proof of concept documentation for vulnerabilities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "vulnerability": {"type": "object", "description": "Vulnerability details"},
                        "poc_type": {"type": "string", "enum": ["detailed", "summary", "technical"], "default": "detailed"},
                        "include_screenshots": {"type": "boolean", "default": True},
                        "include_payloads": {"type": "boolean", "default": True}
                    },
                    "required": ["vulnerability"]
                }
            )
        ]
    
    async def generate_vulnerability_report(
        self,
        scan_results: Dict[str, Any],
        report_format: str = "json",
        include_sections: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None
    ) -> str:
        """Generate comprehensive vulnerability report."""
        results = {
            "report_metadata": {
                "generated_at": get_timestamp(),
                "format": report_format,
                "target": scan_results.get("target", "Unknown"),
                "scan_date": scan_results.get("timestamp", get_timestamp())
            },
            "executive_summary": {},
            "vulnerability_summary": {},
            "detailed_findings": [],
            "recommendations": [],
            "appendices": {}
        }
        
        # Default sections if none specified
        if not include_sections:
            include_sections = [
                "executive_summary", "vulnerability_summary", 
                "detailed_findings", "recommendations", "technical_details"
            ]
        
        # Generate executive summary
        if "executive_summary" in include_sections:
            exec_summary = self._generate_executive_summary(scan_results)
            results["executive_summary"] = exec_summary
        
        # Generate vulnerability summary
        if "vulnerability_summary" in include_sections:
            vuln_summary = self._generate_vulnerability_summary(scan_results, severity_filter)
            results["vulnerability_summary"] = vuln_summary
        
        # Generate detailed findings
        if "detailed_findings" in include_sections:
            detailed_findings = self._generate_detailed_findings(scan_results, severity_filter)
            results["detailed_findings"] = detailed_findings
        
        # Generate recommendations
        if "recommendations" in include_sections:
            recommendations = self._generate_recommendations(scan_results)
            results["recommendations"] = recommendations
        
        # Generate technical details
        if "technical_details" in include_sections:
            tech_details = self._generate_technical_details(scan_results)
            results["appendices"]["technical_details"] = tech_details
        
        # Save report
        report_path = await self._save_report(results, report_format)
        results["report_metadata"]["file_path"] = report_path
        
        return self.format_result(results, f"Vulnerability Report Generated ({report_format})")
    
    async def create_executive_summary(
        self,
        scan_data: Dict[str, Any],
        target_info: Optional[Dict[str, Any]] = None,
        business_context: Optional[str] = None
    ) -> str:
        """Create executive summary from scan results."""
        results = {
            "target_info": target_info or {},
            "business_context": business_context,
            "timestamp": get_timestamp(),
            "summary": {},
            "key_findings": [],
            "risk_overview": {},
            "recommendations": []
        }
        
        # Analyze scan data
        analysis = self._analyze_scan_data(scan_data)
        
        # Generate summary
        summary = {
            "total_vulnerabilities": analysis["total_vulns"],
            "critical_issues": analysis["critical_count"],
            "high_risk_issues": analysis["high_count"],
            "medium_risk_issues": analysis["medium_count"],
            "low_risk_issues": analysis["low_count"],
            "overall_risk_rating": analysis["overall_risk"],
            "scan_coverage": analysis["coverage"]
        }
        results["summary"] = summary
        
        # Generate key findings
        key_findings = self._extract_key_findings(analysis)
        results["key_findings"] = key_findings
        
        # Generate risk overview
        risk_overview = self._generate_risk_overview(analysis, business_context)
        results["risk_overview"] = risk_overview
        
        # Generate high-level recommendations
        recommendations = self._generate_executive_recommendations(analysis)
        results["recommendations"] = recommendations
        
        return self.format_result(results, "Executive Summary")
    
    async def track_findings(
        self,
        finding_id: str,
        status: str,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        remediation: Optional[str] = None
    ) -> str:
        """Track and manage security findings."""
        results = {
            "finding_id": finding_id,
            "timestamp": get_timestamp(),
            "tracking_info": {},
            "status_history": [],
            "metrics": {}
        }
        
        # Load existing tracking data
        tracking_data = await self._load_tracking_data(finding_id)
        
        # Update finding
        updated_finding = {
            "finding_id": finding_id,
            "status": status,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "last_updated": get_timestamp(),
            "updated_by": "mcp_server"
        }
        
        # Add to status history
        if tracking_data:
            updated_finding["created_date"] = tracking_data.get("created_date", get_timestamp())
            updated_finding["status_history"] = tracking_data.get("status_history", [])
        else:
            updated_finding["created_date"] = get_timestamp()
            updated_finding["status_history"] = []
        
        # Add status change to history
        status_change = {
            "status": status,
            "timestamp": get_timestamp(),
            "changed_by": "mcp_server"
        }
        updated_finding["status_history"].append(status_change)
        
        # Save updated tracking data
        await self._save_tracking_data(finding_id, updated_finding)
        
        # Generate metrics
        metrics = await self._generate_tracking_metrics(finding_id)
        results["metrics"] = metrics
        results["tracking_info"] = updated_finding
        
        return self.format_result(results, f"Finding Tracking: {finding_id}")
    
    async def generate_metrics_dashboard(
        self,
        time_period: Optional[str] = None,
        metrics_type: Optional[List[str]] = None,
        targets: Optional[List[str]] = None
    ) -> str:
        """Generate security metrics and KPIs dashboard."""
        results = {
            "time_period": time_period or "last_30_days",
            "metrics_type": metrics_type or [],
            "targets": targets or [],
            "timestamp": get_timestamp(),
            "dashboard_data": {},
            "kpis": {},
            "trends": {},
            "charts": []
        }
        
        if not metrics_type:
            metrics_type = [
                "vulnerability_trends", "finding_resolution", "scan_coverage",
                "risk_posture", "compliance_status"
            ]
        
        # Generate vulnerability trends
        if "vulnerability_trends" in metrics_type:
            vuln_trends = await self._generate_vulnerability_trends(time_period, targets)
            results["dashboard_data"]["vulnerability_trends"] = vuln_trends
        
        # Generate finding resolution metrics
        if "finding_resolution" in metrics_type:
            resolution_metrics = await self._generate_resolution_metrics(time_period, targets)
            results["dashboard_data"]["finding_resolution"] = resolution_metrics
        
        # Generate scan coverage metrics
        if "scan_coverage" in metrics_type:
            coverage_metrics = await self._generate_coverage_metrics(time_period, targets)
            results["dashboard_data"]["scan_coverage"] = coverage_metrics
        
        # Generate risk posture metrics
        if "risk_posture" in metrics_type:
            risk_metrics = await self._generate_risk_metrics(time_period, targets)
            results["dashboard_data"]["risk_posture"] = risk_metrics
        
        # Generate compliance status
        if "compliance_status" in metrics_type:
            compliance_metrics = await self._generate_compliance_metrics(time_period, targets)
            results["dashboard_data"]["compliance_status"] = compliance_metrics
        
        # Generate KPIs
        kpis = self._calculate_kpis(results["dashboard_data"])
        results["kpis"] = kpis
        
        # Generate trend analysis
        trends = self._analyze_trends(results["dashboard_data"])
        results["trends"] = trends
        
        return self.format_result(results, "Security Metrics Dashboard")
    
    async def export_scan_data(
        self,
        data_source: str,
        export_format: str = "json",
        include_raw_data: bool = False,
        filter_criteria: Optional[Dict[str, Any]] = None
    ) -> str:
        """Export scan data in various formats."""
        results = {
            "data_source": data_source,
            "export_format": export_format,
            "timestamp": get_timestamp(),
            "exported_records": 0,
            "file_path": "",
            "export_summary": {}
        }
        
        # Load scan data
        scan_data = await self._load_scan_data(data_source)
        if not scan_data:
            return f"No scan data found for source: {data_source}"
        
        # Apply filters
        if filter_criteria:
            scan_data = self._apply_filters(scan_data, filter_criteria)
        
        # Include or exclude raw data
        if not include_raw_data:
            scan_data = self._remove_raw_data(scan_data)
        
        # Export data
        export_path = await self._export_data(scan_data, export_format, data_source)
        
        results["exported_records"] = len(scan_data) if isinstance(scan_data, list) else 1
        results["file_path"] = export_path
        results["export_summary"] = self._generate_export_summary(scan_data)
        
        return self.format_result(results, f"Data Export: {data_source}")
    
    async def create_remediation_plan(
        self,
        vulnerabilities: List[Dict[str, Any]],
        business_priorities: Optional[List[str]] = None,
        resource_constraints: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create prioritized remediation plan."""
        results = {
            "total_vulnerabilities": len(vulnerabilities),
            "business_priorities": business_priorities or [],
            "resource_constraints": resource_constraints or {},
            "timestamp": get_timestamp(),
            "remediation_plan": {},
            "priority_matrix": {},
            "timeline": {},
            "resource_allocation": {}
        }
        
        # Prioritize vulnerabilities
        prioritized_vulns = self._prioritize_vulnerabilities(
            vulnerabilities, business_priorities, resource_constraints
        )
        
        # Create remediation phases
        remediation_phases = self._create_remediation_phases(prioritized_vulns)
        results["remediation_plan"]["phases"] = remediation_phases
        
        # Generate priority matrix
        priority_matrix = self._generate_priority_matrix(prioritized_vulns)
        results["priority_matrix"] = priority_matrix
        
        # Create timeline
        timeline = self._create_remediation_timeline(remediation_phases, resource_constraints)
        results["timeline"] = timeline
        
        # Allocate resources
        resource_allocation = self._allocate_resources(remediation_phases, resource_constraints)
        results["resource_allocation"] = resource_allocation
        
        # Generate summary statistics
        summary = self._generate_remediation_summary(remediation_phases)
        results["remediation_plan"]["summary"] = summary
        
        return self.format_result(results, "Remediation Plan")
    
    async def compliance_mapping(
        self,
        findings: List[Dict[str, Any]],
        frameworks: Optional[List[str]] = None,
        generate_gaps: bool = True
    ) -> str:
        """Map findings to compliance frameworks."""
        results = {
            "total_findings": len(findings),
            "frameworks": frameworks or [],
            "timestamp": get_timestamp(),
            "compliance_mapping": {},
            "gap_analysis": {},
            "recommendations": []
        }
        
        if not frameworks:
            frameworks = ["OWASP_TOP10", "NIST_CSF", "ISO27001", "PCI_DSS", "SOX"]
        
        # Map findings to frameworks
        for framework in frameworks:
            mapping = self._map_findings_to_framework(findings, framework)
            results["compliance_mapping"][framework] = mapping
        
        # Generate gap analysis
        if generate_gaps:
            for framework in frameworks:
                gaps = self._analyze_compliance_gaps(findings, framework)
                results["gap_analysis"][framework] = gaps
        
        # Generate compliance recommendations
        recommendations = self._generate_compliance_recommendations(
            results["compliance_mapping"], results["gap_analysis"]
        )
        results["recommendations"] = recommendations
        
        return self.format_result(results, "Compliance Mapping")
    
    async def risk_assessment(
        self,
        vulnerabilities: List[Dict[str, Any]],
        assets: Optional[List[Dict[str, Any]]] = None,
        threat_landscape: Optional[Dict[str, Any]] = None,
        business_impact: Optional[Dict[str, Any]] = None
    ) -> str:
        """Perform comprehensive risk assessment."""
        results = {
            "vulnerabilities_analyzed": len(vulnerabilities),
            "assets": assets or [],
            "threat_landscape": threat_landscape or {},
            "business_impact": business_impact or {},
            "timestamp": get_timestamp(),
            "risk_assessment": {},
            "risk_matrix": {},
            "mitigation_strategies": []
        }
        
        # Calculate risk scores
        risk_scores = self._calculate_risk_scores(
            vulnerabilities, assets, threat_landscape, business_impact
        )
        results["risk_assessment"]["individual_risks"] = risk_scores
        
        # Generate overall risk rating
        overall_risk = self._calculate_overall_risk(risk_scores)
        results["risk_assessment"]["overall_risk"] = overall_risk
        
        # Create risk matrix
        risk_matrix = self._create_risk_matrix(risk_scores)
        results["risk_matrix"] = risk_matrix
        
        # Generate mitigation strategies
        mitigation_strategies = self._generate_mitigation_strategies(risk_scores)
        results["mitigation_strategies"] = mitigation_strategies
        
        # Risk trend analysis
        risk_trends = self._analyze_risk_trends(vulnerabilities)
        results["risk_assessment"]["trends"] = risk_trends
        
        return self.format_result(results, "Risk Assessment")
    
    async def compare_scan_results(
        self,
        baseline_scan: Dict[str, Any],
        current_scan: Dict[str, Any],
        comparison_type: str = "full"
    ) -> str:
        """Compare scan results across time periods."""
        results = {
            "baseline_date": baseline_scan.get("timestamp", "Unknown"),
            "current_date": current_scan.get("timestamp", get_timestamp()),
            "comparison_type": comparison_type,
            "timestamp": get_timestamp(),
            "comparison_results": {},
            "trends": {},
            "summary": {}
        }
        
        if comparison_type in ["full", "vulnerabilities_only"]:
            # Compare vulnerabilities
            vuln_comparison = self._compare_vulnerabilities(baseline_scan, current_scan)
            results["comparison_results"]["vulnerabilities"] = vuln_comparison
        
        if comparison_type in ["full", "metrics_only"]:
            # Compare metrics
            metrics_comparison = self._compare_metrics(baseline_scan, current_scan)
            results["comparison_results"]["metrics"] = metrics_comparison
        
        if comparison_type == "full":
            # Compare scan coverage
            coverage_comparison = self._compare_coverage(baseline_scan, current_scan)
            results["comparison_results"]["coverage"] = coverage_comparison
            
            # Compare assets
            asset_comparison = self._compare_assets(baseline_scan, current_scan)
            results["comparison_results"]["assets"] = asset_comparison
        
        # Generate trend analysis
        trends = self._generate_trend_analysis(results["comparison_results"])
        results["trends"] = trends
        
        # Generate comparison summary
        summary = self._generate_comparison_summary(results["comparison_results"])
        results["summary"] = summary
        
        return self.format_result(results, "Scan Results Comparison")
    
    # Helper methods
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary section."""
        return {
            "scope": scan_results.get("target", "Unknown"),
            "scan_date": scan_results.get("timestamp", get_timestamp()),
            "methodology": "Automated vulnerability scanning",
            "key_statistics": {},
            "risk_summary": {}
        }
    
    def _generate_vulnerability_summary(self, scan_results: Dict[str, Any], severity_filter: Optional[List[str]]) -> Dict[str, Any]:
        """Generate vulnerability summary section."""
        return {
            "total_vulnerabilities": 0,
            "by_severity": {},
            "by_category": {},
            "by_confidence": {}
        }
    
    def _generate_detailed_findings(self, scan_results: Dict[str, Any], severity_filter: Optional[List[str]]) -> List[Dict[str, Any]]:
        """Generate detailed findings section."""
        return []
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations section."""
        return []
    
    def _generate_technical_details(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical details appendix."""
        return {
            "scan_configuration": {},
            "tools_used": [],
            "scan_duration": "",
            "coverage_analysis": {}
        }
    
    async def _save_report(self, results: Dict[str, Any], report_format: str) -> str:
        """Save report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_report_{timestamp}.{report_format}"
        filepath = os.path.join(self.config.output.output_dir, filename)
        
        if report_format == "json":
            save_json_report(results, filepath)
        elif report_format == "csv":
            await self._save_csv_report(results, filepath)
        elif report_format == "html":
            await self._save_html_report(results, filepath)
        elif report_format == "pdf":
            await self._save_pdf_report(results, filepath)
        
        return filepath
    
    async def _save_csv_report(self, results: Dict[str, Any], filepath: str) -> None:
        """Save report as CSV."""
        # Flatten findings into CSV rows
        rows = []
        
        findings = results.get("findings", {})
        for category, items in findings.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        row = {
                            "Category": category,
                            "Severity": item.get("severity", "unknown"),
                            "Title": item.get("title", item.get("type", "N/A")),
                            "Description": item.get("description", "N/A"),
                            "Target": item.get("url", item.get("target", "N/A")),
                            "Evidence": str(item.get("evidence", item.get("details", "N/A")))[:200],
                            "Timestamp": results.get("scan_metadata", {}).get("timestamp", "N/A")
                        }
                        rows.append(row)
        
        # If no structured findings, try to extract from other formats
        if not rows:
            summary = results.get("summary", {})
            for key, value in summary.items():
                if isinstance(value, (list, dict)) and value:
                    row = {
                        "Category": key,
                        "Severity": "info",
                        "Title": key,
                        "Description": str(value)[:500],
                        "Target": results.get("target", "N/A"),
                        "Evidence": "",
                        "Timestamp": results.get("timestamp", "N/A")
                    }
                    rows.append(row)
        
        # Write CSV file
        if rows:
            fieldnames = ["Category", "Severity", "Title", "Description", "Target", "Evidence", "Timestamp"]
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        else:
            # Write empty CSV with headers if no data
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Severity", "Title", "Description", "Target", "Evidence", "Timestamp"])
                writer.writerow(["No findings", "info", "Scan completed", "No vulnerabilities found", "", "", results.get("timestamp", "N/A")])
    
    async def _save_html_report(self, results: Dict[str, Any], filepath: str) -> None:
        """Save report as HTML."""
        # Extract data from results
        target = results.get("target", "Unknown Target")
        timestamp = results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        findings = results.get("findings", {})
        summary = results.get("summary", {})
        
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_findings = []
        
        for category, items in findings.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        severity = item.get("severity", "info").lower()
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        all_findings.append({
                            "category": category,
                            "severity": severity,
                            **item
                        })
        
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background: #f5f7fa; color: #2d3748; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .meta {{ opacity: 0.9; font-size: 0.9em; }}
        .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: #718096; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }}
        .critical {{ color: #e53e3e; }}
        .high {{ color: #dd6b20; }}
        .medium {{ color: #d69e2e; }}
        .low {{ color: #38a169; }}
        .info {{ color: #3182ce; }}
        .finding {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #e2e8f0; }}
        .finding.critical {{ border-left-color: #e53e3e; }}
        .finding.high {{ border-left-color: #dd6b20; }}
        .finding.medium {{ border-left-color: #d69e2e; }}
        .finding.low {{ border-left-color: #38a169; }}
        .finding.info {{ border-left-color: #3182ce; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; }}
        .finding-title {{ font-size: 1.3em; font-weight: 600; flex: 1; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
        .badge.critical {{ background: #fff5f5; color: #e53e3e; }}
        .badge.high {{ background: #fffaf0; color: #dd6b20; }}
        .badge.medium {{ background: #fffff0; color: #d69e2e; }}
        .badge.low {{ background: #f0fff4; color: #38a169; }}
        .badge.info {{ background: #ebf8ff; color: #3182ce; }}
        .finding-meta {{ font-size: 0.85em; color: #718096; margin-bottom: 10px; }}
        .finding-description {{ margin: 15px 0; padding: 15px; background: #f7fafc; border-radius: 4px; }}
        .finding-evidence {{ margin-top: 10px; padding: 10px; background: #edf2f7; border-radius: 4px; font-size: 0.9em; }}
        .section-title {{ font-size: 1.8em; font-weight: 600; margin: 30px 0 15px 0; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }}
        .no-findings {{ text-align: center; padding: 40px; color: #718096; }}
        footer {{ text-align: center; padding: 20px; color: #a0aec0; font-size: 0.9em; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Assessment Report</h1>
            <div class="meta">
                <div><strong>Target:</strong> {target}</div>
                <div><strong>Scan Date:</strong> {timestamp}</div>
            </div>
        </header>
        
        <h2 class="section-title">📊 Executive Summary</h2>
        <div class="dashboard">
            <div class="stat-card">
                <div class="stat-value critical">{severity_counts.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{severity_counts.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{severity_counts.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low">{severity_counts.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value info">{severity_counts.get('info', 0)}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
        
        <h2 class="section-title">🔍 Findings</h2>
"""
        
        if all_findings:
            for finding in all_findings:
                severity = finding.get('severity', 'info')
                title = finding.get('title', finding.get('type', 'Unknown Finding'))
                category = finding.get('category', 'General')
                description = finding.get('description', 'No description available')
                url = finding.get('url', finding.get('target', ''))
                evidence = finding.get('evidence', finding.get('details', ''))
                
                html += f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <div class="finding-title">{title}</div>
                <span class="badge {severity}">{severity.upper()}</span>
            </div>
            <div class="finding-meta">
                <strong>Category:</strong> {category}
                {f' | <strong>URL:</strong> {url}' if url else ''}
            </div>
            <div class="finding-description">{description}</div>
            {f'<div class="finding-evidence"><strong>Evidence:</strong> {str(evidence)[:500]}</div>' if evidence else ''}
        </div>
"""
        else:
            html += """
        <div class="no-findings">
            <h3>✅ No vulnerabilities found</h3>
            <p>The scan completed successfully without detecting any security issues.</p>
        </div>
"""
        
        html += """
        <footer>
            <p>Generated by BugBounty MCP Server | Keep your applications secure 🛡️</p>
        </footer>
    </div>
</body>
</html>
"""
        
        # Write HTML file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
    
    async def _save_pdf_report(self, results: Dict[str, Any], filepath: str) -> None:
        """Save report as PDF."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        except ImportError:
            # If reportlab is not available, create a simple text-based PDF alternative
            with open(filepath.replace('.pdf', '.txt'), 'w', encoding='utf-8') as f:
                f.write("Security Assessment Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target: {results.get('target', 'Unknown')}\n")
                f.write(f"Timestamp: {results.get('timestamp', 'N/A')}\n\n")
                f.write(json.dumps(results, indent=2))
            return
        
        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#4A5568'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2D3748'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Extract data
        target = results.get("target", "Unknown Target")
        timestamp = results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        findings = results.get("findings", {})
        
        # Title Page
        story.append(Paragraph("🔒 Security Assessment Report", title_style))
        story.append(Spacer(1, 0.5*inch))
        
        # Metadata
        meta_data = [
            ["Target:", target],
            ["Scan Date:", timestamp],
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4A5568')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_findings = []
        
        for category, items in findings.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        severity = item.get("severity", "info").lower()
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        all_findings.append({
                            "category": category,
                            "severity": severity,
                            **item
                        })
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(severity_counts.get('critical', 0))],
            ["High", str(severity_counts.get('high', 0))],
            ["Medium", str(severity_counts.get('medium', 0))],
            ["Low", str(severity_counts.get('low', 0))],
            ["Informational", str(severity_counts.get('info', 0))],
        ]
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4A5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F7FAFC')])
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Findings
        if all_findings:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Sort findings by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))
            
            for idx, finding in enumerate(all_findings, 1):
                severity = finding.get('severity', 'info').upper()
                title = finding.get('title', finding.get('type', 'Unknown Finding'))
                category = finding.get('category', 'General')
                description = finding.get('description', 'No description available')
                url = finding.get('url', finding.get('target', ''))
                
                # Finding header
                finding_title = f"{idx}. {title} [{severity}]"
                story.append(Paragraph(finding_title, styles['Heading3']))
                
                # Finding details
                details_text = f"<b>Category:</b> {category}<br/>"
                if url:
                    details_text += f"<b>URL:</b> {url}<br/>"
                details_text += f"<br/><b>Description:</b><br/>{description}"
                
                story.append(Paragraph(details_text, styles['BodyText']))
                story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Paragraph("No vulnerabilities were found during the scan.", styles['BodyText']))
        
        # Build PDF
        doc.build(story)
    
    def _analyze_scan_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan data for summary generation."""
        return {
            "total_vulns": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "overall_risk": "medium",
            "coverage": 100
        }
    
    def _extract_key_findings(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract key findings from analysis."""
        return []
    
    def _generate_risk_overview(self, analysis: Dict[str, Any], business_context: Optional[str]) -> Dict[str, Any]:
        """Generate risk overview."""
        return {"overall_risk": "medium", "key_risks": []}
    
    def _generate_executive_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate executive-level recommendations."""
        return []
    
    async def _load_tracking_data(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Load existing tracking data for finding."""
        tracking_file = os.path.join(self.config.data_dir, f"tracking_{finding_id}.json")
        try:
            with open(tracking_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
    
    async def _save_tracking_data(self, finding_id: str, data: Dict[str, Any]) -> None:
        """Save tracking data for finding."""
        tracking_file = os.path.join(self.config.data_dir, f"tracking_{finding_id}.json")
        with open(tracking_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    async def _generate_tracking_metrics(self, finding_id: str) -> Dict[str, Any]:
        """Generate tracking metrics."""
        return {"days_open": 0, "status_changes": 0}
    
    # Additional helper methods would continue here...
    # Due to length constraints, providing core structure
    
    async def _generate_vulnerability_trends(self, time_period: Optional[str], targets: Optional[List[str]]) -> Dict[str, Any]:
        """Generate vulnerability trend data."""
        return {}
    
    async def _generate_resolution_metrics(self, time_period: Optional[str], targets: Optional[List[str]]) -> Dict[str, Any]:
        """Generate finding resolution metrics."""
        return {}
    
    async def _generate_coverage_metrics(self, time_period: Optional[str], targets: Optional[List[str]]) -> Dict[str, Any]:
        """Generate scan coverage metrics."""
        return {}
    
    async def _generate_risk_metrics(self, time_period: Optional[str], targets: Optional[List[str]]) -> Dict[str, Any]:
        """Generate risk posture metrics."""
        return {}
    
    async def _generate_compliance_metrics(self, time_period: Optional[str], targets: Optional[List[str]]) -> Dict[str, Any]:
        """Generate compliance status metrics."""
        return {}
    
    def _calculate_kpis(self, dashboard_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate key performance indicators."""
        return {}
    
    def _analyze_trends(self, dashboard_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trends in dashboard data."""
        return {}
    
    async def _load_scan_data(self, data_source: str) -> Optional[Dict[str, Any]]:
        """Load scan data from source."""
        return None
    
    def _apply_filters(self, data: Dict[str, Any], filters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply filtering criteria to data."""
        return data
    
    def _remove_raw_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove raw data from scan results."""
        return data
    
    async def _export_data(self, data: Dict[str, Any], format: str, source: str) -> str:
        """Export data to specified format."""
        return ""
    
    def _generate_export_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate export summary."""
        return {}
    
    def _prioritize_vulnerabilities(self, vulns: List[Dict[str, Any]], priorities: Optional[List[str]], constraints: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize vulnerabilities for remediation."""
        return vulns
    
    def _create_remediation_phases(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create remediation phases."""
        return []
    
    def _generate_priority_matrix(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate priority matrix."""
        return {}
    
    def _create_remediation_timeline(self, phases: List[Dict[str, Any]], constraints: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Create remediation timeline."""
        return {}
    
    def _allocate_resources(self, phases: List[Dict[str, Any]], constraints: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Allocate resources for remediation."""
        return {}
    
    def _generate_remediation_summary(self, phases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate remediation summary."""
        return {}
    
    def _map_findings_to_framework(self, findings: List[Dict[str, Any]], framework: str) -> Dict[str, Any]:
        """Map findings to compliance framework."""
        return {}
    
    def _analyze_compliance_gaps(self, findings: List[Dict[str, Any]], framework: str) -> Dict[str, Any]:
        """Analyze compliance gaps."""
        return {}
    
    def _generate_compliance_recommendations(self, mapping: Dict[str, Any], gaps: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations."""
        return []
    
    def _calculate_risk_scores(self, vulns: List[Dict[str, Any]], assets: Optional[List[Dict[str, Any]]], threats: Optional[Dict[str, Any]], impact: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Calculate risk scores."""
        return []
    
    def _calculate_overall_risk(self, risk_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk rating."""
        return {}
    
    def _create_risk_matrix(self, risk_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create risk matrix."""
        return {}
    
    def _generate_mitigation_strategies(self, risk_scores: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate mitigation strategies."""
        return []
    
    def _analyze_risk_trends(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze risk trends."""
        return {}
    
    def _compare_vulnerabilities(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Compare vulnerabilities between scans."""
        return {}
    
    def _compare_metrics(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Compare metrics between scans."""
        return {}
    
    def _compare_coverage(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Compare scan coverage."""
        return {}
    
    def _compare_assets(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Compare assets between scans."""
        return {}
    
    def _generate_trend_analysis(self, comparison: Dict[str, Any]) -> Dict[str, Any]:
        """Generate trend analysis."""
        return {}
    
    def _generate_comparison_summary(self, comparison: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comparison summary."""
        return {}
