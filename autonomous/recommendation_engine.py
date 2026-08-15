#!/usr/bin/env python3
"""
Coreline Autonomous Recommendation Engine

Maps forensic indicators to actionable containment scripts.

Generates precise remediation steps based on:
- MITRE ATT&CK tactics
- Finding severity
- Asset criticality
- Attack progression

All high-priority actions require enclave signature for authorization.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ActionPriority(str, Enum):
    """Recommendation priority levels"""
    IMMEDIATE = "IMMEDIATE"      # Critical threats requiring immediate action
    HIGH = "HIGH"                # High-risk findings
    MEDIUM = "MEDIUM"            # Moderate risk
    LOW = "LOW"                  # Informational
    MONITOR = "MONITOR"          # Watch and wait


class ContainmentAction(str, Enum):
    """Standard containment actions"""
    ISOLATE_SYSTEM = "ISOLATE_SYSTEM"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    BLOCK_NETWORK = "BLOCK_NETWORK"
    REMOVE_PERSISTENCE = "REMOVE_PERSISTENCE"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    COLLECT_FORENSICS = "COLLECT_FORENSICS"
    MONITOR = "MONITOR"


@dataclass
class RemediationRecommendation:
    """Structured remediation recommendation"""
    priority: ActionPriority
    action: ContainmentAction
    target: str
    rationale: str
    mitre_tactic: Optional[str]
    requires_signature: bool
    automation_script: Optional[str] = None
    rollback_procedure: Optional[str] = None


class RecommendationEngine:
    """
    Autonomous recommendation engine.

    Maps forensic findings to actionable containment procedures.
    """

    # MITRE Tactics → Recommended Actions
    MITRE_ACTION_MAP = {
        "TA0001": ContainmentAction.BLOCK_NETWORK,      # Initial Access
        "TA0002": ContainmentAction.TERMINATE_PROCESS,  # Execution
        "TA0003": ContainmentAction.REMOVE_PERSISTENCE, # Persistence
        "TA0004": ContainmentAction.REVOKE_CREDENTIALS, # Privilege Escalation
        "TA0005": ContainmentAction.DISABLE_ACCOUNT,    # Defense Evasion
        "TA0006": ContainmentAction.REVOKE_CREDENTIALS, # Credential Access
        "TA0007": ContainmentAction.COLLECT_FORENSICS,  # Discovery
        "TA0008": ContainmentAction.ISOLATE_SYSTEM,     # Lateral Movement
        "TA0009": ContainmentAction.COLLECT_FORENSICS,  # Collection
        "TA0010": ContainmentAction.BLOCK_NETWORK,      # Exfiltration
        "TA0011": ContainmentAction.ISOLATE_SYSTEM,     # Command and Control
        "TA0040": ContainmentAction.ISOLATE_SYSTEM,     # Impact
    }

    def __init__(self):
        """Initialize recommendation engine"""
        self.recommendations: List[RemediationRecommendation] = []

    def generate_recommendations(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[RemediationRecommendation]:
        """
        Generate containment recommendations from findings.

        Args:
            findings: List of forensic findings

        Returns:
            Prioritized list of recommendations
        """
        recommendations = []

        for finding in findings:
            rec = self._map_finding_to_action(finding)
            if rec:
                recommendations.append(rec)

        # Sort by priority
        priority_order = {
            ActionPriority.IMMEDIATE: 0,
            ActionPriority.HIGH: 1,
            ActionPriority.MEDIUM: 2,
            ActionPriority.LOW: 3,
            ActionPriority.MONITOR: 4
        }
        recommendations.sort(key=lambda x: priority_order[x.priority])

        self.recommendations = recommendations
        return recommendations

    def _map_finding_to_action(self, finding: Dict[str, Any]) -> Optional[RemediationRecommendation]:
        """
        Map individual finding to containment action.

        Args:
            finding: Forensic finding

        Returns:
            Remediation recommendation or None
        """
        severity = finding.get("severity", "Low")
        mitre_tactic = finding.get("mitre_tactic")
        artifact_type = finding.get("artifact_type", "unknown")
        evidence = finding.get("evidence", "")

        # Determine priority from severity
        priority = self._severity_to_priority(severity)

        # Determine action from MITRE tactic or artifact type
        if mitre_tactic:
            # Extract tactic ID (e.g., "TA0003" from "TA0003 - Persistence")
            tactic_id = mitre_tactic.split(" ")[0] if " " in mitre_tactic else mitre_tactic
            action = self.MITRE_ACTION_MAP.get(tactic_id, ContainmentAction.COLLECT_FORENSICS)
        else:
            action = self._infer_action_from_artifact(artifact_type, evidence)

        # Determine if signature required (IMMEDIATE or HIGH priority)
        requires_signature = priority in [ActionPriority.IMMEDIATE, ActionPriority.HIGH]

        # Generate automation script (if applicable)
        automation_script = self._generate_automation_script(action, finding)

        # Generate rollback procedure
        rollback = self._generate_rollback(action)

        return RemediationRecommendation(
            priority=priority,
            action=action,
            target=artifact_type,
            rationale=evidence[:200],  # Truncate for readability
            mitre_tactic=mitre_tactic,
            requires_signature=requires_signature,
            automation_script=automation_script,
            rollback_procedure=rollback
        )

    def _severity_to_priority(self, severity: str) -> ActionPriority:
        """Map severity to priority"""
        severity_map = {
            "Critical": ActionPriority.IMMEDIATE,
            "High": ActionPriority.HIGH,
            "Medium": ActionPriority.MEDIUM,
            "Low": ActionPriority.LOW
        }
        return severity_map.get(severity, ActionPriority.MONITOR)

    def _infer_action_from_artifact(self, artifact_type: str, evidence: str) -> ContainmentAction:
        """Infer action from artifact type and evidence"""

        evidence_lower = evidence.lower()

        # Process-based indicators
        if artifact_type == "process_tree":
            if "powershell" in evidence_lower or "cmd.exe" in evidence_lower:
                return ContainmentAction.TERMINATE_PROCESS
            return ContainmentAction.COLLECT_FORENSICS

        # Persistence indicators
        if artifact_type == "scheduled_tasks" or "persistence" in evidence_lower:
            return ContainmentAction.REMOVE_PERSISTENCE

        # Network indicators
        if artifact_type == "network_connections" or "c2" in evidence_lower:
            return ContainmentAction.BLOCK_NETWORK

        # Credential indicators
        if "credential" in evidence_lower or "password" in evidence_lower:
            return ContainmentAction.REVOKE_CREDENTIALS

        # Default
        return ContainmentAction.COLLECT_FORENSICS

    def _generate_automation_script(
        self,
        action: ContainmentAction,
        finding: Dict[str, Any]
    ) -> Optional[str]:
        """
        Generate automation script for action.

        Args:
            action: Containment action
            finding: Forensic finding

        Returns:
            PowerShell/Bash script or None
        """

        if action == ContainmentAction.TERMINATE_PROCESS:
            return f"""# Terminate suspicious process
# Target: {finding.get('artifact_type')}
# Evidence: {finding.get('evidence', '')[:100]}

# Windows
taskkill /F /IM powershell.exe

# Linux
pkill -9 powershell
"""

        elif action == ContainmentAction.ISOLATE_SYSTEM:
            return """# Isolate system from network
# WARNING: This will disconnect the system

# Windows
netsh interface set interface \"Ethernet\" admin=disable

# Linux
sudo ifconfig eth0 down
"""

        elif action == ContainmentAction.REMOVE_PERSISTENCE:
            return f"""# Remove persistence mechanism
# Target: {finding.get('artifact_type')}

# Windows - Remove scheduled task
schtasks /Delete /TN "suspicious_task" /F

# Remove autorun registry key
reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "suspicious_entry" /f
"""

        elif action == ContainmentAction.BLOCK_NETWORK:
            return """# Block network communication
# Add firewall rule to block C2 traffic

# Windows
netsh advfirewall firewall add rule name="Block C2" dir=out action=block remoteip=1.2.3.4

# Linux
sudo iptables -A OUTPUT -d 1.2.3.4 -j DROP
"""

        return None

    def _generate_rollback(self, action: ContainmentAction) -> Optional[str]:
        """Generate rollback procedure for action"""

        rollback_map = {
            ContainmentAction.ISOLATE_SYSTEM: "Re-enable network interface: netsh interface set interface \"Ethernet\" admin=enable",
            ContainmentAction.BLOCK_NETWORK: "Remove firewall rule: netsh advfirewall firewall delete rule name=\"Block C2\"",
            ContainmentAction.DISABLE_ACCOUNT: "Re-enable account: net user <username> /active:yes",
            ContainmentAction.TERMINATE_PROCESS: "Restart service if needed: net start <service>",
        }

        return rollback_map.get(action)

    def export_runbook(self) -> str:
        """
        Export recommendations as markdown runbook.

        Returns:
            Formatted markdown runbook
        """
        runbook = "# Incident Response Runbook\n\n"
        runbook += f"**Generated**: {self._timestamp()}\n\n"
        runbook += "## Containment Recommendations\n\n"

        for i, rec in enumerate(self.recommendations, 1):
            runbook += f"### {i}. {rec.action.value}\n\n"
            runbook += f"**Priority**: {rec.priority.value}\n\n"
            runbook += f"**Target**: {rec.target}\n\n"
            runbook += f"**Rationale**: {rec.rationale}\n\n"

            if rec.mitre_tactic:
                runbook += f"**MITRE Tactic**: {rec.mitre_tactic}\n\n"

            if rec.requires_signature:
                runbook += "⚠️  **Requires cryptographic signature for authorization**\n\n"

            if rec.automation_script:
                runbook += "**Automation Script**:\n```bash\n"
                runbook += rec.automation_script
                runbook += "\n```\n\n"

            if rec.rollback_procedure:
                runbook += f"**Rollback**: {rec.rollback_procedure}\n\n"

            runbook += "---\n\n"

        return runbook

    def _timestamp(self) -> str:
        """Get current timestamp (timezone-aware UTC)"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


# Module exports
__all__ = [
    "RecommendationEngine",
    "RemediationRecommendation",
    "ActionPriority",
    "ContainmentAction"
]
