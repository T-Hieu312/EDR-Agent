import re
from typing import Any, Dict, Iterable, List, Optional


def _normalize(text: Optional[str]) -> str:
    if not text:
        return ""
    return str(text).lower()


def _collect_network_indicators(network_connections: Optional[Iterable[Dict[str, Any]]]) -> List[str]:
    indicators: List[str] = []
    if not network_connections:
        return indicators

    for conn in network_connections:
        remote = conn.get("remote_address")
        if not remote:
            continue
        if remote.startswith("127.") or remote.startswith("::1"):
            continue
        indicators.append("external-connection")
        break

    return indicators


def detect_ioc(
    process_name: Optional[str] = None,
    command_line: Optional[str] = "",
    parent_name: Optional[str] = "",
    network_connections: Optional[Iterable[Dict[str, Any]]] = None,
    event_data: Optional[Any] = None,
) -> Dict[str, Any]:
    """Phân tích IOC cơ bản cho một process."""
    text = " ".join(
        filter(
            None,
            [
                process_name,
                command_line,
                parent_name,
                str(event_data) if event_data else "",
            ],
        )
    )
    normalized = _normalize(text)

    matched_iocs = set()

    if "powershell" in normalized:
        matched_iocs.add("powershell")
    if "rundll32" in normalized:
        matched_iocs.add("rundll32")
    if "wmic" in normalized:
        matched_iocs.add("wmic")
    if "certutil" in normalized:
        matched_iocs.add("certutil")
    if "bitsadmin" in normalized:
        matched_iocs.add("bitsadmin")
    if "regsvr32" in normalized:
        matched_iocs.add("regsvr32")
    if "schtasks" in normalized:
        matched_iocs.add("schtasks")
    if "curl" in normalized or "wget" in normalized:
        matched_iocs.add("download")
    if "http://" in normalized or "https://" in normalized:
        matched_iocs.add("network-download")
    if re.search(r"(?i)(-enc|-encodedcommand|base64|downloadstring|invoke-webrequest)", command_line or ""):
        matched_iocs.add("encoded-powershell")

    for indicator in _collect_network_indicators(network_connections):
        matched_iocs.add(indicator)

    risk_score = 0
    if "powershell" in matched_iocs:
        risk_score += 20
    if "download" in matched_iocs or "network-download" in matched_iocs:
        risk_score += 25
    if "encoded-powershell" in matched_iocs:
        risk_score += 25
    if "external-connection" in matched_iocs:
        risk_score += 15
    if "rundll32" in matched_iocs or "regsvr32" in matched_iocs:
        risk_score += 20

    risk_score = min(risk_score, 100)
    suspicious = risk_score >= 35 or bool(matched_iocs)

    return {
        "suspicious": suspicious,
        "risk_score": risk_score,
        "matched_iocs": sorted(matched_iocs),
    }
