"""Execute explicitly approved XDR response commands on this Windows endpoint."""
import ipaddress
import subprocess

import psutil


def _powershell(script: str) -> None:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError((completed.stderr or completed.stdout or "Windows Firewall command failed").strip())


def execute(command: dict, xdr_host: str) -> str:
    action, target = command["action"], command["target"]
    request_id = command["request_id"]
    rule_name = "DATN-XDR-" + request_id

    if action == "kill_process":
        pid = int(target["process_id"])
        if pid <= 4:
            raise ValueError("Refusing to terminate a protected system PID")
        process = psutil.Process(pid)
        process.terminate()
        process.wait(timeout=5)
        return f"Terminated process PID {pid}"

    if action == "block_ip":
        address = str(ipaddress.ip_address(target["ip_address"]))
        safe_ip = "[System.Net.IPAddress]::Parse('" + address + "')"
        _powershell(
            f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound "
            f"-Action Block -RemoteAddress {safe_ip} -Profile Any | Out-Null; "
            f"New-NetFirewallRule -DisplayName '{rule_name}-in' -Direction Inbound "
            f"-Action Block -RemoteAddress {safe_ip} -Profile Any | Out-Null"
        )
        return f"Blocked {address} inbound and outbound with Windows Firewall"

    if action == "isolate_host" and target.get("operation") == "restore":
        _powershell(
            "$path = Join-Path $env:ProgramData 'DATN-XDR\\firewall-policy.json'; "
            "if (-not (Test-Path $path)) { throw 'No saved firewall policy was found' }; "
            "$saved = Get-Content $path -Raw | ConvertFrom-Json; "
            "foreach ($profile in $saved) { Set-NetFirewallProfile -Profile $profile.Name "
            "-DefaultInboundAction $profile.DefaultInboundAction "
            "-DefaultOutboundAction $profile.DefaultOutboundAction }; "
            "Get-NetFirewallRule -Group 'DATN-XDR-Isolation' -ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule; Remove-Item $path -Force"
        )
        return "Restored saved Windows Firewall profile and removed XDR isolation rules"

    if action == "isolate_host":
        # Default outbound blocking preserves the management connection only.
        xdr_ip = __import__("socket").gethostbyname(xdr_host)
        _powershell(
            "$dir = Join-Path $env:ProgramData 'DATN-XDR'; New-Item -ItemType Directory -Force $dir | Out-Null; "
            "$backup = Join-Path $dir 'firewall-policy.json'; "
            "if (-not (Test-Path $backup)) { Get-NetFirewallProfile | "
            "Select-Object Name,DefaultInboundAction,DefaultOutboundAction | "
            "ConvertTo-Json | Set-Content -Encoding UTF8 $backup }; "
            f"Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block "
            f"-DefaultOutboundAction Block; "
            f"New-NetFirewallRule -DisplayName '{rule_name}-management' -Direction Outbound "
            f"-Action Allow -RemoteAddress '{xdr_ip}' -Profile Any -Group 'DATN-XDR-Isolation' | Out-Null"
        )
        return f"Isolated host; outbound management access to XDR ({xdr_ip}) remains allowed"

    raise ValueError(f"Unsupported response action: {action}")
