# Hướng dẫn test EDR Agent trên 1 máy Windows

Tài liệu này hướng dẫn chạy thử EDR Agent **trên một máy Windows duy nhất** (chưa cần dựng lab).
Agent và server giả lập chạy cùng máy, nói chuyện qua `localhost (127.0.0.1)`.

---

## 1. Các file cần dùng (để chung 1 thư mục, ví dụ `C:\edr-agent`)

| STT | File | Vai trò |
|---|---|---|
| 1 | `edr_agent.py` | Chạy chính — khởi động agent |
| 2 | `sysmon_collector.py` | Đọc sự kiện Sysmon từ Windows Event Log |
| 3 | `sender.py` | Gửi dữ liệu lên server, retry khi lỗi |
| 4 | `xdr_stub_server.py` | Server giả lập để nhận (đóng vai XDR server) |
| 5 | `config.yaml` | Cấu hình — giữ nguyên, không sửa khi test 1 máy |
| 6 | `requirements.txt` | Danh sách thư viện |

> Ba file 1–2–3 phải nằm **cùng thư mục** vì `edr_agent.py` gọi tới `sysmon_collector.py` và `sender.py`.
> Hai file `lab-proxmox-edr-xdr.md` và `README.md` chỉ là tài liệu, không cần cho test này.

---

## 2. Cài đặt (làm 1 lần)

### B1. Cài Python
- Tải Python 3.11 trở lên tại https://www.python.org/downloads/
- Khi cài, **tick vào "Add Python to PATH"**.
- Kiểm tra: mở PowerShell gõ `python --version` (hoặc `py --version`) phải ra số phiên bản.

### B2. Cài Sysmon (bắt buộc — agent đọc dữ liệu từ đây)
Mở **PowerShell quyền Administrator**, chạy:
```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```
Kiểm tra Sysmon đã chạy: mở **Event Viewer** → Applications and Services Logs → Microsoft → Windows → **Sysmon → Operational**. Gõ `whoami` trong cmd rồi F5, phải thấy sự kiện mới (Event ID 1) có `CommandLine` và `ParentImage`.

### B3. Cài thư viện Python
Mở PowerShell tại thư mục chứa code:
```powershell
cd C:\edr-agent
pip install -r requirements.txt
pip install flask
```
> Nếu `pip` báo không nhận lệnh, dùng `py -m pip install ...` thay cho `pip install ...`.

---

## 3. Chạy test (mở 2 cửa sổ PowerShell)

Hướng dẫn này dùng `xdr_stub_server.py` để test agent độc lập, không phải XDR thật. Trước khi chạy stub, sửa `sender.url` trong `config.yaml` thành:
```yaml
url: "http://127.0.0.1:8080/api/events"
```

### Cửa sổ 1 — Server giả lập (nơi nhận dữ liệu)
```powershell
cd C:\edr-agent
python xdr_stub_server.py
```
Màn hình đứng chờ, lắng nghe ở cổng `8080`. Giữ cửa sổ này mở.

### Cửa sổ 2 — EDR Agent
```powershell
cd C:\edr-agent
python edr_agent.py --config config.yaml
```
### Sinh dữ liệu để kiểm tra
Mở thêm một cửa sổ cmd, gõ vài lệnh hoặc mở vài ứng dụng:
```cmd
whoami
ipconfig
notepad
```

---

## 4. Kết quả đúng là như thế nào

- **Cửa sổ 1 (server)** in ra các dòng kiểu:
  ```
  [13:25:10] Nhận 3 event từ agent=DESKTOP-ABC
     - process_create: C:\Windows\System32\whoami.exe | cmd=whoami
  ```
- Trong thư mục xuất hiện file **`received_events.jsonl`** chứa dữ liệu server đã nhận.
- **Cửa sổ 2 (agent)** in log "Đã gửi N event tới XDR."

Nếu thấy như trên là **đạt** — agent thu thập được process/parent-child/command line và gửi thành công.

---

## 5. Test xử lý mất kết nối (chứng minh không mất dữ liệu)

1. Khi cả hai đang chạy, tắt **cửa sổ 1** (nhấn `Ctrl + C`) khoảng 30 giây.
2. Trong lúc đó vẫn mở vài ứng dụng để sinh event. Agent không gửi được sẽ cất vào file **`spool.jsonl`**.
3. Bật lại server: `python xdr_stub_server.py`.
4. Sau vài giây, agent tự gửi bù. Log báo "đã gửi hết hàng đợi đĩa" và `spool.jsonl` rỗng trở lại.

---

## 6. Dừng chương trình
Nhấn `Ctrl + C` ở từng cửa sổ. Agent sẽ cố gửi nốt dữ liệu còn lại trước khi thoát.

---

## 7. Lỗi thường gặp

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| `python`/`pip` không nhận lệnh | Chưa Add Python to PATH. Cài lại và tick, hoặc dùng `py -m pip`. |
| Agent báo thiếu `pywin32` | Chạy `pip install pywin32`. |
| Agent báo thiếu `yaml`/`requests` | Chạy `pip install -r requirements.txt` lại. |
| Server không nhận được gì | Kiểm tra Sysmon đã chạy chưa (Event Viewer). Sinh thêm tiến trình mới. |
| Lỗi kết nối cổng 8080 | Windows Firewall chặn — cho phép, hoặc tạm tắt firewall khi test. |
| `401 invalid agent key` | `agent_key` trong `config.yaml` phải khớp `AGENT_KEY` trong `xdr_stub_server.py` (mặc định đã khớp). |

---

## 8. Khi đưa vào lab thật (để sau)
Không chạy stub nữa; khởi chạy XDR thật theo `README.md` ở thư mục XDR. Đổi URL trong `config.yaml` thành:
```yaml
sender:
  url: "http://<IP-máy-XDR>:8000/api/events/batch"
```
Đặt `agent.agent_key` trong `config.yaml` giống với biến môi trường `XDR_AGENT_KEY` trên XDR. Mở TCP 8000 trên firewall máy XDR nếu agent chạy máy khác.
