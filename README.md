# EDR Agent - gửi Sysmon logs lên XDR

Agent đọc sự kiện từ `Microsoft-Windows-Sysmon/Operational`, gom thành batch và gửi tới API XDR `POST /api/events/batch`. Khi mất kết nối, event được giữ trong `spool.jsonl` để gửi lại. XDR lưu event vào SQLite; cảnh báo chỉ được tạo nếu event khớp rule đã cấu hình.

## Điều kiện

- Máy EDR chạy Windows và đã cài Sysmon, bật Sysmon Event Log.
- Máy XDR chạy ứng dụng trong thư mục `XDR` và cho phép máy EDR truy cập TCP port `8000`.
- Python 3.11 trở lên trên máy EDR; dùng PowerShell quyền Administrator khi cài Sysmon/đọc log nếu cần.

## 1. Khởi chạy XDR

Chọn một trong hai cách ở máy XDR.

### Chạy bằng Docker Compose

Mở PowerShell tại thư mục `XDR`, đặt khóa agent:

```powershell
$env:XDR_AGENT_KEY = "A19-EDR-DEMO-KEY"
docker compose up --build -d
```

### Chạy trực tiếp bằng Python

```powershell
cd D:\DATN\XDR
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
$env:XDR_AGENT_KEY = "A19-EDR-DEMO-KEY"
cd backend
py -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Kiểm tra từ máy XDR:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Kết quả cần có `status: ok`. Nếu EDR và XDR ở hai máy khác nhau, cho phép inbound TCP `8000` trên firewall của máy XDR và ghi nhận IP LAN của máy đó.

## 2. Cài và cấu hình EDR

Trên máy Windows có Sysmon, mở PowerShell tại thư mục `EDR`:

```powershell
cd D:\DATN\EDR
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Tạo file cấu hình từ mẫu:

```powershell
Copy-Item config.example.yaml config.yaml
```

Mở `config.yaml` và cấu hình `sender.url`:

```yaml
sender:
  url: "http://127.0.0.1:8000/api/events/batch"
```

- Đặt `XDR_AGENT_KEY` trong PowerShell cho agent; giá trị phải khớp với khóa trên XDR:

```powershell
$env:XDR_AGENT_KEY = "A19-EDR-DEMO-KEY"
```

- Nếu XDR ở máy khác, thay `127.0.0.1` bằng IP LAN của máy XDR, ví dụ `http://10.10.10.60:8000/api/events/batch`.
- Để `agent_id` trống để tự lấy hostname; có thể đặt ID riêng nếu cần.

## 3. Chạy và kiểm tra

Từ thư mục `EDR`, chạy agent bằng quyền phù hợp để đọc Sysmon:

```powershell
.\.venv\Scripts\Activate.ps1
$env:XDR_AGENT_KEY = "A19-EDR-DEMO-KEY"
python edr_agent.py --config config.yaml
```

Tạo event mới bằng cách mở ứng dụng hoặc chạy lệnh mới, ví dụ `whoami`. Agent gửi theo lô sau tối đa `flush_interval` giây hoặc khi đủ `batch_size`.

Kiểm tra dữ liệu ở XDR:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/events?limit=10"
Invoke-RestMethod "http://127.0.0.1:8000/api/hosts"
```

Event được lưu với `source: edr`, tên máy ở `host_id`, và dữ liệu Sysmon gốc trong `raw`. Các event Sysmon thông thường được lưu để giám sát; chúng không tự tạo alert nếu chưa có detection rule phù hợp.

## Lọc event trước khi gửi

Agent áp dụng `filters` trong `config.yaml` trước khi đưa event vào hàng đợi XDR. Mặc định, nội dung event giống hệt nhau trên cùng máy trong vòng 10 giây chỉ gửi một lần; các rule loại trừ khác đang để trống để tránh bỏ mất telemetry quan trọng. Ví dụ:

```yaml
filters:
  enabled: true
  dedupe_window_seconds: 10
  dedupe_cache_size: 10000
  exclude_event_ids: []
  keep_event_ids_when:
    10:
      TargetImage: ["\\lsass.exe"] # chỉ giữ ProcessAccess hướng tới LSASS
  exclude_process_names: ["SearchIndexer.exe"]
  exclude_path_contains: ["\\Temp\\benign-app\\"]
  exclude_data_contains:
    QueryName: ["example.local"]
```

`exclude_event_ids` loại toàn bộ Event ID; `keep_event_ids_when` chỉ giữ Event ID đó khi ít nhất một trường khớp chuỗi đã cấu hình (các giá trị dùng phép chứa, không phân biệt hoa thường); `exclude_process_names` khớp tên exe ở trường `Image`/`ProcessName`; `exclude_path_contains` dò chuỗi trong giá trị `data`; `exclude_data_contains` dò chuỗi trong trường chỉ định. Cấu hình mặc định giảm nhiễu Event ID 10 bằng cách chỉ giữ event có `TargetImage` là LSASS. Xóa block `10` trong `keep_event_ids_when` để nhận lại toàn bộ ProcessAccess. Đặt `dedupe_window_seconds: 0` để tắt chống trùng lặp.

## Xử lý lỗi thường gặp

| Lỗi | Cách kiểm tra |
|---|---|
| `Connection refused` hoặc timeout | Kiểm tra XDR đang chạy, URL/IP, TCP 8000 và firewall. |
| HTTP `401` | Đảm bảo `agent_key` và `XDR_AGENT_KEY` giống nhau. |
| HTTP `503` | XDR chưa được khởi chạy với biến môi trường `XDR_AGENT_KEY`. |
| Không thấy event | Kiểm tra Sysmon có ghi event mới trong Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational. |
| Thiếu `win32evtlog` | Kích hoạt virtualenv EDR rồi cài lại requirements; đảm bảo đang chạy trên Windows. |

Khi XDR tạm thời không truy cập được, EDR sẽ retry rồi ghi event vào `spool.jsonl`; agent tự gửi lại khi kết nối được. Dừng agent bằng `Ctrl+C` để cố flush batch cuối.

> Đây là prototype phục vụ demo/lab. Khóa mẫu trong hướng dẫn không phù hợp môi trường production; hãy thay bằng khóa ngẫu nhiên riêng và chỉ triển khai trên mạng tin cậy hoặc bảo vệ API bằng HTTPS.
