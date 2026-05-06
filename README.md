# Công cụ phát hiện email phishing bằng AI

Phân loại email phishing/spam bằng LLM, đồng thời trích xuất IoC như URL, domain, IP và địa chỉ email.

## Cấu trúc project

```text
project/
├── config/
│   └── config.yaml          # Cấu hình LLM và detection
├── src/
│   ├── main.py              # Giao diện dòng lệnh
│   ├── email_parser.py      # Parser email: header, body, URL, attachment
│   ├── llm_client.py        # Client gọi API LLM
│   └── phishing_detector.py # Pipeline phân tích phishing
├── samples/
│   ├── phishing_sample.eml
│   └── legitimate_sample.eml
├── Check Email.bat          # Launcher kéo thả email để kiểm tra
└── requirements.txt
```

## Cài đặt

```powershell
pip install -r requirements.txt
```

## Cấu hình LLM

Cách nhanh nhất là đặt API key bằng biến môi trường:

```powershell
$env:OPENAI_API_KEY="your-api-key"
$env:LLM_PROVIDER="openai"
$env:LLM_MODEL="gpt-4o-mini"
```

Hoặc chỉnh trực tiếp trong [config/config.yaml](config/config.yaml):

```yaml
llm:
  provider: openai
  api:
    base_url: https://api.openai.com/v1
    api_key: ${OPENAI_API_KEY}
    model: gpt-4o-mini
```

Nếu dùng LLM local qua Ollama:

```yaml
llm:
  provider: local
  api:
    base_url: http://localhost:11434/v1
    model: llama3
```

## Cách sử dụng

Phân tích email từ file:

```powershell
python src\main.py --email samples\phishing_sample.eml
```

Xuất kết quả dạng JSON:

```powershell
python src\main.py --email samples\phishing_sample.eml --output json
```

Lưu kết quả vào file:

```powershell
python src\main.py --email suspicious.eml --save result.json
```

Phân tích nội dung email nhập trực tiếp:

```powershell
python src\main.py --text "From: test@test.com`nSubject: Verify account`n`nClick here..."
```

## Kéo thả email để kiểm tra

Bạn có thể kéo file `.eml` hoặc `.txt` thả vào `Check Email.bat` hoặc shortcut `Check Email.lnk`. Cửa sổ sẽ tự chạy phân tích và giữ lại kết quả để đọc.

## Pipeline xử lý

```text
Email đầu vào -> Parse header/body/URL -> Phân tích bằng LLM -> Phân loại -> Trích xuất IoC -> Báo cáo
```

Các bước chính:

1. Trích xuất header, body, URL, domain, email và metadata tệp đính kèm.
2. Phân tích người gửi, Reply-To, URL đáng ngờ, nội dung khẩn cấp hoặc mạo danh.
3. Phân loại phishing, spam hoặc hợp lệ với độ tin cậy và mức rủi ro.
4. Trả về chỉ dấu đe dọa, IoC và khuyến nghị xử lý.

## Kết quả mẫu

```text
============================================================
KẾT QUẢ KIỂM TRA EMAIL
============================================================

[!!] Mức rủi ro: CAO
   Phishing: CÓ
   Spam: KHÔNG
   Độ tin cậy: 95.00%

[*] Tóm tắt: Email có nhiều dấu hiệu phishing, bao gồm mạo danh thương hiệu và URL đáng ngờ.

[!] Chỉ dấu đe dọa:
   - Tên miền người gửi có dấu hiệu mạo danh Amazon
   - Reply-To không khớp với người gửi
   - URL dùng tên miền đáng ngờ

[IoC] Chỉ dấu xâm nhập:
   - [url] https://amaz0n-verify-account.ru/...
   - [domain] amaz0n-verify-account.ru
```
