"""Công cụ phát hiện email phishing bằng AI - điểm vào CLI.

Sử dụng:
    python main.py --email "path/to/email.eml"
    python main.py --text "email content string"
    python main.py --email "path/to/email.eml" --config config/config.yaml
    python main.py --help
"""

import os
import sys
import argparse
import json
import yaml

ARGPARSE_TRANSLATIONS = {
    "usage: ": "cách dùng: ",
    "options": "tùy chọn",
    "optional arguments": "tùy chọn",
    "positional arguments": "tham số vị trí",
    "show this help message and exit": "hiển thị trợ giúp rồi thoát",
}
argparse._ = lambda message: ARGPARSE_TRANSLATIONS.get(message, message)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Thêm thư mục src vào path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishing_detector import PhishingPipeline, format_result


def load_config(config_path: str) -> dict:
    """Tải cấu hình từ file YAML."""
    if not os.path.exists(config_path):
        print(f"Cảnh báo: Không tìm thấy file cấu hình: {config_path}")
        print("Đang sử dụng cấu hình mặc định.")
        return get_default_config()

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    return config


def get_default_config() -> dict:
    """Lấy cấu hình mặc định."""
    return {
        "llm": {
            "provider": os.environ.get("LLM_PROVIDER", "openai"),
            "api": {
                "base_url": os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1"),
                "api_key": os.environ.get("OPENAI_API_KEY", ""),
                "model": os.environ.get("LLM_MODEL", "gpt-4o-mini"),
                "temperature": 0.1,
                "max_tokens": 1000,
                "timeout": 30,
            },
        },
        "detection": {
            "confidence_threshold": 0.7,
            "verbose": True,
            "extract_iocs": True,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Công cụ phát hiện email phishing/spam bằng AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python main.py --email suspicious.eml
  python main.py --email suspicious.eml --config config/config.yaml
  python main.py --text "From: test@test.com..." --output json

Biến môi trường:
  OPENAI_API_KEY     - API key OpenAI
  ANTHROPIC_API_KEY  - API key Anthropic
  LLM_PROVIDER       - Nhà cung cấp LLM (openai, anthropic, local)
  LLM_BASE_URL       - Địa chỉ API LLM tùy chỉnh
  LLM_MODEL          - Tên model cần sử dụng
""",
    )

    parser.add_argument(
        "--email",
        "-e",
        type=str,
        help="Đường dẫn tới file email (.eml hoặc .txt)",
    )

    parser.add_argument(
        "--text",
        "-t",
        type=str,
        help="Nội dung email dạng chuỗi",
    )

    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="config/config.yaml",
        help="Đường dẫn file cấu hình (mặc định: config/config.yaml)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Định dạng kết quả (mặc định: text)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Hiển thị kết quả chi tiết",
    )

    parser.add_argument(
        "--save",
        "-s",
        type=str,
        help="Lưu kết quả vào file",
    )

    args = parser.parse_args()

    if not args.email and not args.text:
        parser.print_help()
        print("\nLỗi: Cần cung cấp --email hoặc --text")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = args.config

    config_candidates = [
        config_path,
        os.path.join(script_dir, "..", "config", "config.yaml"),
        os.path.join(os.getcwd(), "config", "config.yaml"),
    ]

    for candidate in config_candidates:
        if os.path.exists(candidate):
            config_path = candidate
            break

    config = load_config(config_path)

    llm_config = config.get("llm", {}).get("api", {})
    api_key = llm_config.get("api_key", "")
    provider = config.get("llm", {}).get("provider", "openai")
    env_var = f"{provider.upper()}_API_KEY" if provider != "openai" else "OPENAI_API_KEY"

    if api_key.startswith("${") and api_key.endswith("}"):
        env_var = api_key[2:-1]
        api_key = os.environ.get(env_var, "")

    if not api_key:
        api_key = os.environ.get(env_var, "")

    key_required = provider != "local"
    api_key_missing = key_required and not api_key

    config["runtime"] = {
        "api_key_missing": api_key_missing,
        "api_key_env_var": env_var,
        "provider": provider,
    }

    if api_key_missing:
        print("=" * 60)
        print("CHƯA SETUP API KEY")
        print("=" * 60)
        print(f"Nhà cung cấp LLM hiện tại: {provider}")
        print(f"Biến môi trường cần thiết: {env_var}")
        print("")
        print("Cách setup nhanh trong PowerShell:")
        print(f'  $env:{env_var}="dien-api-key-cua-ban"')
        print("")
        print("Hoặc sửa trực tiếp mục llm.api.api_key trong config/config.yaml")
        print("Tool vẫn sẽ trích xuất header/URL/IoC, nhưng chưa thể phân tích bằng AI.")
        print("=" * 60)
        print("")

    try:
        pipeline = PhishingPipeline(config)
    except Exception as e:
        print(f"Lỗi khi khởi tạo pipeline: {e}")
        sys.exit(1)

    if args.email:
        if not os.path.exists(args.email):
            print(f"Lỗi: Không tìm thấy file email: {args.email}")
            sys.exit(1)
        print(f"[THÔNG TIN] Đang phân tích email: {args.email}")
        result = pipeline.process_file(args.email)
    else:
        print("[THÔNG TIN] Đang phân tích nội dung email...")
        result = pipeline.process(args.text)

    if args.output == "json":
        output = json.dumps(
            {
                "is_phishing": result.is_phishing,
                "is_spam": result.is_spam,
                "confidence": result.confidence,
                "risk_level": result.risk_level,
                "threat_indicators": result.threat_indicators,
                "summary": result.summary,
                "recommendations": result.recommendations,
                "iocs": result.iocs,
                "details": result.details,
                "timestamp": result.timestamp,
            },
            indent=2,
            ensure_ascii=False,
        )
    else:
        output = format_result(result, verbose=args.verbose)

    print(output)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\n[THÔNG TIN] Đã lưu kết quả vào: {args.save}")

    if result.risk_level == "unknown":
        sys.exit(3)
    if result.is_phishing:
        sys.exit(2)
    if result.is_spam:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
