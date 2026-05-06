"""Phishing Detection Pipeline - Main detection logic"""

import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from email_parser import ParsedEmail, EmailParser
from llm_client import LLMClient, LLMClientFactory


@dataclass
class PhishingResult:
    """Phishing detection result"""
    is_phishing: bool
    is_spam: bool
    confidence: float
    risk_level: str  # low, medium, high, critical
    threat_indicators: List[str]
    summary: str
    recommendations: List[str]
    iocs: List[Dict]
    details: Dict
    timestamp: str
    llm_analysis: str


class PhishingDetector:
    """AI-powered phishing detection pipeline"""
    
    SYSTEM_PROMPT = """Bạn là chuyên gia an ninh mạng chuyên phân tích email phishing.
Hãy đánh giá email theo góc nhìn phòng thủ, có cấu trúc rõ ràng và ưu tiên chỉ dấu có thể hành động.
Trả lời ngắn gọn, chính xác, bằng tiếng Việt."""
    
    ANALYSIS_PROMPT_TEMPLATE = """Hãy phân tích email sau để phát hiện phishing/spam.

THÔNG TIN EMAIL:
- Người gửi: {sender}
- Reply-To: {reply_to}
- Tiêu đề: {subject}
- Ngày gửi: {date}

NỘI DUNG EMAIL:
{body}

DANH SÁCH URL TRÍCH XUẤT:
{urls}

TỆP ĐÍNH KÈM:
{attachments}

Trả về kết quả theo đúng định dạng JSON sau:
{{"is_phishing": true/false, "is_spam": true/false, "confidence": 0.0-1.0, "risk_level": "low/medium/high/critical", "threat_indicators": ["chỉ dấu 1"], "summary": "Tóm tắt ngắn bằng tiếng Việt", "recommendations": ["hành động đề xuất"], "suspicious_elements": {{"sender_analysis": "..."}}}}

Yêu cầu:
- Giữ nguyên tên khóa JSON bằng tiếng Anh để hệ thống đọc được.
- Các giá trị dạng mô tả trong summary, threat_indicators, recommendations và suspicious_elements phải viết bằng tiếng Việt.
- risk_level chỉ dùng một trong các giá trị: low, medium, high, critical.

Cần kiểm tra:
1. Giả mạo người gửi hoặc mạo danh thương hiệu
2. URL đáng ngờ như tên miền sai chính tả, URL dùng IP, chuyển hướng
3. Từ ngữ khẩn cấp hoặc gây áp lực
4. Yêu cầu cung cấp thông tin nhạy cảm
5. Reply-To không khớp với người gửi
6. Tệp đính kèm đáng ngờ
7. Mạo danh thương hiệu
8. Dấu hiệu social engineering

Chỉ trả về JSON hợp lệ, không thêm văn bản bên ngoài JSON."""
    
    def __init__(self, llm_client: LLMClient, config: Dict = None):
        self.llm_client = llm_client
        self.config = config or {}
        self.parser = EmailParser(
            extract_iocs=self.config.get('detection', {}).get('extract_iocs', True)
        )
        self.confidence_threshold = self.config.get('detection', {}).get('confidence_threshold', 0.7)
    
    def analyze(self, raw_email: str) -> PhishingResult:
        """Analyze raw email for phishing indicators"""
        # Parse email
        parsed = self.parser.parse(raw_email)
        
        # Build analysis prompt
        prompt = self._build_prompt(parsed)
        
        # Get LLM analysis
        llm_result = None
        response_content = ""
        runtime_config = self.config.get("runtime", {})
        if runtime_config.get("api_key_missing"):
            env_var = runtime_config.get("api_key_env_var", "OPENAI_API_KEY")
            provider = runtime_config.get("provider", "openai")
            response_content = "Bỏ qua phân tích LLM vì chưa cấu hình API key."
            llm_result = {
                "is_phishing": False,
                "is_spam": False,
                "confidence": 0.0,
                "risk_level": "unknown",
                "threat_indicators": [
                    f"Chưa setup API key cho nhà cung cấp LLM '{provider}'.",
                    f"Cần đặt biến môi trường {env_var} hoặc cấu hình llm.api.api_key trong config/config.yaml."
                ],
                "summary": "Chưa thể phân tích bằng AI vì thiếu API key.",
                "recommendations": [
                    f"Chạy PowerShell: $env:{env_var}=\"dien-api-key-cua-ban\"",
                    "Sau khi setup API key, chạy lại lệnh kiểm tra email."
                ]
            }
        else:
            try:
                response = self.llm_client.complete(prompt, self.SYSTEM_PROMPT)
                response_content = response.content
                llm_result = self._parse_llm_response(response.content)
            except Exception as e:
                llm_result = {
                    "is_phishing": False,
                    "is_spam": False,
                    "confidence": 0.0,
                    "risk_level": "unknown",
                    "threat_indicators": [f"Phân tích LLM thất bại: {str(e)}"],
                    "summary": "Không thể hoàn tất phân tích bằng AI",
                    "recommendations": ["Nên kiểm tra thủ công email này"]
                }
        
        # Build result
        result = PhishingResult(
            is_phishing=llm_result.get('is_phishing', False),
            is_spam=llm_result.get('is_spam', False),
            confidence=llm_result.get('confidence', 0.0),
            risk_level=llm_result.get('risk_level', 'low'),
            threat_indicators=llm_result.get('threat_indicators', []),
            summary=llm_result.get('summary', ''),
            recommendations=llm_result.get('recommendations', []),
            iocs=[asdict(ioc) for ioc in parsed.iocs],
            details={
                "sender": parsed.headers.sender,
                "sender_domain": parsed.headers.sender_domain,
                "reply_to": parsed.headers.reply_to,
                "subject": parsed.headers.subject,
                "urls_count": len(parsed.urls),
                "suspicious_urls": [u.url for u in parsed.urls if u.is_suspicious],
                "attachments": parsed.attachments,
                "suspicious_elements": llm_result.get('suspicious_elements', {})
            },
            timestamp=datetime.now().isoformat(),
            llm_analysis=response_content
        )
        
        return result
    
    def _build_prompt(self, parsed: ParsedEmail) -> str:
        """Build analysis prompt from parsed email"""
        urls_info = []
        for url in parsed.urls:
            status = "[ĐÁNG NGỜ]" if url.is_suspicious else "[OK]"
            urls_info.append(f"  - {status} {url.url}")
            if url.suspicious_keywords:
                urls_info.append(f"    Từ khóa đáng ngờ: {', '.join(url.suspicious_keywords)}")
        
        attachments_info = []
        for att in parsed.attachments:
            attachments_info.append(f"  - {att['filename']} ({att['content_type']}, {att['size']} bytes)")
        
        body = parsed.body_text
        if len(body) > 2000:
            body = body[:2000] + "\n... [đã cắt bớt]"
        
        return self.ANALYSIS_PROMPT_TEMPLATE.format(
            sender=parsed.headers.sender or "Không rõ",
            reply_to=parsed.headers.reply_to or "Không có",
            subject=parsed.headers.subject or "Không có tiêu đề",
            date=str(parsed.headers.date or "Không rõ"),
            body=body or "Không có nội dung văn bản",
            urls="\n".join(urls_info) if urls_info else "Không tìm thấy URL",
            attachments="\n".join(attachments_info) if attachments_info else "Không có tệp đính kèm"
        )
    
    def _parse_llm_response(self, response: str) -> Dict:
        """Parse LLM JSON response"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())
            return json.loads(response)
        except json.JSONDecodeError:
            # If JSON parsing fails, return default
            return {
                "is_phishing": False,
                "is_spam": False,
                "confidence": 0.5,
                "risk_level": "medium",
                "threat_indicators": ["Không thể đọc phản hồi JSON từ LLM"],
                "summary": "Phản hồi của LLM không đúng định dạng JSON",
                "recommendations": ["Nên kiểm tra thủ công email này"]
            }


class PhishingPipeline:
    """Complete phishing detection pipeline"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.llm_client = LLMClientFactory.from_config(config.get('llm', {}))
        self.detector = PhishingDetector(self.llm_client, config)
    
    def process(self, raw_email: str) -> PhishingResult:
        """Process email through the pipeline"""
        return self.detector.analyze(raw_email)
    
    def process_file(self, filepath: str) -> PhishingResult:
        """Process email from file"""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw_email = f.read()
        return self.process(raw_email)


def format_result(result: PhishingResult, verbose: bool = True) -> str:
    """Format detection result for display"""
    lines = []
    lines.append("=" * 60)
    lines.append("KẾT QUẢ KIỂM TRA EMAIL")
    lines.append("=" * 60)
    
    # Verdict with risk indicator
    risk_marker = {
        "low": "[+]",
        "medium": "[!]",
        "high": "[!!]",
        "critical": "[!!!]"
    }.get(result.risk_level, "[?]")

    risk_label = {
        "low": "THẤP",
        "medium": "TRUNG BÌNH",
        "high": "CAO",
        "critical": "NGHIÊM TRỌNG",
        "unknown": "KHÔNG RÕ",
    }.get(result.risk_level, result.risk_level.upper())
    
    lines.append(f"\n{risk_marker} Mức rủi ro: {risk_label}")
    lines.append(f"   Phishing: {'CÓ' if result.is_phishing else 'KHÔNG'}")
    lines.append(f"   Spam: {'CÓ' if result.is_spam else 'KHÔNG'}")
    lines.append(f"   Độ tin cậy: {result.confidence:.2%}")
    
    lines.append(f"\n[*] Tóm tắt: {result.summary}")
    
    if result.threat_indicators:
        lines.append("\n[!] Chỉ dấu đe dọa:")
        for indicator in result.threat_indicators:
            lines.append(f"   - {indicator}")
    
    if result.recommendations:
        lines.append("\n[>] Khuyến nghị:")
        for rec in result.recommendations:
            lines.append(f"   - {rec}")
    
    if verbose and result.iocs:
        lines.append("\n[IoC] Chỉ dấu xâm nhập:")
        for ioc in result.iocs:
            lines.append(f"   - [{ioc['ioc_type']}] {ioc['value']}")
    
    if verbose:
        lines.append(f"\n[Chi tiết email]:")
        lines.append(f"   Người gửi: {result.details.get('sender', 'Không rõ')}")
        lines.append(f"   Tiêu đề: {result.details.get('subject', 'Không có tiêu đề')}")
        lines.append(f"   Số URL tìm thấy: {result.details.get('urls_count', 0)}")
        if result.details.get('suspicious_urls'):
            lines.append(f"   URL đáng ngờ: {len(result.details['suspicious_urls'])}")
    
    lines.append(f"\n[Thời gian] Đã phân tích lúc: {result.timestamp}")
    lines.append("=" * 60)
    
    return "\n".join(lines)
