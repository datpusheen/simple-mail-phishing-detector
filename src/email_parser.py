"""Email Parser Module - Extract and parse email components"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import urllib.parse


@dataclass
class EmailHeader:
    """Email header information"""
    sender: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    to: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    subject: str = ""
    date: Optional[datetime] = None
    message_id: str = ""
    return_path: str = ""
    x_sender_ip: str = ""
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""


@dataclass
class URLInfo:
    """URL information extracted from email"""
    url: str
    domain: str
    is_suspicious: bool = False
    is_ip_based: bool = False
    has_redirect: bool = False
    suspicious_keywords: List[str] = field(default_factory=list)


@dataclass
class IoC:
    """Indicator of Compromise"""
    ioc_type: str  # url, domain, ip, email, hash
    value: str
    context: str = ""
    is_malicious: bool = False


@dataclass
class ParsedEmail:
    """Complete parsed email structure"""
    headers: EmailHeader = field(default_factory=EmailHeader)
    body_text: str = ""
    body_html: str = ""
    urls: List[URLInfo] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)
    iocs: List[IoC] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)


class EmailParser:
    """Parse raw email content and extract components"""
    
    # Regex patterns
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?=&%#+-]+'
    )
    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    )
    IP_PATTERN = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    )
    
    # Suspicious URL indicators
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'password', 'banking', 'alert', 'suspended',
        'verify', 'validate', 'authenticate', 'access'
    ]
    
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
        't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'cur.lv'
    ]
    
    def __init__(self, extract_iocs: bool = True):
        self.extract_iocs = extract_iocs
    
    def parse(self, raw_email: str) -> ParsedEmail:
        """Parse raw email content"""
        parsed = ParsedEmail()
        
        try:
            # Parse email message
            if isinstance(raw_email, str):
                raw_email = raw_email.lstrip('\ufeff')
                raw_email = raw_email.encode('utf-8', errors='ignore')
            elif raw_email.startswith(b'\xef\xbb\xbf'):
                raw_email = raw_email[3:]
            
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            # Extract headers
            parsed.headers = self._extract_headers(msg)
            parsed.raw_headers = dict(msg.items())
            
            # Extract body
            parsed.body_text, parsed.body_html = self._extract_body(msg)
            
            # Extract URLs
            parsed.urls = self._extract_urls(parsed.body_text + " " + parsed.body_html)
            
            # Extract email addresses
            parsed.email_addresses = self._extract_emails(
                parsed.body_text + " " + parsed.body_html
            )
            
            # Extract attachments info
            parsed.attachments = self._extract_attachments(msg)
            
            # Extract IoCs
            if self.extract_iocs:
                parsed.iocs = self._extract_all_iocs(parsed)
                
        except Exception as e:
            parsed.body_text = f"Lỗi khi đọc email: {str(e)}"
        
        return parsed
    
    def _extract_headers(self, msg) -> EmailHeader:
        """Extract email headers"""
        headers = EmailHeader()
        
        headers.sender = msg.get('From', '')
        headers.reply_to = msg.get('Reply-To', '')
        headers.to = self._parse_address_list(msg.get('To', ''))
        headers.cc = self._parse_address_list(msg.get('Cc', ''))
        headers.subject = msg.get('Subject', '')
        headers.message_id = msg.get('Message-ID', '')
        headers.return_path = msg.get('Return-Path', '')
        
        # Extract sender domain
        if headers.sender:
            match = self.EMAIL_PATTERN.search(headers.sender)
            if match:
                email_addr = match.group()
                headers.sender_domain = email_addr.split('@')[-1]
        
        # Parse date
        try:
            date_str = msg.get('Date', '')
            if date_str:
                headers.date = email.utils.parsedate_to_datetime(date_str)
        except:
            pass
        
        # Security headers
        headers.spf_result = msg.get('Received-SPF', '')
        headers.dkim_result = msg.get('Authentication-Results', '')
        
        # Extract sender IP from Received headers
        received = msg.get('Received', '')
        if received:
            ip_match = self.IP_PATTERN.search(received)
            if ip_match:
                headers.x_sender_ip = ip_match.group()
        
        return headers
    
    def _parse_address_list(self, addr_str: str) -> List[str]:
        """Parse email address list"""
        if not addr_str:
            return []
        return self.EMAIL_PATTERN.findall(addr_str)
    
    def _extract_body(self, msg) -> Tuple[str, str]:
        """Extract email body (text and HTML)"""
        text_body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode('utf-8', errors='ignore')
                        if content_type == 'text/plain':
                            text_body += decoded
                        elif content_type == 'text/html':
                            html_body += decoded
                except:
                    pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    content_type = msg.get_content_type()
                    decoded = payload.decode('utf-8', errors='ignore')
                    if content_type == 'text/plain':
                        text_body = decoded
                    elif content_type == 'text/html':
                        html_body = decoded
                else:
                    content = msg.get_content()
                    if isinstance(content, str):
                        if msg.get_content_type() == 'text/html':
                            html_body = content
                        else:
                            text_body = content
            except:
                pass
        
        return text_body, html_body
    
    def _extract_urls(self, text: str) -> List[URLInfo]:
        """Extract and analyze URLs from text"""
        urls = []
        seen = set()
        
        for match in self.URL_PATTERN.finditer(text):
            url = match.group()
            if url in seen:
                continue
            seen.add(url)
            
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc.lower()
                
                url_info = URLInfo(
                    url=url,
                    domain=domain,
                    is_ip_based=bool(self.IP_PATTERN.match(domain)),
                    has_redirect='redirect' in url.lower() or 'url=' in url.lower()
                )
                
                # Check for suspicious indicators
                url_lower = url.lower()
                for keyword in self.SUSPICIOUS_KEYWORDS:
                    if keyword in url_lower:
                        url_info.suspicious_keywords.append(keyword)
                        url_info.is_suspicious = True
                
                # Check URL shorteners
                for shortener in self.URL_SHORTENERS:
                    if shortener in domain:
                        url_info.is_suspicious = True
                        break
                
                urls.append(url_info)
                
            except:
                pass
        
        return urls
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        return list(set(self.EMAIL_PATTERN.findall(text)))
    
    def _extract_attachments(self, msg) -> List[Dict]:
        """Extract attachment information"""
        attachments = []
        
        for part in msg.walk():
            content_disposition = str(part.get('Content-Disposition', ''))
            if 'attachment' in content_disposition:
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True) or b'')
                    })
        
        return attachments
    
    def _extract_all_iocs(self, parsed: ParsedEmail) -> List[IoC]:
        """Extract all Indicators of Compromise"""
        iocs = []
        
        # URL IoCs
        for url_info in parsed.urls:
            iocs.append(IoC(
                ioc_type='url',
                value=url_info.url,
                context=f"Tên miền: {url_info.domain}",
                is_malicious=url_info.is_suspicious
            ))
        
        # Domain IoCs
        domains = set(url.domain for url in parsed.urls)
        for domain in domains:
            iocs.append(IoC(
                ioc_type='domain',
                value=domain
            ))
        
        # IP IoCs
        if parsed.headers.x_sender_ip:
            iocs.append(IoC(
                ioc_type='ip',
                value=parsed.headers.x_sender_ip,
                context="IP người gửi từ header"
            ))
        
        # Email IoCs
        for email_addr in parsed.email_addresses:
            if email_addr != parsed.headers.sender:
                iocs.append(IoC(
                    ioc_type='email',
                    value=email_addr,
                    context="Tìm thấy trong nội dung email"
                ))
        
        return iocs


def parse_email_file(filepath: str) -> ParsedEmail:
    """Parse email from file"""
    with open(filepath, 'rb') as f:
        raw_email = f.read()
    parser = EmailParser()
    return parser.parse(raw_email)
