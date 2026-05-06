"""LLM Client Module - Interface with external LLM APIs"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, Optional, Any
from dataclasses import dataclass
import time


@dataclass
class LLMConfig:
    """LLM Configuration"""
    provider: str = "openai"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    max_tokens: int = 1000
    timeout: int = 30


@dataclass
class LLMResponse:
    """LLM Response structure"""
    content: str
    model: str
    usage: Dict[str, int]
    latency_ms: float
    raw_response: Dict[str, Any] = None


class LLMClient:
    """Client for external LLM API calls"""
    
    def __init__(self, config: LLMConfig = None):
        self.config = config or LLMConfig()
        self._load_api_key()
    
    def _load_api_key(self):
        """Load API key from environment if not set"""
        if not self.config.api_key:
            env_var = f"{self.config.provider.upper()}_API_KEY"
            if self.config.provider == "openai":
                env_var = "OPENAI_API_KEY"
            elif self.config.provider == "anthropic":
                env_var = "ANTHROPIC_API_KEY"
            self.config.api_key = os.environ.get(env_var, "")
    
    def complete(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        """Send completion request to LLM"""
        start_time = time.time()
        
        if self.config.provider in ["openai", "local"]:
            response = self._openai_complete(prompt, system_prompt)
        elif self.config.provider == "anthropic":
            response = self._anthropic_complete(prompt, system_prompt)
        else:
            raise ValueError(f"Nhà cung cấp LLM không được hỗ trợ: {self.config.provider}")
        
        response.latency_ms = (time.time() - start_time) * 1000
        return response
    
    def _openai_complete(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        """OpenAI-compatible API call"""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}"
        }
        
        url = f"{self.config.base_url}/chat/completions"
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                return LLMResponse(
                    content=result['choices'][0]['message']['content'],
                    model=result.get('model', self.config.model),
                    usage=result.get('usage', {}),
                    latency_ms=0,
                    raw_response=result
                )
                
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            raise Exception(f"Lỗi API LLM ({e.code}): {error_body}")
        except urllib.error.URLError as e:
            raise Exception(f"Lỗi kết nối API LLM: {e.reason}")
    
    def _anthropic_complete(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        """Anthropic API call"""
        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.config.max_tokens
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        url = f"{self.config.base_url}/messages"
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                return LLMResponse(
                    content=result['content'][0]['text'],
                    model=result.get('model', self.config.model),
                    usage=result.get('usage', {}),
                    latency_ms=0,
                    raw_response=result
                )
                
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            raise Exception(f"Lỗi API Anthropic ({e.code}): {error_body}")
        except urllib.error.URLError as e:
            raise Exception(f"Lỗi kết nối API Anthropic: {e.reason}")


class LLMClientFactory:
    """Factory for creating LLM clients from config"""
    
    @staticmethod
    def from_config(config_dict: Dict[str, Any]) -> LLMClient:
        """Create LLM client from configuration dictionary"""
        api_config = config_dict.get('api', {})
        
        # Substitute environment variables
        api_key = api_config.get('api_key', '')
        if api_key and api_key.startswith('${') and api_key.endswith('}'):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, '')
        
        llm_config = LLMConfig(
            provider=config_dict.get('provider', 'openai'),
            base_url=api_config.get('base_url', 'https://api.openai.com/v1'),
            api_key=api_key,
            model=api_config.get('model', 'gpt-4o-mini'),
            temperature=api_config.get('temperature', 0.1),
            max_tokens=api_config.get('max_tokens', 1000),
            timeout=api_config.get('timeout', 30)
        )
        
        return LLMClient(llm_config)
