from typing import Dict, List
import re
from .payload_generator import PayloadGenerator
from .config import Config

class XSSDetector:
    def __init__(self):
        self.config = Config()
        self.payload_gen = PayloadGenerator()
        self.xss_patterns = [
            r'<script.*?>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'document\.\w+',
            r'window\.location'
        ]

    def detect_xss(self, input_string: str) -> Dict:
        """Detect XSS vulnerability using pattern matching"""
        for pattern in self.xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                confidence = 0.9 if 'script' in input_string.lower() else 0.7
                return {
                    'xss': True,
                    'confidence': confidence,
                    'payload': input_string
                }
        return {'xss': False, 'confidence': 0}

    def scan_page(self, url: str, forms: List[Dict]) -> List[Dict]:
        """Scan a web page for XSS vulnerabilities"""
        results = []
        payloads = self.payload_gen.generate_payloads(self.config.FUZZING_ITERATIONS)
        
        for form in forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                for payload in payloads:
                    detection_result = self.detect_xss(payload)
                    if detection_result['xss']:
                        results.append({
                            'url': url,
                            'form_action': form['action'],
                            'input_name': input_field['name'],
                            'payload': payload,
                            'confidence': detection_result['confidence'],
                            'type': 'reflected' if form['method'] == 'get' else 'stored'
                        })
        return results
