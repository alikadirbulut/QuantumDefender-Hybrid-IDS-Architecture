"""
Pluggable signature engine with hot-reload hook.
Now uses optimized Aho-Corasick engine by default.
"""
from __future__ import annotations
from typing import List, Optional

# Import optimized engine, fallback to basic if unavailable
try:
    from agent.signature_engine.aho_corasick_engine import OptimizedSignatureEngine
    SignatureEngine = OptimizedSignatureEngine
except ImportError:
    # Fallback to basic implementation if dependencies unavailable
    from agent.schemas import SignatureRule
    
    class SignatureEngine:
        """Basic signature engine (fallback when Aho-Corasick unavailable)"""
        def __init__(self):
            self.rules: List[SignatureRule] = []

        def load_rules(self, rules: List[SignatureRule]) -> None:
            self.rules = rules

        def match(self, payload: dict) -> Optional[SignatureRule]:
            body = str(payload).lower()
            for rule in self.rules:
                pat = rule.pattern.lower()
                if pat in body:
                    return rule
            return None

        def hot_reload(self, rules: List[SignatureRule]) -> None:
            self.load_rules(rules)
        
        def match_all(self, payload: dict) -> List[SignatureRule]:
            """Find all matching rules"""
            matches = []
            body = str(payload).lower()
            for rule in self.rules:
                pat = rule.pattern.lower()
                if pat in body:
                    matches.append(rule)
            return matches
        
        def get_stats(self) -> dict:
            """Get engine statistics"""
            return {"total_rules": len(self.rules), "aho_corasick_enabled": False}





