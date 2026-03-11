"""
Optimized signature matcher for cloud-side pattern matching.
Uses Aho-Corasick for high-performance multi-pattern matching.
"""
from __future__ import annotations
import re
import json
from typing import Optional, Dict, List
from collections import defaultdict

try:
    import ahocorasick
    AHO_CORASICK_AVAILABLE = True
except ImportError:
    AHO_CORASICK_AVAILABLE = False
    ahocorasick = None


class CloudSignatureMatcher:
    """
    High-performance signature matcher for cloud-side detection.
    Optimized for large signature databases.
    """
    
    def __init__(self):
        self.signatures: List[Dict] = []
        self._string_automaton = None
        self._regex_patterns: List[tuple] = []
        self._ip_patterns: Dict[str, Dict] = {}
        self._domain_patterns: Dict[str, Dict] = {}
        self._use_aho_corasick = AHO_CORASICK_AVAILABLE
        
        if self._use_aho_corasick:
            self._string_automaton = ahocorasick.Automaton()
    
    def load_signatures(self, signatures: List[Dict]) -> None:
        """
        Load signatures and build optimized data structures.
        
        Args:
            signatures: List of signature dictionaries
        """
        self.signatures = signatures
        
        # Reset data structures
        if self._string_automaton:
            self._string_automaton = ahocorasick.Automaton()
        self._regex_patterns = []
        self._ip_patterns = {}
        self._domain_patterns = {}
        
        # Categorize signatures
        for sig in signatures:
            self._add_signature(sig)
        
        # Finalize automaton
        if self._string_automaton:
            self._string_automaton.make_automaton()
    
    def _add_signature(self, sig: Dict) -> None:
        """Add signature to appropriate data structure"""
        sig_type = sig.get("type", "").lower()
        pattern = sig.get("pattern", "")
        
        if sig_type == "ip_equals":
            self._ip_patterns[pattern] = sig
        elif sig_type == "domain_match":
            self._domain_patterns[pattern.lower()] = sig
        elif sig_type == "regex_contains":
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                self._regex_patterns.append((compiled, sig))
            except re.error:
                pass
        else:
            # String pattern matching
            if self._use_aho_corasick and self._string_automaton:
                pattern_lower = pattern.lower()
                self._string_automaton.add_word(pattern_lower, (pattern_lower, sig))
            else:
                escaped = re.escape(pattern)
                compiled = re.compile(escaped, re.IGNORECASE)
                self._regex_patterns.append((compiled, sig))
    
    def match(self, payload: Dict) -> Optional[Dict]:
        """
        Match payload against signatures.
        
        Args:
            payload: Event payload dictionary
            
        Returns:
            First matching signature or None
        """
        # Build searchable text
        host = str(payload.get("host", "")).lower()
        body = json.dumps(payload).lower()
        url = str(payload.get("url", "")).lower()
        
        # IP matching
        dst_ip = payload.get("dst_ip") or payload.get("ip", "")
        if dst_ip and dst_ip in self._ip_patterns:
            return self._ip_patterns[dst_ip]
        
        # Domain matching
        for domain, sig in self._domain_patterns.items():
            if domain in url or domain in host:
                return sig
        
        # Aho-Corasick string matching
        search_text = f"{host} {body} {url}"
        if self._use_aho_corasick and self._string_automaton:
            for end_index, (pattern, sig) in self._string_automaton.iter(search_text):
                return sig
        
        # Regex matching
        for compiled_regex, sig in self._regex_patterns:
            if compiled_regex.search(body):
                return sig
        
        return None


# Global instance for cloud-side matching
_cloud_matcher = CloudSignatureMatcher()

def get_cloud_matcher() -> CloudSignatureMatcher:
    """Get global cloud signature matcher instance"""
    return _cloud_matcher

