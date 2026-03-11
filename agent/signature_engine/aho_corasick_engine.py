"""
Optimized signature engine using Aho-Corasick algorithm for multi-pattern matching.
Provides O(n + m + z) complexity where n is text length, m is total pattern length, z is matches.
Much faster than linear O(n*m) approach for multiple patterns.
"""
from __future__ import annotations
import re
import threading
from typing import List, Optional, Dict, Set
from agent.schemas import SignatureRule

try:
    import ahocorasick
    AHO_CORASICK_AVAILABLE = True
except ImportError:
    AHO_CORASICK_AVAILABLE = False
    ahocorasick = None


class OptimizedSignatureEngine:
    """
    High-performance signature engine using Aho-Corasick automaton.
    Supports multiple signature types with optimized matching.
    """
    
    def __init__(self, use_aho_corasick: bool = True):
        """
        Initialize the optimized signature engine.
        
        Args:
            use_aho_corasick: If True, use Aho-Corasick for string patterns.
                              Falls back to linear search if library unavailable.
        """
        self.rules: List[SignatureRule] = []
        self._lock = threading.RLock()  # Thread-safe hot-reload
        
        # Separate automata for different pattern types
        self._string_automaton = None
        self._regex_patterns: List[tuple] = []  # (compiled_regex, rule)
        self._ip_patterns: Dict[str, SignatureRule] = {}
        self._domain_patterns: Dict[str, SignatureRule] = {}
        self._port_patterns: Dict[int, SignatureRule] = {}
        
        self.use_aho_corasick = use_aho_corasick and AHO_CORASICK_AVAILABLE
        
        if self.use_aho_corasick:
            self._string_automaton = ahocorasick.Automaton()
        else:
            print("[SignatureEngine] Aho-Corasick not available, using linear search")
    
    def load_rules(self, rules: List[SignatureRule]) -> None:
        """
        Load signature rules and build optimized data structures.
        
        Args:
            rules: List of signature rules to load
        """
        with self._lock:
            self.rules = rules
            
            # Reset all data structures
            if self._string_automaton:
                self._string_automaton = ahocorasick.Automaton()
            self._regex_patterns = []
            self._ip_patterns = {}
            self._domain_patterns = {}
            self._port_patterns = {}
            
            # Categorize and compile patterns
            for rule in rules:
                self._add_rule(rule)
            
            # Finalize Aho-Corasick automaton
            if self._string_automaton:
                self._string_automaton.make_automaton()
    
    def _add_rule(self, rule: SignatureRule) -> None:
        """
        Add a single rule to the appropriate data structure based on type.
        
        Args:
            rule: Signature rule to add
        """
        rule_type = rule.type.lower()
        pattern = rule.pattern
        
        if rule_type == "ip_equals":
            # Direct IP matching
            self._ip_patterns[pattern] = rule
        
        elif rule_type == "domain_match":
            # Domain matching (case-insensitive)
            self._domain_patterns[pattern.lower()] = rule
        
        elif rule_type == "port_equals":
            # Port matching
            try:
                port = int(pattern)
                self._port_patterns[port] = rule
            except ValueError:
                pass
        
        elif rule_type == "regex_contains":
            # Compile regex patterns
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                self._regex_patterns.append((compiled, rule))
            except re.error:
                print(f"[SignatureEngine] Invalid regex pattern: {pattern}")
        
        elif rule_type in ("payload_contains", "host_contains", "url_contains"):
            # String pattern matching - use Aho-Corasick
            if self.use_aho_corasick and self._string_automaton:
                # Normalize pattern for case-insensitive matching
                pattern_lower = pattern.lower()
                # Store rule with pattern as key
                self._string_automaton.add_word(pattern_lower, (pattern_lower, rule))
            else:
                # Fallback: store in regex patterns for linear search
                escaped = re.escape(pattern)
                compiled = re.compile(escaped, re.IGNORECASE)
                self._regex_patterns.append((compiled, rule))
        
        else:
            # Unknown type - treat as string pattern
            if self.use_aho_corasick and self._string_automaton:
                pattern_lower = pattern.lower()
                self._string_automaton.add_word(pattern_lower, (pattern_lower, rule))
            else:
                escaped = re.escape(pattern)
                compiled = re.compile(escaped, re.IGNORECASE)
                self._regex_patterns.append((compiled, rule))
    
    def match(self, payload: dict) -> Optional[SignatureRule]:
        """
        Match payload against all loaded signature rules.
        Uses optimized matching based on rule types.
        
        Args:
            payload: Event payload dictionary to match against
            
        Returns:
            First matching SignatureRule or None
        """
        with self._lock:
            # Convert payload to searchable text
            payload_text = self._payload_to_text(payload)
            payload_lower = payload_text.lower()
            
            # 1. Fast IP matching
            dst_ip = str(payload.get("dst_ip") or payload.get("ip", "")).strip()
            if dst_ip and dst_ip in self._ip_patterns:
                return self._ip_patterns[dst_ip]
            
            # 2. Fast domain matching
            url = str(payload.get("url", "")).lower()
            host = str(payload.get("host", "")).lower()
            for domain, rule in self._domain_patterns.items():
                if domain in url or domain in host:
                    return rule
            
            # 3. Fast port matching
            port = payload.get("port_dst") or payload.get("Destination_Port")
            if port and isinstance(port, (int, str)):
                try:
                    port_int = int(port)
                    if port_int in self._port_patterns:
                        return self._port_patterns[port_int]
                except (ValueError, TypeError):
                    pass
            
            # 4. Aho-Corasick string pattern matching (fastest for multiple patterns)
            if self.use_aho_corasick and self._string_automaton:
                for end_index, (pattern, rule) in self._string_automaton.iter(payload_lower):
                    return rule
            
            # 5. Regex pattern matching (slower, but necessary for complex patterns)
            for compiled_regex, rule in self._regex_patterns:
                if compiled_regex.search(payload_text):
                    return rule
            
            return None
    
    def match_all(self, payload: dict) -> List[SignatureRule]:
        """
        Find all matching rules (not just the first).
        Useful for comprehensive threat detection.
        
        Args:
            payload: Event payload dictionary to match against
            
        Returns:
            List of all matching SignatureRule objects
        """
        matches: Set[SignatureRule] = set()
        
        with self._lock:
            payload_text = self._payload_to_text(payload)
            payload_lower = payload_text.lower()
            
            # IP matching
            dst_ip = str(payload.get("dst_ip") or payload.get("ip", "")).strip()
            if dst_ip and dst_ip in self._ip_patterns:
                matches.add(self._ip_patterns[dst_ip])
            
            # Domain matching
            url = str(payload.get("url", "")).lower()
            host = str(payload.get("host", "")).lower()
            for domain, rule in self._domain_patterns.items():
                if domain in url or domain in host:
                    matches.add(rule)
            
            # Port matching
            port = payload.get("port_dst") or payload.get("Destination_Port")
            if port:
                try:
                    port_int = int(port)
                    if port_int in self._port_patterns:
                        matches.add(self._port_patterns[port_int])
                except (ValueError, TypeError):
                    pass
            
            # Aho-Corasick matching
            if self.use_aho_corasick and self._string_automaton:
                for end_index, (pattern, rule) in self._string_automaton.iter(payload_lower):
                    matches.add(rule)
            
            # Regex matching
            for compiled_regex, rule in self._regex_patterns:
                if compiled_regex.search(payload_text):
                    matches.add(rule)
        
        return list(matches)
    
    def _payload_to_text(self, payload: dict) -> str:
        """
        Convert payload dictionary to searchable text string.
        
        Args:
            payload: Event payload dictionary
            
        Returns:
            Combined text representation of payload
        """
        # Extract relevant fields for pattern matching
        fields = [
            str(payload.get("url", "")),
            str(payload.get("host", "")),
            str(payload.get("hostname", "")),
            str(payload.get("src_ip", "")),
            str(payload.get("dst_ip", "")),
            str(payload.get("protocol", "")),
            str(payload.get("category", "")),
        ]
        
        # Include full payload JSON for deep pattern matching
        try:
            import json
            fields.append(json.dumps(payload, default=str))
        except Exception:
            fields.append(str(payload))
        
        return " ".join(fields)
    
    def hot_reload(self, rules: List[SignatureRule]) -> None:
        """
        Atomically swap in new rules without interrupting matching.
        Thread-safe operation.
        
        Args:
            rules: New list of signature rules
        """
        # Build new automaton in parallel
        new_engine = OptimizedSignatureEngine(use_aho_corasick=self.use_aho_corasick)
        new_engine.load_rules(rules)
        
        # Atomic swap (thread-safe)
        with self._lock:
            self.rules = new_engine.rules
            self._string_automaton = new_engine._string_automaton
            self._regex_patterns = new_engine._regex_patterns
            self._ip_patterns = new_engine._ip_patterns
            self._domain_patterns = new_engine._domain_patterns
            self._port_patterns = new_engine._port_patterns
    
    def get_stats(self) -> dict:
        """
        Get statistics about loaded rules and automaton.
        
        Returns:
            Dictionary with statistics
        """
        with self._lock:
            return {
                "total_rules": len(self.rules),
                "ip_patterns": len(self._ip_patterns),
                "domain_patterns": len(self._domain_patterns),
                "port_patterns": len(self._port_patterns),
                "regex_patterns": len(self._regex_patterns),
                "aho_corasick_enabled": self.use_aho_corasick,
                "aho_corasick_size": len(self._string_automaton) if self._string_automaton else 0
            }


# Backward-compatible alias
SignatureEngine = OptimizedSignatureEngine


