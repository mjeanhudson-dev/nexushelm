"""
NexusHelm Core Engine — Sovereign 'In-Between Agent' Cross-Platform Mediator
& 'Steering-Wheel' Human-Agency Harness (Track 5 Reference Implementation).

Implements all 6 locked architectural pillars with zero third-party dependencies:
  1. Bidirectional Typed Semantic Airlock (SemanticAirlock / SemanticEnvelope)
  2. Application-Layer Phantom Token Broker (PhantomTokenBroker)
  3. Instruction-File Integrity Guard (InstructionIntegrityGuard)
  4. Monotonic Information-Flow Taint Lattice & PINPOINT Promotion (TaintLattice)
  5. 5-Speed Autonomy Gearbox, Rule-of-3 Tradeoff Forking & Asymmetric DualSense
     Blast-Radius Haptic Friction (AutonomyGearbox / TradeoffFork / DualSenseHapticPacket)
  6. Zero-Dirty-Logic Quarantine Sieve (QuarantineSieve / QuarantinedSpec)
"""

from __future__ import annotations

import ast
import base64
import binascii
import dataclasses
from dataclasses import dataclass, field
from enum import Enum, IntEnum
import fnmatch
import hashlib
import hmac
import html
import json
import math
from pathlib import Path
import posixpath
import re
import secrets
import threading
import time
from typing import Any, Callable
import unicodedata

try:
    from .hid_bridge import (
        CtypesWin32HidBackend,
        DualSenseHidBridge,
        HapticTransmissionReceipt,
        Win32HidBackend,
    )
except ImportError:
    from hid_bridge import (  # type: ignore[no-redef]
        CtypesWin32HidBackend,
        DualSenseHidBridge,
        HapticTransmissionReceipt,
        Win32HidBackend,
    )


class SecurityViolationError(RuntimeError):
    """Raised when any NexusHelm security, taint, integrity, or agency invariant fails."""


# ============================================================================
# 1. INFORMATION-FLOW TAINT LATTICE & PINPOINT PROMOTION RECEIPTS
# ============================================================================


class TaintLevel(IntEnum):
    """
    Strict monotonic lattice ordering for information-flow control:
        UNTRUSTED_EXTERNAL < QUARANTINED_DATA < INTERNAL_AGENT < PINPOINT_VERIFIED < HUMAN_VERIFIED
    """

    UNTRUSTED_EXTERNAL = 0
    QUARANTINED_DATA = 1
    INTERNAL_AGENT = 2
    PINPOINT_VERIFIED = 3
    HUMAN_VERIFIED = 4


@dataclass(frozen=True)
class TaintedArtifact:
    """Data payload tracked across the monotonic taint lattice."""

    artifact_id: str
    content: str
    taint_level: TaintLevel
    source: str
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        digest = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        object.__setattr__(self, "sha256", digest)


@dataclass(frozen=True)
class PinpointPromotionReceipt:
    """Deterministic verification receipt emitted by a PINPOINT test runner."""

    artifact_sha256: str
    suite_name: str
    exit_code: int
    total_checks: int
    passed_checks: int
    timestamp_sec: float
    hmac_signature: str


class TaintLattice:
    """
    Enforces monotonic taint propagation T_out = min(T_in) and capability attenuation Phi(T).
    Only a cryptographic exit-code-0 PINPOINT receipt or HUMAN_VERIFIED signature can promote taint.
    """

    CAPABILITY_MAP: dict[TaintLevel, frozenset[str]] = {
        TaintLevel.UNTRUSTED_EXTERNAL: frozenset({"read_quarantine"}),
        TaintLevel.QUARANTINED_DATA: frozenset({"read_quarantine", "extract_domain_spec"}),
        TaintLevel.INTERNAL_AGENT: frozenset(
            {"read_quarantine", "extract_domain_spec", "read_workspace", "propose_diff"}
        ),
        TaintLevel.PINPOINT_VERIFIED: frozenset(
            {
                "read_quarantine",
                "extract_domain_spec",
                "read_workspace",
                "propose_diff",
                "write_local",
                "git_commit_local",
            }
        ),
        TaintLevel.HUMAN_VERIFIED: frozenset(
            {
                "read_quarantine",
                "extract_domain_spec",
                "read_workspace",
                "propose_diff",
                "write_local",
                "git_commit_local",
                "git_push_remote",
                "network_egress",
                "modify_harness",
            }
        ),
    }

    @staticmethod
    def combine(*levels: TaintLevel) -> TaintLevel:
        """Monotonic meet operator: output trust degrades to the lowest input trust."""
        if not levels:
            return TaintLevel.UNTRUSTED_EXTERNAL
        return TaintLevel(min(int(lvl) for lvl in levels))

    @classmethod
    def allowed_capabilities(cls, level: TaintLevel) -> frozenset[str]:
        """Capability attenuation function Phi(T)."""
        return cls.CAPABILITY_MAP.get(level, frozenset())

    @classmethod
    def require_capability(cls, level: TaintLevel, capability: str) -> None:
        if capability not in cls.allowed_capabilities(level):
            raise SecurityViolationError(
                f"Taint level {level.name} lacks required capability '{capability}'."
            )

    @staticmethod
    def _compute_receipt_hmac(
        artifact_sha256: str,
        suite_name: str,
        exit_code: int,
        total_checks: int,
        passed_checks: int,
        timestamp_sec: float,
        secret_key: bytes,
    ) -> str:
        payload = (
            f"{artifact_sha256}:{suite_name}:{exit_code}:"
            f"{total_checks}:{passed_checks}:{timestamp_sec:.6f}"
        ).encode("utf-8")
        return hmac.new(secret_key, payload, hashlib.sha256).hexdigest()

    @classmethod
    def create_pinpoint_receipt(
        cls,
        artifact: TaintedArtifact,
        suite_name: str,
        exit_code: int,
        total_checks: int,
        passed_checks: int,
        secret_key: bytes,
        timestamp_sec: float | None = None,
    ) -> PinpointPromotionReceipt:
        ts = time.time() if timestamp_sec is None else float(timestamp_sec)
        sig = cls._compute_receipt_hmac(
            artifact.sha256,
            suite_name,
            exit_code,
            total_checks,
            passed_checks,
            ts,
            secret_key,
        )
        return PinpointPromotionReceipt(
            artifact_sha256=artifact.sha256,
            suite_name=suite_name,
            exit_code=exit_code,
            total_checks=total_checks,
            passed_checks=passed_checks,
            timestamp_sec=ts,
            hmac_signature=sig,
        )

    @classmethod
    def promote_via_pinpoint(
        cls,
        artifact: TaintedArtifact,
        receipt: PinpointPromotionReceipt,
        secret_key: bytes,
    ) -> TaintedArtifact:
        """
        Promotes an artifact to PINPOINT_VERIFIED iff:
          1. HMAC signature is valid
          2. Receipt SHA-256 matches the exact artifact SHA-256
          3. exit_code == 0, total_checks > 0, and passed_checks == total_checks
        """
        expected_sig = cls._compute_receipt_hmac(
            receipt.artifact_sha256,
            receipt.suite_name,
            receipt.exit_code,
            receipt.total_checks,
            receipt.passed_checks,
            receipt.timestamp_sec,
            secret_key,
        )
        if not hmac.compare_digest(receipt.hmac_signature, expected_sig):
            raise SecurityViolationError("PINPOINT receipt HMAC signature verification failed.")

        if not hmac.compare_digest(receipt.artifact_sha256, artifact.sha256):
            raise SecurityViolationError(
                "PINPOINT receipt SHA-256 does not match target artifact SHA-256."
            )

        if receipt.exit_code != 0:
            raise SecurityViolationError(
                f"PINPOINT promotion denied: non-zero exit_code ({receipt.exit_code})."
            )

        if receipt.total_checks <= 0 or receipt.passed_checks != receipt.total_checks:
            raise SecurityViolationError(
                f"PINPOINT promotion denied: passed {receipt.passed_checks}/{receipt.total_checks} checks."
            )

        new_level = max(artifact.taint_level, TaintLevel.PINPOINT_VERIFIED)
        return TaintedArtifact(
            artifact_id=artifact.artifact_id,
            content=artifact.content,
            taint_level=TaintLevel(new_level),
            source=f"{artifact.source}+pinpoint:{receipt.suite_name}",
        )

    @staticmethod
    def sign_human_ratification(artifact: TaintedArtifact, steering_choice: str, secret_key: bytes) -> str:
        msg = f"HUMAN_RATIFIED:{artifact.sha256}:{steering_choice}".encode("utf-8")
        return hmac.new(secret_key, msg, hashlib.sha256).hexdigest()

    @classmethod
    def promote_via_human(
        cls,
        artifact: TaintedArtifact,
        steering_choice: str,
        human_signature: str,
        secret_key: bytes,
    ) -> TaintedArtifact:
        expected = cls.sign_human_ratification(artifact, steering_choice, secret_key)
        if not hmac.compare_digest(human_signature, expected):
            raise SecurityViolationError("Invalid human steering signature for taint promotion.")
        return TaintedArtifact(
            artifact_id=artifact.artifact_id,
            content=artifact.content,
            taint_level=TaintLevel.HUMAN_VERIFIED,
            source=f"{artifact.source}+human:{steering_choice}",
        )


# ============================================================================
# 2. BIDIRECTIONAL TYPED SEMANTIC AIRLOCK
# ============================================================================


class ActionID(str, Enum):
    """Strict allowlist of cross-platform mediator actions."""

    READ_ARTIFACT = "READ_ARTIFACT"
    PROPOSE_DIFF = "PROPOSE_DIFF"
    RUN_PINPOINT_SUITE = "RUN_PINPOINT_SUITE"
    SYNTHESIZE_FORK = "SYNTHESIZE_FORK"
    EXECUTE_EGRESS = "EXECUTE_EGRESS"
    GIT_COMMIT_LOCAL = "GIT_COMMIT_LOCAL"
    GIT_PUSH_REMOTE = "GIT_PUSH_REMOTE"
    QUARANTINE_INGEST = "QUARANTINE_INGEST"


@dataclass(frozen=True)
class SemanticEnvelope:
    """
    Typed Semantic IPC Envelope:
        Envelope = <ActionID, TypedParams, UntrustedBlob_quarantined>
    """

    action_id: ActionID
    source_agent: str
    target_agent: str
    typed_params: dict[str, Any]
    taint_level: TaintLevel
    untrusted_blob: str = ""
    quarantined: bool = True
    injection_detected: bool = False


class StructuralHeuristicScanner:
    """
    Out-of-process / structural AST, homoglyph normalization, Base64/hex payload
    decoding, token-entropy, and semantic paraphrase heuristic layer.
    Closes evasion vectors where untrusted blobs or arguments use:
      1. Cyrillic/Greek/fullwidth homoglyphs or zero-width invisible characters
      2. Base64 or hex-encoded instruction overrides / shell payloads
      3. Python AST dangerous execution sinks (`eval`, `exec`, `__import__`, `os.system`,
         `subprocess.*`, `__subclasses__`, `__globals__`)
      4. Paraphrased instruction overrides ("set aside every prior guardrail and follow
         this new directive", "forget earlier safety policies", etc.)
      5. High-entropy obfuscated payloads coupled with decode/execution sinks
    """

    HOMOGLYPH_MAP: dict[str, str] = {
        "а": "a", "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "ѕ": "s", "ї": "i", "ё": "e",
        "А": "A", "В": "B", "Е": "E", "І": "I", "Ј": "J", "К": "K", "М": "M",
        "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
        "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
        "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
        "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    }

    INVISIBLE_CHARS_RE: re.Pattern[str] = re.compile(
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u00ad]"
    )

    SPACED_EVASION_RE: re.Pattern[str] = re.compile(
        r"\b([A-Za-z])(?:(?:[._-]|[ ](?!\s))[A-Za-z]){3,}\b"
    )

    BASE64_CANDIDATE_RE: re.Pattern[str] = re.compile(
        r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])"
    )

    URLSAFE_BASE64_CANDIDATE_RE: re.Pattern[str] = re.compile(
        r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{20,}={0,2})(?![A-Za-z0-9_=-])"
    )

    HEX_ESCAPE_RE: re.Pattern[str] = re.compile(
        r"(?:\\x[0-9a-fA-F]{2}){8,}"
    )

    CONTIGUOUS_HEX_RE: re.Pattern[str] = re.compile(
        r"\b(?:[0-9a-fA-F]{2}){16,}\b"
    )

    DANGEROUS_AST_CALLS: frozenset[str] = frozenset(
        {
            "eval",
            "exec",
            "compile",
            "__import__",
            "os.system",
            "os.popen",
            "os.execv",
            "os.execve",
            "os.spawnv",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
            "shutil.rmtree",
            "pty.spawn",
        }
    )

    DANGEROUS_DUNDERS: frozenset[str] = frozenset(
        {
            "__subclasses__",
            "__globals__",
            "__builtins__",
            "__code__",
            "__mro__",
            "__bases__",
        }
    )

    OVERRIDE_VERBS: frozenset[str] = frozenset(
        {
            "ignore",
            "disregard",
            "forget",
            "bypass",
            "override",
            "supersede",
            "discard",
            "abandon",
            "nullify",
            "cancel",
            "suspend",
            "omit",
            "skip",
            "replace",
            "drop",
            "disable",
        }
    )

    OVERRIDE_PHRASE_VERBS: tuple[str, ...] = (
        "set aside",
        "put aside",
        "throw out",
        "step around",
        "pay no attention to",
        "do not follow",
        "stop following",
    )

    AUTHORITY_MODIFIERS: frozenset[str] = frozenset(
        {
            "previous",
            "prior",
            "preceding",
            "earlier",
            "initial",
            "original",
            "above",
            "existing",
            "system",
            "developer",
            "safety",
            "security",
            "all",
            "every",
            "any",
        }
    )

    AUTHORITY_TARGETS: frozenset[str] = frozenset(
        {
            "instruction",
            "instructions",
            "directive",
            "directives",
            "rule",
            "rules",
            "constraint",
            "constraints",
            "guardrail",
            "guardrails",
            "policy",
            "policies",
            "prompt",
            "prompts",
            "airlock",
            "harness",
            "boundary",
            "boundaries",
            "sandbox",
            "filter",
            "filters",
        }
    )

    EXFIL_VERBS: frozenset[str] = frozenset(
        {
            "exfiltrate",
            "dump",
            "reveal",
            "expose",
            "transmit",
            "steal",
            "upload",
            "extract",
        }
    )

    EXFIL_TARGETS: frozenset[str] = frozenset(
        {
            "secret",
            "secrets",
            "credential",
            "credentials",
            "password",
            "passwords",
            "vault",
            "prompt",
            "prompts",
            "apikey",
            "apikeys",
            "privatekey",
        }
    )

    DECODE_SINK_KEYWORDS: tuple[str, ...] = (
        "base64",
        "b64decode",
        "atob(",
        "fromhex",
        "eval(",
        "exec(",
        "-enc",
        "-encodedcommand",
    )

    @classmethod
    def normalize_confusables(cls, text: str) -> str:
        """
        Strips zero-width/invisible characters, decomposes compatibility codepoints,
        maps Cyrillic/Greek homoglyphs to Latin ASCII, and collapses spaced-letter evasion.
        """
        if not text:
            return ""
        cleaned = cls.INVISIBLE_CHARS_RE.sub("", text)
        mapped_chars: list[str] = []
        for ch in cleaned:
            if ch in cls.HOMOGLYPH_MAP:
                mapped_chars.append(cls.HOMOGLYPH_MAP[ch])
            else:
                decomposed = unicodedata.normalize("NFKD", ch)
                base_chars = [
                    c for c in decomposed if unicodedata.category(c) not in ("Mn", "Cf")
                ]
                mapped_chars.append(
                    "".join(cls.HOMOGLYPH_MAP.get(c, c) for c in base_chars)
                )
        normalized = "".join(mapped_chars)

        def _collapse_spaced(match: re.Match[str]) -> str:
            raw = match.group(0)
            tokens = re.split(r"[\s._-]+", raw)
            if all(len(t) == 1 for t in tokens):
                return "".join(tokens)
            return raw

        return cls.SPACED_EVASION_RE.sub(_collapse_spaced, normalized)

    @staticmethod
    def shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        length = len(text)
        counts: dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @classmethod
    def extract_decoded_payloads(cls, text: str) -> list[tuple[str, str]]:
        """
        Extracts and decodes candidate Base64 and hex-encoded spans that decode to
        printable UTF-8 text.
        """
        decoded_items: list[tuple[str, str]] = []
        if not text:
            return decoded_items

        for regex, decoder in (
            (cls.BASE64_CANDIDATE_RE, base64.b64decode),
            (cls.URLSAFE_BASE64_CANDIDATE_RE, base64.urlsafe_b64decode),
        ):
            for match in regex.finditer(text):
                token = match.group(1)
                if token.startswith(("ghp_", "github_pat_", "sk-", "AIza", "xox", "glpat-")):
                    continue
                stripped = token.rstrip("=")
                if len(stripped) % 4 == 1:
                    continue
                padded = stripped + ("=" * ((4 - len(stripped) % 4) % 4))
                try:
                    raw_bytes = decoder(padded.encode("ascii"))
                    if len(raw_bytes) < 12:
                        continue
                    decoded_str = raw_bytes.decode("utf-8")
                    printable_ratio = sum(
                        1 for c in decoded_str if c.isprintable() or c in "\r\n\t"
                    ) / max(len(decoded_str), 1)
                    if printable_ratio >= 0.85 and any(c.isalpha() for c in decoded_str):
                        decoded_items.append((token, decoded_str))
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue

        for match in cls.HEX_ESCAPE_RE.finditer(text):
            span = match.group(0)
            hex_digits = span.replace("\\x", "")
            try:
                decoded_str = bytes.fromhex(hex_digits).decode("utf-8")
                if any(c.isalpha() for c in decoded_str):
                    decoded_items.append((span, decoded_str))
            except (ValueError, UnicodeDecodeError):
                continue

        for match in cls.CONTIGUOUS_HEX_RE.finditer(text):
            span = match.group(0)
            # Ignore uniform repeated test hashes like 'a' * 64
            if len(set(span.lower())) <= 2:
                continue
            try:
                raw_bytes = bytes.fromhex(span)
                decoded_str = raw_bytes.decode("utf-8")
                printable_ratio = sum(
                    1 for c in decoded_str if c.isprintable() or c in "\r\n\t"
                ) / max(len(decoded_str), 1)
                if printable_ratio >= 0.90 and " " in decoded_str:
                    decoded_items.append((span, decoded_str))
            except (ValueError, UnicodeDecodeError):
                continue

        return decoded_items

    @classmethod
    def scan_python_ast(cls, text: str) -> str | None:
        """
        Uses Python's `ast` module to inspect candidate code blocks or expressions
        for dangerous execution sinks or sandbox-escape dunder traversal.
        """
        if not text:
            return None

        # Quick check for dunder traversal even inside malformed code fragments
        for dunder in cls.DANGEROUS_DUNDERS:
            if dunder in text:
                return f"ast_dunder:{dunder}"

        snippets: list[str] = [text.strip()]
        # Also extract fenced markdown blocks and individual lines that look like calls
        for block in re.findall(r"```(?:python|py)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE):
            if block.strip():
                snippets.append(block.strip())
        for line in text.splitlines():
            stripped = line.strip()
            if "(" in stripped and ")" in stripped:
                snippets.append(stripped)

        for snippet in snippets:
            if not snippet or len(snippet) > 8000:
                continue
            try:
                tree = ast.parse(snippet)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = cls._resolve_ast_call_name(node.func)
                    if call_name in cls.DANGEROUS_AST_CALLS:
                        return f"ast_call:{call_name}"
                elif isinstance(node, ast.Attribute):
                    if node.attr in cls.DANGEROUS_DUNDERS:
                        return f"ast_dunder:{node.attr}"
        return None

    @staticmethod
    def _resolve_ast_call_name(func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts: list[str] = [func_node.attr]
            curr = func_node.value
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return ""

    @classmethod
    def scan_paraphrased_override(cls, text: str) -> str | None:
        """
        Detects paraphrased instruction overrides, persona coercion, and high-entropy
        decode-sink combinations using token-set and entropy heuristics.
        """
        if not text:
            return None

        norm = cls.normalize_confusables(text)
        lower_full = norm.lower()

        # Check high-entropy obfuscated token combined with decode/exec sink keywords
        if any(kw in lower_full for kw in cls.DECODE_SINK_KEYWORDS):
            for tok in re.findall(r"[A-Za-z0-9+/=_-]{24,}", norm):
                if cls.shannon_entropy(tok) >= 4.15:
                    return f"high_entropy_decode_sink:{tok[:24]}"

        clauses = re.split(r"[\r\n.!?;]+", lower_full)
        for clause in clauses:
            clause_str = clause.strip()
            if not clause_str:
                continue
            words = set(re.findall(r"[a-z]+", clause_str))
            if not words:
                continue

            has_override_verb = bool(words & cls.OVERRIDE_VERBS) or any(
                phrase in clause_str for phrase in cls.OVERRIDE_PHRASE_VERBS
            )
            has_authority_mod = bool(words & cls.AUTHORITY_MODIFIERS)
            has_authority_target = bool(words & cls.AUTHORITY_TARGETS)

            if has_override_verb and has_authority_target and (
                has_authority_mod or len(words & cls.AUTHORITY_TARGETS) >= 1
            ):
                return clause_str[:80]

            # Persona / unrestricted coercion
            if any(
                p in clause_str
                for p in (
                    "without restrictions",
                    "no restrictions",
                    "unrestricted mode",
                    "uncensored mode",
                    "new system directive",
                    "new developer directive",
                    "authorized by admin",
                    "sudo mode",
                )
            ):
                return clause_str[:80]

            # Paraphrased secret/prompt exfiltration imperative
            if (words & cls.EXFIL_VERBS) and (words & cls.EXFIL_TARGETS):
                return clause_str[:80]

        return None


class SemanticAirlock:
    """
    Bidirectional Typed Semantic Airlock:
      - Outbound: validates ActionID allowlist, strict parameter keys/types, and blocks
        natural-language prompt injection, shell escapes, or permission-bypass flags.
      - Inbound: wraps untrusted tool/model responses into inert quarantined blobs and
        neutralizes embedded prompt-injection directives (including homoglyph, Base64/hex,
        structural AST, and paraphrased overrides) before any downstream model sees them.
    """

    ALLOWED_PARAM_KEYS: dict[ActionID, frozenset[str]] = {
        ActionID.READ_ARTIFACT: frozenset({"path", "max_lines"}),
        ActionID.PROPOSE_DIFF: frozenset({"path", "patch_sha256", "summary", "lines_changed"}),
        ActionID.RUN_PINPOINT_SUITE: frozenset({"suite_name", "target_binary", "timeout_sec"}),
        ActionID.SYNTHESIZE_FORK: frozenset({"track_id", "decision_topic"}),
        ActionID.EXECUTE_EGRESS: frozenset({"provider", "operation", "target_domain", "phantom_handle", "method"}),
        ActionID.GIT_COMMIT_LOCAL: frozenset({"branch", "commit_message", "files"}),
        ActionID.GIT_PUSH_REMOTE: frozenset({"remote", "branch", "phantom_handle"}),
        ActionID.QUARANTINE_INGEST: frozenset({"source_label", "archive_sha256"}),
    }

    INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
        re.compile(p, re.IGNORECASE | re.DOTALL)
        for p in (
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
            r"disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|constraints|rules)",
            r"system\s+override",
            r"you\s+are\s+now\s+(in\s+)?(developer|unrestricted|god|jailbreak)\s+mode",
            r"<\s*/?\s*(system|instruction|tool_call|function_calls)\s*>",
            r"\[\s*INST\s*\]|\<\|\s*im_start\s*\|\>\s*system",
            r"dangerouslySkipPermissions",
            r"--sandbox\s*=\s*none",
            r"--no-verify",
            r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b",
            r"\brmdir(\.exe)?\s+.*(/[sS]|--recursive)",
            r"\bformat\s+[a-zA-Z]:",
            r"\bdel(\.exe)?\s+.*(/[sS]|/[fF]|/[qQ])",
            r"\b(Invoke-Expression|iex)\s*\(",
            r"(curl|wget)\s+[^|]+\|\s*(ba)?sh",
            r"\bdrop\s+(table|database)\b",
            r"exfiltrate\s+(credentials|secrets|tokens|keys)",
        )
    )

    @classmethod
    def _scan_text_for_injection(cls, text: str) -> str | None:
        if not text:
            return None
        for pattern in cls.INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)

        normalized = StructuralHeuristicScanner.normalize_confusables(text)
        if normalized != text:
            for pattern in cls.INJECTION_PATTERNS:
                match = pattern.search(normalized)
                if match:
                    return f"homoglyph_obfuscated:{match.group(0)}"

        for raw_span, decoded in StructuralHeuristicScanner.extract_decoded_payloads(text):
            norm_decoded = StructuralHeuristicScanner.normalize_confusables(decoded)
            for pattern in cls.INJECTION_PATTERNS:
                if pattern.search(decoded) or pattern.search(norm_decoded):
                    return f"encoded_payload:{raw_span[:24]}"
            if (
                StructuralHeuristicScanner.scan_python_ast(decoded)
                or StructuralHeuristicScanner.scan_paraphrased_override(norm_decoded)
            ):
                return f"encoded_payload:{raw_span[:24]}"

        ast_hit = StructuralHeuristicScanner.scan_python_ast(text)
        if ast_hit:
            return ast_hit

        paraphrase_hit = StructuralHeuristicScanner.scan_paraphrased_override(normalized)
        if paraphrase_hit:
            return f"paraphrased_override:{paraphrase_hit}"

        return None

    @classmethod
    def build_outbound_envelope(
        cls,
        action_id: ActionID | str,
        source_agent: str,
        target_agent: str,
        typed_params: dict[str, Any],
        taint_level: TaintLevel = TaintLevel.INTERNAL_AGENT,
        untrusted_blob: str = "",
    ) -> SemanticEnvelope:
        """Validates outbound cross-agent / tool request and constructs a locked SemanticEnvelope."""
        try:
            resolved_action = ActionID(action_id)
        except ValueError as exc:
            raise SecurityViolationError(f"Unrecognized ActionID '{action_id}'.") from exc

        if not isinstance(typed_params, dict):
            raise SecurityViolationError("typed_params must be a JSON-serializable dict.")

        allowed_keys = cls.ALLOWED_PARAM_KEYS[resolved_action]
        unknown_keys = set(typed_params.keys()) - allowed_keys
        if unknown_keys:
            raise SecurityViolationError(
                f"Disallowed parameter keys for {resolved_action.value}: {sorted(unknown_keys)}"
            )

        # Ensure strict JSON serializability and scan all string fields for outbound injection
        try:
            serialized = json.dumps(typed_params, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise SecurityViolationError("typed_params contains non-JSON-serializable values.") from exc

        matched = cls._scan_text_for_injection(serialized)
        if matched:
            raise SecurityViolationError(
                f"Outbound Semantic Airlock blocked injection pattern in typed_params: '{matched}'"
            )

        # If an untrusted blob is carried alongside, sanitize it so it stays passive
        sanitized_blob, blob_injected = cls._neutralize_inbound_text(untrusted_blob)
        if blob_injected:
            effective_taint = TaintLevel.UNTRUSTED_EXTERNAL
        elif untrusted_blob:
            effective_taint = TaintLattice.combine(taint_level, TaintLevel.QUARANTINED_DATA)
        else:
            effective_taint = taint_level

        return SemanticEnvelope(
            action_id=resolved_action,
            source_agent=source_agent,
            target_agent=target_agent,
            typed_params=dict(typed_params),
            taint_level=effective_taint,
            untrusted_blob=sanitized_blob,
            quarantined=True,
            injection_detected=blob_injected,
        )

    @classmethod
    def _neutralize_inbound_text(cls, raw_text: str) -> tuple[str, bool]:
        if not raw_text:
            return "", False
        sanitized = raw_text
        detected = False
        for pattern in cls.INJECTION_PATTERNS:
            if pattern.search(sanitized):
                detected = True
                sanitized = pattern.sub("[AIRLOCK_NEUTRALIZED_DIRECTIVE]", sanitized)

        # Neutralize Base64 / hex encoded injection payloads
        for raw_span, decoded in StructuralHeuristicScanner.extract_decoded_payloads(sanitized):
            if cls._scan_text_for_injection(decoded):
                detected = True
                sanitized = sanitized.replace(raw_span, "[AIRLOCK_NEUTRALIZED_DIRECTIVE]")

        # Line-by-line structural AST, homoglyph, and paraphrased override neutralization
        out_lines: list[str] = []
        for line in sanitized.splitlines():
            norm_line = StructuralHeuristicScanner.normalize_confusables(line)
            line_flagged = False
            for pattern in cls.INJECTION_PATTERNS:
                if pattern.search(norm_line):
                    line_flagged = True
                    break
            if not line_flagged and (
                StructuralHeuristicScanner.scan_python_ast(line)
                or StructuralHeuristicScanner.scan_paraphrased_override(norm_line)
            ):
                line_flagged = True

            if line_flagged:
                detected = True
                out_lines.append("[AIRLOCK_NEUTRALIZED_DIRECTIVE]")
            else:
                out_lines.append(line)

        if detected:
            sanitized = "\n".join(out_lines)
        return sanitized, detected

    @classmethod
    def inspect_inbound_result(
        cls,
        action_id: ActionID,
        source_agent: str,
        target_agent: str,
        raw_result: str | dict[str, Any],
        source_taint: TaintLevel = TaintLevel.UNTRUSTED_EXTERNAL,
    ) -> SemanticEnvelope:
        """
        Inspects and sanitizes inbound tool/platform results before delivering to an agent.
        Forces UNTRUSTED_EXTERNAL taint if prompt injection is detected in the inbound payload.
        """
        raw_str = (
            json.dumps(raw_result, sort_keys=True)
            if isinstance(raw_result, dict)
            else str(raw_result)
        )
        sanitized_str, detected = cls._neutralize_inbound_text(raw_str)
        final_taint = (
            TaintLevel.UNTRUSTED_EXTERNAL
            if detected
            else TaintLattice.combine(source_taint, TaintLevel.QUARANTINED_DATA)
        )
        return SemanticEnvelope(
            action_id=action_id,
            source_agent=source_agent,
            target_agent=target_agent,
            typed_params={},
            taint_level=final_taint,
            untrusted_blob=sanitized_str,
            quarantined=True,
            injection_detected=detected,
        )


# ============================================================================
# 3. APPLICATION-LAYER PHANTOM TOKEN BROKER
# ============================================================================


@dataclass(frozen=True)
class _VaultEntry:
    provider: str
    operation: str
    raw_secret: str
    allowed_domains: frozenset[str]
    handle_id: str
    expires_at: float


class PhantomTokenBroker:
    """
    Application-Layer Phantom Token Broker:
      - Provisions opaque handles (`phantom://<provider>/<op>` and `phantom://<provider>/<op>/<hmac>`)
      - Scrubs raw secrets from prompts/context so subagents never hold live credentials
      - Swaps phantom handles for live credentials ONLY at the verified egress boundary
        for matching allowed domains.
    """

    RAW_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
        re.compile(p)
        for p in (
            r"\bghp_[A-Za-z0-9]{20,}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            r"\bxox[baprs]-[A-Za-z0-9-]{15,}\b",
            r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        )
    )

    def __init__(self, broker_key: bytes | None = None) -> None:
        self._broker_key = broker_key or secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._vault: dict[tuple[str, str], _VaultEntry] = {}
        self._handle_index: dict[str, tuple[str, str]] = {}

    def register_secret(
        self,
        provider: str,
        operation: str,
        raw_secret: str,
        allowed_domains: set[str] | list[str] | tuple[str, ...],
        ttl_seconds: float = 3600.0,
    ) -> str:
        """Registers a secret in the enclave and returns its canonical phantom handle."""
        prov = provider.strip().lower()
        op = operation.strip().lower()
        if not prov or not op or not raw_secret:
            raise ValueError("provider, operation, and raw_secret must be non-empty.")
        domains = frozenset(d.strip().lower() for d in allowed_domains if d.strip())
        if not domains:
            raise ValueError("At least one allowed egress domain is required.")

        sig = hmac.new(
            self._broker_key,
            f"{prov}:{op}:{raw_secret}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]
        short_handle = f"phantom://{prov}/{op}"
        signed_handle = f"phantom://{prov}/{op}/{sig}"

        entry = _VaultEntry(
            provider=prov,
            operation=op,
            raw_secret=raw_secret,
            allowed_domains=domains,
            handle_id=signed_handle,
            expires_at=time.time() + ttl_seconds,
        )
        with self._lock:
            prev = self._vault.get((prov, op))
            if prev is not None and prev.handle_id != signed_handle:
                self._handle_index.pop(prev.handle_id, None)
            self._vault[(prov, op)] = entry
            self._handle_index[short_handle] = (prov, op)
            self._handle_index[signed_handle] = (prov, op)
        return signed_handle

    def scrub_for_subagent(self, payload: Any) -> Any:
        """
        Recursively scrubs any raw registered secrets or recognizable API keys from
        strings, dicts (keys and values), lists, tuples, or sets before passing context to a subagent.
        """
        with self._lock:
            if isinstance(payload, str):
                scrubbed = payload
                for (prov, op), entry in self._vault.items():
                    if entry.raw_secret in scrubbed:
                        scrubbed = scrubbed.replace(entry.raw_secret, f"phantom://{prov}/{op}")
                for pattern in self.RAW_CREDENTIAL_PATTERNS:
                    scrubbed = pattern.sub("phantom://redacted/credential", scrubbed)
                return scrubbed
            if isinstance(payload, dict):
                return {
                    self.scrub_for_subagent(k): self.scrub_for_subagent(v)
                    for k, v in payload.items()
                }
            if isinstance(payload, list):
                return [self.scrub_for_subagent(item) for item in payload]
            if isinstance(payload, tuple):
                return tuple(self.scrub_for_subagent(item) for item in payload)
            if isinstance(payload, set):
                return {self.scrub_for_subagent(item) for item in payload}
            if isinstance(payload, frozenset):
                return frozenset(self.scrub_for_subagent(item) for item in payload)
            return payload

    def assert_no_raw_credentials(self, payload: Any) -> None:
        """Raises SecurityViolationError if any raw credential exists in the payload."""
        serialized = (
            json.dumps(payload, default=list) if not isinstance(payload, str) else payload
        )
        with self._lock:
            for (prov, op), entry in self._vault.items():
                if entry.raw_secret in serialized:
                    raise SecurityViolationError(
                        f"Raw secret for {prov}/{op} leaked into subagent context!"
                    )
        for pattern in self.RAW_CREDENTIAL_PATTERNS:
            if pattern.search(serialized):
                raise SecurityViolationError(
                    "Raw credential pattern detected in subagent payload!"
                )

    def resolve_at_egress(
        self,
        phantom_handle: str,
        target_domain: str,
        now_ts: float | None = None,
    ) -> str:
        """
        Swaps a `phantom://provider/op` handle for the underlying secret at the
        application-layer egress boundary after verifying domain pinning and TTL.
        """
        handle = phantom_handle.strip()
        if not handle.startswith("phantom://"):
            raise SecurityViolationError(
                f"Invalid phantom token handle '{handle}': must start with 'phantom://'."
            )
        with self._lock:
            key = self._handle_index.get(handle)
            if key is None:
                raise SecurityViolationError(f"Unknown or revoked phantom handle '{handle}'.")
            entry = self._vault[key]

        current_time = time.time() if now_ts is None else now_ts
        if current_time > entry.expires_at:
            raise SecurityViolationError(f"Phantom handle '{handle}' has expired.")

        norm_domain = target_domain.strip().lower()
        if norm_domain not in entry.allowed_domains:
            raise SecurityViolationError(
                f"Phantom egress blocked: handle '{handle}' is pinned to {sorted(entry.allowed_domains)}, "
                f"cannot egress to '{norm_domain}'."
            )
        return entry.raw_secret


# ============================================================================
# 4. INSTRUCTION-FILE INTEGRITY GUARD
# ============================================================================


@dataclass(frozen=True)
class IntegrityReport:
    """Result of verifying workspace instruction files against a locked SHA-256 manifest."""

    is_clean: bool
    verified_count: int
    modified: tuple[str, ...]
    added: tuple[str, ...]
    deleted: tuple[str, ...]


class InstructionIntegrityGuard:
    """
    Guards `AGENTS.md`, `CLAUDE.md`, `.agents/**`, `.claude/**`, `.cursor/**`, and `.gemini/**`
    using SHA-256 baselines to block lateral cross-agent persistence.
    """

    PROTECTED_GLOBS: tuple[str, ...] = (
        "AGENTS.md",
        "CLAUDE.md",
        "**/AGENTS.md",
        "**/CLAUDE.md",
        ".agents/**",
        ".claude/**",
        ".cursor/**",
        ".gemini/**",
    )

    PROTECTED_SEGMENTS: frozenset[str] = frozenset(
        {"agents.md", "claude.md", ".agents", ".claude", ".cursor", ".gemini"}
    )

    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self._lock = threading.RLock()
        self.baseline_hashes: dict[str, str] = {}
        self.refresh_baseline()

    @classmethod
    def is_protected_path(cls, rel_path: str) -> bool:
        raw = rel_path.replace("\\", "/").strip().strip("/")
        if not raw:
            return False
        norm = posixpath.normpath(raw)
        if norm == "." or not norm:
            return False
        # Block any '..' path traversal attempting to escape the workspace root
        if norm == ".." or norm.startswith("../"):
            return True
        norm_lower = norm.lower()
        parts = [p for p in norm_lower.split("/") if p and p != "."]
        if any(seg in cls.PROTECTED_SEGMENTS for seg in parts):
            return True
        for pattern in cls.PROTECTED_GLOBS:
            pat_lower = pattern.lower()
            if fnmatch.fnmatchcase(norm_lower, pat_lower):
                return True
            if pat_lower.endswith("/**") and norm_lower.startswith(pat_lower[:-2]):
                return True
        return False

    def _scan_protected_files(self) -> dict[str, str]:
        hashes: dict[str, str] = {}
        if not self.workspace_root.exists():
            return hashes
        for file_path in sorted(self.workspace_root.rglob("*")):
            try:
                if not file_path.is_file():
                    continue
                rel = file_path.relative_to(self.workspace_root).as_posix()
                if self.is_protected_path(rel):
                    digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
                    hashes[rel] = digest
            except OSError:
                continue
        return hashes

    def refresh_baseline(self) -> dict[str, str]:
        with self._lock:
            self.baseline_hashes = self._scan_protected_files()
            return dict(self.baseline_hashes)

    def verify_workspace(self) -> IntegrityReport:
        with self._lock:
            current = self._scan_protected_files()
            baseline_snapshot = dict(self.baseline_hashes)
        modified: list[str] = []
        added: list[str] = []
        deleted: list[str] = []

        for rel, base_sha in sorted(baseline_snapshot.items()):
            if rel not in current:
                deleted.append(rel)
            elif not hmac.compare_digest(current[rel], base_sha):
                modified.append(rel)

        for rel in sorted(current.keys()):
            if rel not in baseline_snapshot:
                added.append(rel)

        is_clean = not (modified or added or deleted)
        return IntegrityReport(
            is_clean=is_clean,
            verified_count=len(current),
            modified=tuple(modified),
            added=tuple(added),
            deleted=tuple(deleted),
        )

    def assert_workspace_clean(self) -> IntegrityReport:
        report = self.verify_workspace()
        if not report.is_clean:
            raise SecurityViolationError(
                f"Instruction-File Integrity Guard triggered! "
                f"modified={list(report.modified)}, added={list(report.added)}, deleted={list(report.deleted)}"
            )
        return report

    def guard_proposed_paths(self, touched_paths: list[str], taint_level: TaintLevel) -> None:
        """Blocks any non-HUMAN_VERIFIED write to protected instruction files."""
        for p in touched_paths:
            if self.is_protected_path(p) and taint_level < TaintLevel.HUMAN_VERIFIED:
                raise SecurityViolationError(
                    f"Lateral persistence blocked: protected instruction file '{p}' "
                    f"cannot be modified at taint level {taint_level.name}."
                )


# ============================================================================
# 5. 5-SPEED AUTONOMY GEARBOX, RULE-OF-3 FORKING & DUALSENSE HAPTIC FRICTION
# ============================================================================


class AutonomyGear(IntEnum):
    """5-Speed Autonomy Gearbox for Human-Agency Steering."""

    G0_EBRAKE_STOP = 0
    G1_CLUTCH_MANUAL = 1
    G2_SPORT_TACTILE = 2
    G3_ARBITER_CRUISE = 3
    G4_SLOW_SIMMER_OVERNIGHT = 4


class ForkArchetype(str, Enum):
    """Mandatory Rule-of-3 Creative Tradeoff Archetypes."""

    CONSERVATIVE = "Conservative"
    BALANCED = "Balanced"
    VISIONARY = "Visionary"


@dataclass(frozen=True)
class ForkOption:
    """Single strategic branch in a 3-Way Creative Steering Fork."""

    archetype: ForkArchetype
    title: str
    summary: str
    tradeoffs: str
    blast_radius: int


@dataclass
class TradeoffFork:
    """
    Enforces the Mandatory Rule-of-3 Creative Tradeoff Forking invariant
    (Conservative, Balanced, Visionary + custom human override).
    Never allows a single-option fait accompli monolith.
    """

    decision_topic: str
    options: tuple[ForkOption, ...]
    selected_archetype: str | None = None
    custom_override: str | None = None

    def __post_init__(self) -> None:
        if not self.decision_topic or not self.decision_topic.strip():
            raise ValueError("decision_topic must be non-empty.")
        if len(self.options) != 3:
            raise SecurityViolationError(
                f"Rule-of-3 violation: expected exactly 3 ForkOptions, got {len(self.options)}."
            )
        required = {
            ForkArchetype.CONSERVATIVE,
            ForkArchetype.BALANCED,
            ForkArchetype.VISIONARY,
        }
        present = {opt.archetype for opt in self.options}
        if present != required:
            raise SecurityViolationError(
                f"Rule-of-3 violation: options must cover {sorted(a.value for a in required)}, "
                f"got {sorted(a.value for a in present)}."
            )
        summaries = {opt.summary.strip() for opt in self.options}
        if len(summaries) < 3 or any(not s for s in summaries):
            raise SecurityViolationError(
                "Rule-of-3 violation: all 3 fork options must have distinct non-empty summaries."
            )
        for opt in self.options:
            if not (0 <= opt.blast_radius <= 100):
                raise ValueError(f"Blast radius must be in [0, 100], got {opt.blast_radius}.")

    def resolve_choice(
        self,
        selection: str | ForkArchetype,
        custom_override: str | None = None,
    ) -> dict[str, Any]:
        """Records the human driver's selection among the 3 archetypes or a custom hybrid override."""
        if custom_override and custom_override.strip():
            self.selected_archetype = "Custom"
            self.custom_override = custom_override.strip()
            return {
                "decision_topic": self.decision_topic,
                "mode": "Custom",
                "steering_vector": self.custom_override,
            }

        sel_str = selection.value if isinstance(selection, ForkArchetype) else str(selection).strip()
        for opt in self.options:
            if opt.archetype.value.lower() == sel_str.lower():
                self.selected_archetype = opt.archetype.value
                self.custom_override = None
                return {
                    "decision_topic": self.decision_topic,
                    "mode": opt.archetype.value,
                    "title": opt.title,
                    "summary": opt.summary,
                    "blast_radius": opt.blast_radius,
                }
        raise ValueError(
            f"Unknown fork selection '{sel_str}'. Choose Conservative, Balanced, Visionary, or provide custom_override."
        )


@dataclass(frozen=True)
class DualSenseHapticPacket:
    """
    64-byte DualSense USB HID Output Report 0x02 encoding Asymmetric Blast-Radius Friction:
      - B(a) < 20: Trigger Mode 0x00 (Off), Cyan lightbar (0, 180, 255)
      - 20 <= B(a) < 70: Trigger Mode 0x05 (Soft spring), Amber lightbar (255, 165, 0)
      - B(a) >= 70: Right Trigger Mode 0x21 (Hard static detent) + Left Trigger Mode 0x26
        (40 Hz active warning vibration), Crimson lightbar (255, 20, 20)
    """

    blast_radius: int
    right_trigger_mode: int
    left_trigger_mode: int
    lightbar_rgb: tuple[int, int, int]
    raw_report_64b: bytes

    @classmethod
    def for_blast_radius(cls, blast_radius: int) -> DualSenseHapticPacket:
        if not (0 <= blast_radius <= 100):
            raise ValueError(f"Blast radius B(a) must be in [0, 100], got {blast_radius}.")

        buf = bytearray(64)
        buf[0] = 0x02  # USB Output Report ID 0x02
        buf[1] = 0xFF  # Valid flag byte 1
        buf[2] = 0xF7  # Valid flag byte 2

        if blast_radius < 20:
            r_mode = 0x00
            l_mode = 0x00
            rgb = (0, 180, 255)
        elif blast_radius < 70:
            r_mode = 0x05
            l_mode = 0x05
            buf[11] = r_mode
            buf[12] = 0x40
            buf[13] = 0x60
            buf[22] = l_mode
            buf[23] = 0x40
            buf[24] = 0x60
            rgb = (255, 165, 0)
        else:
            # High-blast hard detent: R2 static resistance 0x21 + L2 40Hz vibration pulse 0x26
            r_mode = 0x21
            l_mode = 0x26
            buf[3] = 180   # Right high-frequency rumble motor
            buf[4] = 220   # Left low-frequency rumble motor
            buf[11] = r_mode
            buf[12] = 0x90  # Detent start position
            buf[13] = 0xFF  # Maximum static resistance force
            buf[22] = l_mode
            buf[23] = 40    # 40 Hz tactile warning judder
            buf[24] = 0xE0  # High vibration amplitude
            rgb = (255, 20, 20)

        buf[45], buf[46], buf[47] = rgb
        return cls(
            blast_radius=blast_radius,
            right_trigger_mode=r_mode,
            left_trigger_mode=l_mode,
            lightbar_rgb=rgb,
            raw_report_64b=bytes(buf),
        )


@dataclass(frozen=True)
class GearEvaluationDecision:
    """Decision emitted by the 5-Speed Autonomy Gearbox for a proposed action."""

    allowed_autonomously: bool
    requires_human_ratification: bool
    halted: bool
    gear: AutonomyGear
    blast_radius: int
    haptic_packet: DualSenseHapticPacket
    reason: str
    haptic_receipt: HapticTransmissionReceipt | None = None
    hardware_transmitted: bool = False
    transmission_mode: str = "in_memory_fallback"


class AutonomyGearbox:
    """
    5-Speed Autonomy Gearbox & Asymmetric Blast-Radius Gatekeeper.
    Integrates with `DualSenseHidBridge` to transmit 64-byte USB Report `0x02`
    tactile confirmation packets (`0x21`/`0x26`) to live DualSense hardware when
    `probe_hardware=True`, with deterministic in-memory 64-byte packet verification fallback.
    """

    DEFAULT_BLAST_SCORES: dict[ActionID, int] = {
        ActionID.READ_ARTIFACT: 5,
        ActionID.QUARANTINE_INGEST: 10,
        ActionID.SYNTHESIZE_FORK: 15,
        ActionID.RUN_PINPOINT_SUITE: 25,
        ActionID.PROPOSE_DIFF: 40,
        ActionID.GIT_COMMIT_LOCAL: 55,
        ActionID.EXECUTE_EGRESS: 85,
        ActionID.GIT_PUSH_REMOTE: 90,
    }

    def __init__(
        self,
        initial_gear: AutonomyGear = AutonomyGear.G2_SPORT_TACTILE,
        hid_bridge: DualSenseHidBridge | None = None,
        probe_hardware: bool = False,
    ) -> None:
        self.current_gear: AutonomyGear = initial_gear
        self.hid_bridge: DualSenseHidBridge = hid_bridge or DualSenseHidBridge()
        self.probe_hardware: bool = probe_hardware

    def shift_gear(self, new_gear: AutonomyGear) -> AutonomyGear:
        self.current_gear = AutonomyGear(new_gear)
        return self.current_gear

    def engage_ebrake(self) -> AutonomyGear:
        """Immediate atomic halt (G0_EBRAKE_STOP)."""
        self.current_gear = AutonomyGear.G0_EBRAKE_STOP
        return self.current_gear

    @classmethod
    def compute_blast_radius(
        cls,
        action_id: ActionID,
        override_score: int | None = None,
        touches_protected_files: bool = False,
    ) -> int:
        if touches_protected_files:
            return 95
        if override_score is not None:
            if not (0 <= override_score <= 100):
                raise ValueError("override_score must be in [0, 100].")
            return override_score
        return cls.DEFAULT_BLAST_SCORES.get(action_id, 50)

    def _build_decision(
        self,
        *,
        allowed_autonomously: bool,
        requires_human_ratification: bool,
        halted: bool,
        score: int,
        packet: DualSenseHapticPacket,
        receipt: HapticTransmissionReceipt,
        reason: str,
    ) -> GearEvaluationDecision:
        return GearEvaluationDecision(
            allowed_autonomously=allowed_autonomously,
            requires_human_ratification=requires_human_ratification,
            halted=halted,
            gear=self.current_gear,
            blast_radius=score,
            haptic_packet=packet,
            reason=reason,
            haptic_receipt=receipt,
            hardware_transmitted=receipt.transmitted_to_hardware,
            transmission_mode=receipt.mode,
        )

    def evaluate_action(
        self,
        action_id: ActionID,
        taint_level: TaintLevel,
        blast_radius: int | None = None,
        consensus_models: int = 1,
        target_branch: str = "main",
        human_ratified: bool = False,
        probe_hardware: bool | None = None,
    ) -> GearEvaluationDecision:
        score = self.compute_blast_radius(action_id, override_score=blast_radius)
        packet = DualSenseHapticPacket.for_blast_radius(score)
        effective_probe = self.probe_hardware if probe_hardware is None else bool(probe_hardware)
        receipt = self.hid_bridge.transmit_haptic_packet(packet, probe_hardware=effective_probe)

        # G0: E-Brake halts everything unconditionally
        if self.current_gear == AutonomyGear.G0_EBRAKE_STOP:
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=False,
                halted=True,
                score=score,
                packet=packet,
                receipt=receipt,
                reason="G0_EBRAKE_STOP engaged: all runner execution atomically halted.",
            )

        if human_ratified:
            return self._build_decision(
                allowed_autonomously=True,
                requires_human_ratification=False,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason="Explicit human steering ratification verified.",
            )

        # UNTRUSTED_EXTERNAL taint is restricted strictly to QUARANTINE_INGEST unless promoted or ratified
        if taint_level == TaintLevel.UNTRUSTED_EXTERNAL and action_id != ActionID.QUARANTINE_INGEST:
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=True,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason=(
                    f"Taint level {taint_level.name} cannot execute {action_id.value} autonomously "
                    "without PINPOINT promotion or human ratification."
                ),
            )

        # High blast radius B(a) >= 70 ALWAYS requires deliberate human tactile/signed ratification
        if score >= 70:
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=True,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason=(
                    f"High blast radius B(a)={score} >= 70: requires DualSense 0x21/0x26 "
                    "tactile detent pull or cryptographic human signature."
                ),
            )

        # G1: Manual clutch requires confirmation for any non-zero action
        if self.current_gear == AutonomyGear.G1_CLUTCH_MANUAL:
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=True,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason="G1_CLUTCH_MANUAL requires step-by-step human confirmation.",
            )

        # G2: Sport tactile allows read/low-blast (<20) autonomously, pauses for writes (>=20)
        if self.current_gear == AutonomyGear.G2_SPORT_TACTILE:
            if score < 20:
                return self._build_decision(
                    allowed_autonomously=True,
                    requires_human_ratification=False,
                    halted=False,
                    score=score,
                    packet=packet,
                    receipt=receipt,
                    reason="G2_SPORT_TACTILE: low-blast read/synthesis permitted autonomously.",
                )
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=True,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason=f"G2_SPORT_TACTILE: B(a)={score} >= 20 pauses for interactive diff review.",
            )

        # G3: Arbiter Cruise auto-approves B(a) < 70 iff consensus_models >= 2 and PINPOINT_VERIFIED
        if self.current_gear == AutonomyGear.G3_ARBITER_CRUISE:
            if score < 20:
                return self._build_decision(
                    allowed_autonomously=True,
                    requires_human_ratification=False,
                    halted=False,
                    score=score,
                    packet=packet,
                    receipt=receipt,
                    reason="G3_ARBITER_CRUISE: low-blast operation permitted.",
                )
            if consensus_models >= 2 and taint_level >= TaintLevel.PINPOINT_VERIFIED:
                return self._build_decision(
                    allowed_autonomously=True,
                    requires_human_ratification=False,
                    halted=False,
                    score=score,
                    packet=packet,
                    receipt=receipt,
                    reason=(
                        f"G3_ARBITER_CRUISE: multi-model consensus ({consensus_models}) + "
                        f"{taint_level.name} passed."
                    ),
                )
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=True,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason=(
                    "G3_ARBITER_CRUISE: requires >=2 model consensus and PINPOINT_VERIFIED "
                    "for autonomous local mutation."
                ),
            )

        # G4: Slow Simmer Overnight allows B(a) < 70 only on isolated simmer/* branches for internal agents
        if self.current_gear == AutonomyGear.G4_SLOW_SIMMER_OVERNIGHT:
            if score < 20 or (target_branch.startswith("simmer/") and taint_level >= TaintLevel.INTERNAL_AGENT):
                return self._build_decision(
                    allowed_autonomously=True,
                    requires_human_ratification=False,
                    halted=False,
                    score=score,
                    packet=packet,
                    receipt=receipt,
                    reason=f"G4_SLOW_SIMMER_OVERNIGHT: isolated branch '{target_branch}' operation permitted.",
                )
            return self._build_decision(
                allowed_autonomously=False,
                requires_human_ratification=True,
                halted=False,
                score=score,
                packet=packet,
                receipt=receipt,
                reason=(
                    f"G4_SLOW_SIMMER_OVERNIGHT: mutations on non-isolated branch '{target_branch}' "
                    "are blocked until morning briefing ratification."
                ),
            )

        raise ValueError(f"Unhandled gear: {self.current_gear}")

    def verify_dualsense_input_ratification(
        self,
        input_report_64b: bytes,
        blast_radius: int,
    ) -> bool:
        """
        Evaluates a 64-byte DualSense USB Input Report 0x01 for physical driver ratification:
          - Touchpad Click (byte 10 & 0x02) -> immediately engages G0_EBRAKE_STOP and returns False.
          - B(a) >= 70 -> requires R2 pedal (byte 5 >= 200, pulled past 0x21 detent) AND Cross (byte 8 & 0x20).
          - 20 <= B(a) < 70 -> requires R2 pedal (byte 5 >= 60) OR Cross (byte 8 & 0x20).
          - B(a) < 20 -> returns True.
        """
        if len(input_report_64b) != 64 or input_report_64b[0] != 0x01:
            raise ValueError("Expected 64-byte DualSense USB Input Report 0x01.")

        # Touchpad click (d[10] & 0x02) is the physical E-Brake
        if input_report_64b[10] & 0x02:
            self.engage_ebrake()
            return False

        r2_value = input_report_64b[5]
        cross_pressed = bool(input_report_64b[8] & 0x20)

        if blast_radius >= 70:
            return r2_value >= 200 and cross_pressed
        if blast_radius >= 20:
            return r2_value >= 60 or cross_pressed
        return True

    def poll_dualsense_ratification(
        self,
        blast_radius: int,
        probe_hardware: bool | None = None,
        fallback_report_64b: bytes | None = None,
    ) -> tuple[bool, str]:
        """
        Reads a 64-byte Input Report 0x01 via the Win32 HID bridge (or deterministic fallback)
        and evaluates physical driver ratification.
        """
        effective_probe = self.probe_hardware if probe_hardware is None else bool(probe_hardware)
        report_64b, mode = self.hid_bridge.read_input_report_0x01(
            probe_hardware=effective_probe,
            fallback_report_64b=fallback_report_64b,
        )
        return self.verify_dualsense_input_ratification(report_64b, blast_radius), mode


# ============================================================================
# 6. ZERO-DIRTY-LOGIC QUARANTINE SIEVE
# ============================================================================


@dataclass(frozen=True)
class QuarantinedSpec:
    """
    Sanitized domain specification distilled from tainted legacy notes or Drive archives.
    Always wrapped in `<tainted_raw_idea isolation="quarantined">` with QUARANTINED_DATA taint.
    """

    source: str
    raw_sha256: str
    quarantined_xml: str
    taint_level: TaintLevel
    dirty_patterns_stripped: int
    problem_statements: tuple[str, ...]
    mathematical_invariants: tuple[str, ...]
    domain_constraints: tuple[str, ...]


class QuarantineSieve:
    """
    Zero-Dirty-Logic Quarantine Sieve:
      - Ingests raw legacy transcripts / notes strictly as passive reference data
      - Strips prompt injections, imperative system overrides, homoglyph/Base64/AST
        obfuscations, and conversational loops
      - Emits `<tainted_raw_idea isolation="quarantined">` container + clean domain specs
    """

    DIRTY_LOGIC_PATTERNS: tuple[re.Pattern[str], ...] = (
        *SemanticAirlock.INJECTION_PATTERNS,
        re.compile(r"override\s+default\s+behavior", re.IGNORECASE),
        re.compile(r"execute\s+shell\s+command", re.IGNORECASE),
        re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
    )

    XML_BREAKOUT_PATTERN: re.Pattern[str] = re.compile(
        r"<\s*/?\s*tainted_raw_idea\b[^>]*>", re.IGNORECASE
    )

    @classmethod
    def sanitize_and_quarantine(cls, raw_text: str, source: str = "legacy_drive") -> QuarantinedSpec:
        raw_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        cleaned = raw_text
        stripped_count = 0

        for pattern in cls.DIRTY_LOGIC_PATTERNS:
            matches = pattern.findall(cleaned)
            if matches:
                stripped_count += len(matches)
                cleaned = pattern.sub("[QUARANTINED_DIRTY_LOGIC_REMOVED]", cleaned)

        # Strip Base64 / hex encoded dirty logic payloads
        for raw_span, decoded in StructuralHeuristicScanner.extract_decoded_payloads(cleaned):
            norm_decoded = StructuralHeuristicScanner.normalize_confusables(decoded)
            if (
                any(p.search(decoded) or p.search(norm_decoded) for p in cls.DIRTY_LOGIC_PATTERNS)
                or StructuralHeuristicScanner.scan_python_ast(decoded)
                or StructuralHeuristicScanner.scan_paraphrased_override(norm_decoded)
            ):
                stripped_count += 1
                cleaned = cleaned.replace(raw_span, "[QUARANTINED_DIRTY_LOGIC_REMOVED]")

        # Line-level homoglyph, structural AST, and paraphrased override sieve
        sieved_lines: list[str] = []
        for raw_line in cleaned.splitlines():
            if "[QUARANTINED_DIRTY_LOGIC_REMOVED]" in raw_line:
                sieved_lines.append(raw_line)
                continue
            norm_line = StructuralHeuristicScanner.normalize_confusables(raw_line)
            line_dirty = any(p.search(norm_line) for p in cls.DIRTY_LOGIC_PATTERNS)
            if not line_dirty and (
                StructuralHeuristicScanner.scan_python_ast(raw_line)
                or StructuralHeuristicScanner.scan_paraphrased_override(norm_line)
            ):
                line_dirty = True
            if line_dirty:
                stripped_count += 1
                sieved_lines.append("[QUARANTINED_DIRTY_LOGIC_REMOVED]")
            else:
                sieved_lines.append(raw_line)
        cleaned = "\n".join(sieved_lines)

        # Escape any case/whitespace variant of <tainted_raw_idea> or </tainted_raw_idea>
        safe_body = cls.XML_BREAKOUT_PATTERN.sub("&lt;/tainted_raw_idea&gt;", cleaned).strip()
        safe_source = html.escape(source, quote=True)
        xml_box = (
            f'<tainted_raw_idea source="{safe_source}" isolation="quarantined" sha256="{raw_sha}">\n'
            f"{safe_body}\n"
            f"</tainted_raw_idea>"
        )

        problems: list[str] = []
        math_invariants: list[str] = []
        constraints: list[str] = []

        for raw_line in safe_body.splitlines():
            line = raw_line.strip(" -*\t")
            if not line or "[QUARANTINED_DIRTY_LOGIC_REMOVED]" in line:
                continue
            lower = line.lower()
            dangerous_ast = (
                "eval(", "exec(", "__import__(", "os.system(", "subprocess.",
                "shutil.", "pty.", "open(", "socket.", "__class__", "__subclasses__"
            )
            if any(tok in line for tok in ("=", "$$", "\\frac", "\\sum", "<=", ">=")):
                if not any(d in lower for d in dangerous_ast) and not StructuralHeuristicScanner.scan_python_ast(line):
                    math_invariants.append(line)
            elif lower.startswith(("problem:", "goal:", "wedge:", "objective:")):
                problems.append(line)
            elif lower.startswith(("constraint:", "invariant:", "must:", "rule:")):
                constraints.append(line)

        return QuarantinedSpec(
            source=source,
            raw_sha256=raw_sha,
            quarantined_xml=xml_box,
            taint_level=TaintLevel.QUARANTINED_DATA,
            dirty_patterns_stripped=stripped_count,
            problem_statements=tuple(problems),
            mathematical_invariants=tuple(math_invariants),
            domain_constraints=tuple(constraints),
        )


# ============================================================================
# 7. UNIFIED NEXUSHELM MEDIATOR FACADE
# ============================================================================


class NexusHelmMediator:
    """
    Unified Sovereign 'In-Between Agent' Mediator combining all 6 NexusHelm subsystems.
    """

    PROPOSE_CAPABILITY_MAP: dict[ActionID, str] = {
        ActionID.QUARANTINE_INGEST: "read_quarantine",
        ActionID.SYNTHESIZE_FORK: "extract_domain_spec",
        ActionID.READ_ARTIFACT: "read_workspace",
        ActionID.RUN_PINPOINT_SUITE: "read_workspace",
        ActionID.PROPOSE_DIFF: "propose_diff",
        ActionID.GIT_COMMIT_LOCAL: "propose_diff",
        ActionID.GIT_PUSH_REMOTE: "propose_diff",
        ActionID.EXECUTE_EGRESS: "propose_diff",
    }

    EXEC_CAPABILITY_MAP: dict[ActionID, str] = {
        ActionID.QUARANTINE_INGEST: "read_quarantine",
        ActionID.SYNTHESIZE_FORK: "extract_domain_spec",
        ActionID.READ_ARTIFACT: "read_workspace",
        ActionID.RUN_PINPOINT_SUITE: "read_workspace",
        ActionID.PROPOSE_DIFF: "propose_diff",
        ActionID.GIT_COMMIT_LOCAL: "git_commit_local",
        ActionID.GIT_PUSH_REMOTE: "git_push_remote",
        ActionID.EXECUTE_EGRESS: "network_egress",
    }

    def __init__(
        self,
        workspace_root: str | Path,
        initial_gear: AutonomyGear = AutonomyGear.G2_SPORT_TACTILE,
        secret_key: bytes | None = None,
        probe_hardware: bool = False,
        hid_bridge: DualSenseHidBridge | None = None,
    ) -> None:
        self.secret_key = secret_key or secrets.token_bytes(32)
        self.airlock = SemanticAirlock()
        self.broker = PhantomTokenBroker(broker_key=self.secret_key)
        self.integrity_guard = InstructionIntegrityGuard(workspace_root=workspace_root)
        self.hid_bridge = hid_bridge or DualSenseHidBridge()
        self.gearbox = AutonomyGearbox(
            initial_gear=initial_gear,
            hid_bridge=self.hid_bridge,
            probe_hardware=probe_hardware,
        )
        self.sieve = QuarantineSieve()
        self.lattice = TaintLattice()
        self.audit_log: list[dict[str, Any]] = []

    def dispatch_envelope(
        self,
        envelope: SemanticEnvelope,
        touched_paths: list[str] | None = None,
        consensus_models: int = 1,
        target_branch: str = "main",
        human_ratified: bool = False,
        probe_hardware: bool | None = None,
    ) -> GearEvaluationDecision:
        """
        Validates workspace instruction-file integrity, checks for raw credential leaks,
        enforces TaintLattice capability attenuation, verifies protected-path permissions,
        and evaluates the 5-Speed Autonomy Gearbox (with optional live Win32 DualSense HID probe).
        """
        # 1. Verify workspace instruction-file integrity before any dispatch
        self.integrity_guard.assert_workspace_clean()

        # 2. Ensure no raw credentials leaked into outbound typed_params or untrusted_blob
        self.broker.assert_no_raw_credentials(envelope.typed_params)
        if envelope.untrusted_blob:
            self.broker.assert_no_raw_credentials(envelope.untrusted_blob)

        # 3. Check protected instruction file paths and TaintLattice capability attenuation
        paths = touched_paths or []
        if "path" in envelope.typed_params and isinstance(envelope.typed_params["path"], str):
            paths = [*paths, envelope.typed_params["path"]]
        if "files" in envelope.typed_params and isinstance(envelope.typed_params["files"], list):
            paths = [*paths, *(str(f) for f in envelope.typed_params["files"])]

        effective_taint = (
            TaintLevel.HUMAN_VERIFIED if human_ratified else envelope.taint_level
        )
        propose_cap = self.PROPOSE_CAPABILITY_MAP.get(envelope.action_id, "propose_diff")
        self.lattice.require_capability(effective_taint, propose_cap)
        self.integrity_guard.guard_proposed_paths(paths, effective_taint)

        touches_protected = any(
            self.integrity_guard.is_protected_path(p) for p in paths
        )
        blast = self.gearbox.compute_blast_radius(
            envelope.action_id,
            touches_protected_files=touches_protected,
        )

        decision = self.gearbox.evaluate_action(
            action_id=envelope.action_id,
            taint_level=effective_taint,
            blast_radius=blast,
            consensus_models=consensus_models,
            target_branch=target_branch,
            human_ratified=human_ratified,
            probe_hardware=probe_hardware,
        )

        if decision.allowed_autonomously and not human_ratified:
            exec_cap = self.EXEC_CAPABILITY_MAP.get(envelope.action_id, "propose_diff")
            self.lattice.require_capability(effective_taint, exec_cap)

        self.audit_log.append(
            {
                "action_id": envelope.action_id.value,
                "source_agent": envelope.source_agent,
                "target_agent": envelope.target_agent,
                "taint_level": effective_taint.name,
                "gear": decision.gear.name,
                "blast_radius": decision.blast_radius,
                "allowed_autonomously": decision.allowed_autonomously,
                "requires_human_ratification": decision.requires_human_ratification,
                "halted": decision.halted,
                "hardware_transmitted": decision.hardware_transmitted,
                "transmission_mode": decision.transmission_mode,
            }
        )
        return decision
