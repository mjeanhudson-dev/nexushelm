# 🛡️ NexusHelm — Sovereign In-Between Agent Mediator & "Steering-Wheel" Human-Agency Harness

**Track 5 Reference Implementation (`C:\Users\Zachariah\aether agent\nexushelm\`)**

> *"That'd be the ultimate AI harness, but I feel there would be major push back if well implemented about human agency and need of input — but it's what people are asking out of tomorrow on paper; just hard to understand as one lives through it."*

`NexusHelm` solves the dual failure mode of modern multi-agent orchestrators (Gemini + Claude + Codex):
1. **Cross-Platform Security Vulnerability**: Natural-language inter-agent relays enable indirect prompt injection, lateral persistence across `AGENTS.md` / `CLAUDE.md`, and cross-provider API credential leakage.
2. **Human-Agency Alienation ("Passenger-Seat Syndrome")**: Current frameworks either bombard the user with 50 modal popups an hour or execute silent 2,000-line monoliths that strip creative ownership from the human operator.

---

## 🏗️ Six Verified Architectural Pillars

### 1. Bidirectional Typed Semantic Airlock (`SemanticAirlock` / `SemanticEnvelope`)
- Models never exchange unconstrained conversational prose as executable commands.
- Every cross-agent call is decompiled into a strictly typed `SemanticEnvelope`:
  $$\text{Envelope} = \langle \text{ActionID} \in \mathcal{A}_{\text{allowlist}},\; \text{TypedParams} \in \mathcal{S}_{\text{json}},\; \text{UntrustedBlob}_{\text{quarantined}} \rangle$$
- Blocks outbound prompt injection, permission-bypass flags (`dangerouslySkipPermissions`, `--sandbox=none`), and destructive shell payloads (`rm -rf`, `format C:`).
- Sanitizes inbound results from external scrapers/tools, neutralizing embedded `<system>` or `Ignore previous instructions` directives and clamping taint to `UNTRUSTED_EXTERNAL`.

### 2. Application-Layer Phantom Token Broker (`PhantomTokenBroker`)
- Subagents never hold raw API keys (`ghp_...`, `sk-...`, `AIza...`) in prompts, environment variables, or memory.
- Issues HMAC-signed opaque handles (`phantom://github/push/<sig>`) and automatically scrubs accidental raw secrets from outbound context.
- Swaps phantom handles for live credentials **only at the application-layer egress boundary** after verifying strict domain pinning (blocking SSRF/exfiltration to unauthorized domains) and TTL validity.

### 3. Instruction-File Integrity Guard (`InstructionIntegrityGuard`)
- Computes and locks a baseline SHA-256 manifest over `AGENTS.md`, `CLAUDE.md`, `.agents/**`, `.claude/**`, `.cursor/**`, and `.gemini/**`.
- Blocks any non-`HUMAN_VERIFIED` tool call or diff attempting to modify, add, or delete harness instruction files, eliminating lateral cross-agent persistence.

### 4. Monotonic Information-Flow Taint Lattice (`TaintLattice` / `PinpointPromotionReceipt`)
- Enforces strict lattice ordering:
  $$\text{UNTRUSTED\_EXTERNAL} < \text{QUARANTINED\_DATA} < \text{INTERNAL\_AGENT} < \text{PINPOINT\_VERIFIED} < \text{HUMAN\_VERIFIED}$$
- Composed data inherits the minimum trust of its inputs: $T_{\text{out}} = \min(T_1, \dots, T_n)$.
- Only a cryptographically signed `PinpointPromotionReceipt` with `exit_code == 0` and `100%` passing checks can promote an `INTERNAL_AGENT` artifact to `PINPOINT_VERIFIED`.

### 5. 5-Speed Autonomy Gearbox, Rule-of-3 Creative Forking & DualSense Haptic Friction
- **5-Speed Autonomy Gearbox (`AutonomyGear`)**:
  - `G0_EBRAKE_STOP`: Instant atomic halt of all active runner processes (triggered via DualSense Touchpad Click `d[10] & 0x02` or `ESC`).
  - `G1_CLUTCH_MANUAL`: Step-by-step human confirmation on every action.
  - `G2_SPORT_TACTILE`: Autonomous read/research ($B(a) < 20$); interactive diff review on local mutations ($B(a) \ge 20$).
  - `G3_ARBITER_CRUISE`: Multi-model consensus ($\ge 2$ models) + `PINPOINT_VERIFIED` auto-approves local commits ($B(a) < 70$); external side effects ($B(a) \ge 70$) require human ratification.
  - `G4_SLOW_SIMMER_OVERNIGHT`: Harvests surplus weekly token budget on isolated `simmer/*` branches while hard-blocking main-branch mutations or external egress until morning ratification.
- **Mandatory Rule-of-3 Creative Tradeoff Forking (`TradeoffFork`)**:
  - Rejects single-option fait accompli monoliths; requires three distinct strategic archetypes (`Conservative`, `Balanced`, `Visionary`) plus support for custom hybrid overrides.
- **Asymmetric Blast-Radius Friction (`DualSenseHapticPacket`)**:
  - Generates 64-byte DualSense USB HID Output Report `0x02` packets scaled to $B(a) \in [0, 100]$:
    - $B(a) < 20$: Mode `0x00` (Zero friction, Cyan lightbar)
    - $20 \le B(a) < 70$: Mode `0x05` (Soft spring resistance, Amber lightbar)
    - $B(a) \ge 70$: Right Trigger Mode `0x21` (Hard static resistance detent) + Left Trigger Mode `0x26` (40 Hz active warning judder, Crimson lightbar)

### 6. Zero-Dirty-Logic Quarantine Sieve (`QuarantineSieve`)
- Wraps raw legacy notes and Google Takeout/Drive archives inside `<tainted_raw_idea isolation="quarantined">`, stripping conversational loops and legacy prompt injections while extracting clean mathematical invariants and domain constraints.

---

## 🧪 Verification & Usage

```powershell
# Run the unit and adversarial test suite (7 comprehensive test methods)
python -m unittest discover -s "C:\Users\Zachariah\aether agent\nexushelm\tests" -p "test_*.py" -v

# Run the interactive end-to-end simulation
python "C:\Users\Zachariah\aether agent\nexushelm\demo_runner.py"
```
