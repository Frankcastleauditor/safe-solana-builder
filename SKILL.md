---
name: safe-solana-builder
description: >
  Use this skill whenever the user wants to write, scaffold, or build a Solana smart contract
  or program from scratch. Triggers on: "write a Solana program", "create a smart contract",
  "build an anchor program", "write a native Rust Solana program", "scaffold a Solana program",
  "help me write a program that does X on Solana", or any request to produce production-grade
  on-chain Solana code. This skill enforces Frank Castle's security best practices and pitfall
  avoidance guidelines automatically — giving every program a first layer of protection before
  it ever reaches an auditor. Always use this skill — even for simple programs — whenever
  Solana program code is the primary deliverable.
---

# Safe Solana Builder — by Frank Castle

You are writing production-grade Solana programs. Security is not an afterthought — it is baked into every line. Every program produced by this skill ships with a full project scaffold, a test file skeleton, and a security checklist.

### What This Skill Enforces

This skill systematically addresses the following vulnerability classes derived from real Solana protocol audits:

- **Protocol-specific vulnerabilities** — oracle manipulation, fee bypass, slippage attacks, LP preprocessing gaps
- **Logic flaws & edge cases** — dust DoS, time-unit mismatches, pre/post-fee inconsistencies, type narrowing
- **Access control & authorization bugs** — missing signer checks, frontrunnable initialization, namespace capture, inbound transfer auth, post-expiry flows
- **State management errors** — coupled-field resets, counter drift, vested/unvested balance separation, rollback safety
- **Lifecycle & state machine integrity** — absorbing terminal states, canonical transition matrices, paired time-gate divergence, user-param reachability constraints
- **PDA-related issues** — zombie accounts, seed collisions, canonical bump enforcement, lifecycle closure
- **Reward accounting exploits** — rounding gaps in partial unstake, dual-path reward debt bypass, retroactive rate application, dead share price, inflation/first-depositor attack, fee-on-transfer delta errors, rewards sourced from principal
- **Vault & pool architecture** — missing withdrawal paths on PDA-controlled vaults, spendable-vs-reserved balance confusion, backing invariant violations
- **Slippage & fee ordering** — slippage on net (not gross) amount, fee base must match executed amount, unambiguous gross/fee/net naming
- **AMM / bonding-curve safety** — completion-threshold capping, post-cap slippage recheck, terminal-state solvency, reserve layer alignment
- **Config management** — every write-path validation, tri-state patch semantics, partial-update corruption, cross-field invariant enforcement, atomic commit
- **Withdraw & drain safety** — cumulative caps for partial withdrawals, liability settlement before residual extraction, exact-remainder accounting after partial drains
- **Token-2022 extension validation** — PermanentDelegate seizure, uncontrolled FreezeAuthority, TransferHook CPI forwarding, ConfidentialTransfer compatibility
- **Treasury & fee recipient hygiene** — sweepable authority requirement, config-time ATA validation
- **Admin key security** — two-step rotation pattern, timelock recommendations for Critical programs
- **BPF runtime limits** — 4096-byte stack frame DoS, Box<> mitigation for large account types
- **Panic safety** — no `unwrap()`/`expect()` on user-controlled `Option`/`Result` paths; always return typed errors
- **Input validation & metadata hygiene** — non-empty required fields, explicit length bounds, URI scheme allowlists for user-supplied strings

---

## Step 1 — Ask the Framework Question

If the user has not already specified, ask exactly this (and nothing else):

> "Should I write this in **Native Rust**, **Anchor**, or **Pinocchio**?"

**Pinocchio** is Anza's zero-dependency, zero-copy framework — 88–95% CU reduction vs. Anchor. Best for high-throughput programs (DEXs, orderbooks, vaults). It is unaudited — flag this in the checklist for Critical programs.

Wait for the answer before proceeding.

---

## Step 1b — Ask the Testing Question

Immediately after the framework is chosen, ask:

> "Should I use **LiteSVM** for testing (fast, in-process, no validator required), or the default testing approach for your framework?"

Present the options clearly:

| Option | Best For |
|---|---|
| **LiteSVM** | Fast unit/integration tests, CI pipelines, time-lock testing, CU profiling, account injection from devnet |
| **Framework default** | Anchor: TypeScript with `@coral-xyz/anchor`; Native: `solana-program-test` async harness |

Wait for the answer before proceeding to Step 2.

---

## Step 2 — Load Your Reference Files

Once **both** the framework and testing approach are chosen, read the following files
**before writing a single line of code**:

1. **Always read first (both files):**
   - `references/shared-base.md` — Core security rules, pitfall patterns, and best practices for ALL Solana programs. Sections 1–20 cover foundational security; sections 21–31 cover vulnerability-derived rules from real protocol audits (reward accounting, vault architecture, Token-2022 extension validation, admin key rotation, BPF stack frame limits, lifecycle state machine integrity, slippage/fee ordering, bonding-curve AMM safety, initialization/namespace capture, config management, withdraw/drain safety, and treasury sweepability).

2. **Then read the framework-specific file:**
   - Native Rust → `references/native-rust.md`
   - Anchor → `references/anchor.md`
   - Pinocchio → `references/pinocchio.md`
   → Framework-specific patterns, constraints, additional pitfalls, and common build/tooling errors.

3. **If LiteSVM was chosen for testing, also read:**
   - `references/litesvm.md`
   → Test structure patterns, sysvar control, token setup, account inspection, CU profiling, and the LiteSVM security test checklist.

4. **Check for a relevant example:**
   See the Examples table at the bottom of this file. If a similar program exists in `examples/`, read it before writing — use it as a quality and structure benchmark.

Do not skip or skim these files. They are the source of truth for this skill.

---

## Step 3 — Assess Risk Level

Before gathering requirements, classify the program's sensitivity. This determines how thorough your security comments and "Known Limitations" section must be.

| Level | Criteria | Examples |
|---|---|---|
| 🟢 Low | No SOL/token custody, no CPI, single user, read-heavy | Counter, registry, simple config |
| 🟡 Medium | Token transfers, basic CPI, multi-user state, PDAs | Staking, voting, simple escrow |
| 🔴 Critical | Vaults, multi-CPI chains, admin keys, large TVL potential | AMM, lending, NFT launchpad, bridges |

State the risk level explicitly at the top of your security checklist. For 🔴 Critical programs: add a "High-Risk Decisions" section to the checklist and flag every admin key, upgrade authority, and irreversible state transition.

---

## Step 4 — Gather Program Requirements

Collect the following in one message (if not already provided):

- **Program name** — what is it called?
- **What it does** — brief description of functionality
- **Accounts** — what accounts does it need?
- **Instructions** — what instructions/functions?
- **Access control** — who can call what? Any admin roles?
- **Token standard** — SPL Token, Token-2022, or none?
- **Any external programs called** — Metaplex, another protocol, etc.?

If the user's description already covers most of these, proceed and note your assumptions clearly.

---

## Step 5 — Write the Program

### 5a. Security Pre-Check (internal, not shown to user)
Before writing, run through shared-base.md and the framework file. Flag which rules apply to this program's design. Note any inherent risks in the design itself.

### 5b. Project Scaffold

Deliver a complete, ready-to-build project structure. Not just `lib.rs` — the full scaffold:

**For Anchor:**
```
<program-name>/
├── Anchor.toml
├── Cargo.toml
├── programs/
│   └── <program-name>/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs
└── tests/
    └── <program-name>.ts           # if framework-default testing
    └── <program-name>_tests.rs     # if LiteSVM testing
```

**For Native Rust / Pinocchio:**
```
<program-name>/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── instruction.rs
    ├── processor.rs
    ├── state.rs
    └── error.rs
tests/
    └── <program-name>_tests.rs     # if LiteSVM testing
```

### 5c. The Program Code

Requirements:
- Compilable without warnings
- Every account validated — ownership, type, signer, writable as applicable
- No unchecked math on any financial value
- PDAs derived with canonical bumps stored and reused
- No logic after CPI calls that relies on stale state
- Descriptive program-specific error types
- Inline security comments on every non-obvious decision

Header comment block at the top of `lib.rs`:
```rust
// ============================================================
// Program: <ProgramName>
// Framework: <Native Rust | Anchor | Pinocchio>
// Testing:   <LiteSVM | solana-program-test | TypeScript/Anchor>
// Risk Level: 🟢 Low | 🟡 Medium | 🔴 Critical
// Author: Frank Castle Security Template
// Security: See accompanying security-checklist.md
// ============================================================
```

### 5d. Test File

Always produce a test file. The approach depends on what was chosen in Step 1b:

#### If LiteSVM was chosen:

Produce Rust tests following `references/litesvm.md`. The test file must include:

**Required structure:**
- A `setup()` function that loads the `.so`, airdrops SOL, and returns `(LiteSVM, Keypair)`
- A `send_tx()` helper that wraps message/transaction building and calls `expire_blockhash()` after each send
- PDA derivation helpers matching the on-chain seeds exactly

**Happy path tests (implement fully):**
- End-to-end success flow with full state assertion (lamports, token balances, account data fields)
- Account closure verification (lamports=0, data.len()=0, owner=system_program)
- CU consumption logged and recorded to a `CU_RESULTS` static for the `zz_cu_summary` test

**Security/edge case tests (implement or scaffold with `TODO` + explanation comment):**
- Wrong signer → `assert!(result.is_err())`
- Re-initialization attempt → `assert!(result.is_err())`
- Before-deadline action → `assert!(result.is_err())` (if time-locked)
- After-deadline action → succeeds (time travel via `svm.set_sysvar(&clock)`)
- Over-limit / zero-amount arithmetic → `assert!(result.is_err())`
- Any program-specific edge cases flagged in the checklist

**Mandatory closing test:**
```rust
#[test]
fn zz_cu_summary() { /* print CU table */ }
```

#### If framework default was chosen:

- Anchor: TypeScript using `@coral-xyz/anchor`
- Native Rust: Rust integration tests using `solana-program-test`

In both cases, cover the same happy path + security/edge case matrix as above.
Mark unimplemented security tests with `TODO` and an explanation comment.

## Examples

The `examples/` directory contains complete reference programs written to this skill's standard. Before writing, check if a similar example exists — use it to calibrate output quality, structure, and checklist depth. Do not copy-paste; treat it as a quality benchmark.

| Example | Framework | Testing | Risk Level | What it demonstrates |
|---|---|---|---|---|
| `examples/nft-whitelist-mint/` | Anchor | TypeScript/Anchor | 🔴 Critical | MintConfig PDA, per-user WhitelistEntry PDA, double-mint guard, Metaplex CPI with program ID verification, SOL balance check around CPI, Token-2022 compatible mint, safe account close |

Each example folder contains:
- `lib.rs` — the full program
- `security-checklist.md` — the applied rules checklist

---

## Notes for Edge Cases

- **Simple programs (counter, hello world):** Still apply all checks. Simplicity is not an excuse for insecure patterns.
- **Inherent design risks (admin key with no timelock, no upgrade authority check):** Flag explicitly in the checklist under "High-Risk Decisions" or "Known Limitations."
- **Token-2022 features (transfer hooks, confidential transfers):** Flag in the checklist as requiring extra manual review — expanded attack surface. Always validate extensions at `initialize` per shared-base §23.
- **Programs with `remaining_accounts`:** Apply the same ownership, signer, and type checks as named accounts. Flag in checklist.
- **Upgrade authority:** Always note whether the program is upgradeable and who holds the authority. Recommend a timelock or multisig for 🔴 Critical programs.
- **Staking / yield programs:** Pay special attention to shared-base §21 (reward accounting). Every reward payout path must update `reward_debt`. Retroactive rate application and partial-unstake rounding are the two most common Critical findings in this category.
- **Share-based pools (stX/totalStaked):** Apply §21.4 (dead share price) and §21.5 (inflation attack) checks at design time — these are architectural, not line-level, and cannot be patched easily after deployment.
- **Large account contexts:** After `anchor build`, check for stack frame warnings (§25). Apply `Box<>` to large account fields if the warning appears.
- **AMM / bonding-curve programs:** Apply §26 (lifecycle state machine), §27 (slippage/fee), §28 (AMM safety), and §30 (withdraw/drain). Completion-threshold capping, post-cap slippage recheck, and terminal-state solvency are the top findings in this category.
- **Programs with admin config instructions:** Apply §29 (initialization, namespace capture, user-param safety, config management). Every config write path must validate all fields; partial updates must use patch semantics to avoid silent zeroing.
- **Programs with a fee treasury or protocol wallet:** Apply §31.4 — the treasury authority must be sweepable (valid signer path to move tokens out). Validate the ATA at config time, not at withdrawal time.
- **User-supplied metadata (name, symbol, URI):** Apply §18 metadata hygiene — enforce non-empty, explicit length bounds, and URI scheme allowlists at the point of instruction processing.

- **LiteSVM for RPC-dependent tests:** LiteSVM does not support all RPC methods. If the program requires wallet integration tests or real validator behaviour, note in the checklist that those tests must use `solana-test-validator` separately.
