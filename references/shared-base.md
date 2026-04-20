# Shared Base — Solana Security Rules & Best Practices
# Frank Castle — Safe Solana Builder
# Applies to ALL Solana programs regardless of framework (Native Rust or Anchor).
# Claude: read every line of this file before writing any program code.

---

## 1. ACCOUNT & IDENTITY VALIDATION

These are the most exploited categories in Solana. Every account that enters your program is untrusted by default.

### 1.1 Signer Checks
- **Always verify `is_signer`** on every account that must authorize an action. An account being present in the accounts list does NOT mean it signed.
- Never treat account presence as authorization. Solana passes all accounts in a flat list — position alone means nothing.
- For authority-based operations (admin actions, user mutations), `is_signer` must be checked explicitly, every time.

### 1.2 Ownership Checks
- **Always verify `account.owner == expected_program_id`** before reading or trusting any account's data.
- An attacker can craft an account with identical data layout owned by a malicious program. If you skip the owner check, you'll read and act on spoofed data.
- The system program, token program, and your own program each have different owner IDs — never conflate them.

### 1.3 Account Data Matching (has_one / constraints)
- Validate that related accounts actually belong together. A user's vault PDA must match the pubkey stored in the user's state account — not just be a valid vault.
- Use `has_one` (Anchor) or manual pubkey comparison (native) to enforce these cross-account relationships.
- Example failure: accepting any token account for a "user's" withdrawal, not just the one registered to that user.

### 1.4 Type Cosplay Prevention (Discriminators)
- Every account type must have a unique **discriminator** (first 8 bytes in Anchor; manually managed in native).
- An attacker can pass an `Admin` account where a `User` account is expected if you don't check the discriminator.
- Always deserialize into the specific expected type and validate its discriminant before trusting any fields.

### 1.5 Reinitialization Attacks
- **Verify an account has not already been initialized before running setup logic.**
- If `initialize` can be called twice, an attacker can overwrite the authority field and hijack the program.
- Use a dedicated `initialized: bool` flag, or rely on Anchor's `init` constraint which prevents reinit by checking account discriminator and ownership.

### 1.6 Writable Checks
- Only accounts explicitly marked as writable (`is_writable`) should be modified.
- Never modify an account not marked writable — doing so will cause a runtime error at best, and a silent corruption at worst in earlier runtime versions.
- `is_signer` and `is_writable` are per-transaction, not per-instruction. Never assume they differ across instructions in the same transaction.

---

## 2. PDA (PROGRAM DERIVED ADDRESSES) SECURITY

PDAs are the backbone of Solana state. A poorly designed PDA is a permanently exploitable backdoor.

### 2.1 Canonical Bumps Only
- **Always use `find_program_address`** to find the canonical (highest valid) bump.
- Never allow a user to supply an arbitrary bump seed. An attacker can pre-mine a bump that results in the same address as another account.
- **Store the canonical bump** in the account's data after creation and **reuse it** on subsequent calls — never brute-force it again on every invocation.
- Use `create_program_address` (with the stored bump) for re-derivation, not `find_program_address`, to save compute.

### 2.2 PDA Sharing Prevention
- Seeds must be specific enough that one PDA can never serve two different users or purposes.
- **Always include the user's `Pubkey` in seeds** for any user-specific state. Example: `[b"vault", user.key().as_ref()]`.
- A shared PDA means one user can affect another's state — this is a critical vulnerability.

### 2.3 Seed Collision Prevention
- Use **unique string prefixes** for different PDA types: `b"vault"`, `b"user_state"`, `b"config"`, etc.
- Seeds `["AB", "C"]` and `["A", "BC"]` produce the **same PDA** — this is a known footgun with concatenated seeds.
- Always use fixed-length seeds or canonical delimiters when seed components come from user input.
- Never assume a PDA derived from user-provided seeds is unique unless you fully control and validate the seed composition.

### 2.4 PDA Purpose Isolation
- Never use a single PDA across multiple logical domains or external programs.
- Each distinct capability (vault, escrow, config, staking position) must use a distinct PDA with distinct seeds.

---

## 3. ARITHMETIC & LOGIC SAFETY

A single overflow or division-before-multiplication can drain a protocol.

### 3.1 Checked / Saturating Math — No Exceptions
- **Never use standard `+`, `-`, `*` operators on financial values.** They will panic (debug) or silently overflow (release).
- Use `.checked_add()`, `.checked_sub()`, `.checked_mul()`, `.checked_div()` and propagate errors with `?`.
- Use `.saturating_sub()` only when a floor of zero is semantically correct (e.g., health factors).
- Treat every arithmetic error as a program bug, not a user error — return a descriptive custom error.

### 3.2 Multiply Before Divide
- **Always perform all multiplications first, then divide last.** Integer division truncates — doing it early loses precision permanently.
- Wrong: `(amount / total_supply) * price`
- Right: `(amount * price) / total_supply`

### 3.3 Price Slippage Checks
- In any function involving pricing, swapping, or purchasing: **require an `expected_price` or `min_amount_out` argument from the user.**
- Without this, MEV bots can manipulate price between submission and execution. The user's transaction lands at a worse price than intended.
- Reject the transaction if the actual price deviates beyond the user-supplied tolerance.

### 3.4 Lamport Balance Invariant
- After every instruction, **the total lamports across all accounts must remain equal.** Never create or destroy lamports — only redistribute.
- When closing an account, the rent-exempt lamports must go to a **trusted destination** (the original initializer or a program-controlled account). Never allow arbitrary destinations — this enables "rent stealing."
- Manually verify lamport math when implementing custom close or de-listing logic.

---

## 4. DUPLICATE MUTABLE ACCOUNT ATTACKS

Passing the same account twice for two different roles is a classic exploit vector.

### 4.1 The Attack
- If your instruction takes `account_a` (source) and `account_b` (destination) and an attacker passes the same account for both, your state writes will conflict. The last write wins (in Anchor, the last serialized field). The net effect is often a free "transfer" to self that bypasses balance checks.

### 4.2 Prevention
- **Always add a constraint ensuring two mutable accounts that must be distinct are actually distinct:**
  ```
  constraint = account_a.key() != account_b.key()
  ```
- If your logic updates different fields of the same account through two references, merge them into a single reference to ensure atomic state updates.
- Ask yourself for every pair of mutable accounts: *"What happens if an attacker passes the same account for both?"*

---

## 5. CROSS-PROGRAM INVOCATIONS (CPI) SAFETY

CPI is the most complex attack surface in Solana. Every CPI is a trust boundary.

### 5.1 Validate Program IDs — No Arbitrary CPI
- **Never invoke a program address provided by the user without verification.** An attacker will pass a malicious program that mimics success responses.
- For well-known programs (System, Token, Token-2022): hardcode their IDs and compare.
- For dynamic programs: check the provided address against a trusted allowlist stored in your program's state account.
- If using `AccountInfo` for the program account: `require_keys_eq!(cpi_program.key(), expected_program::ID)`.

### 5.2 Reload Stale Data After CPI
- **After any CPI that modifies a shared account, reload the account data before using it again.**
- Your in-memory deserialized struct does not update automatically when the on-chain state changes via CPI.
- Missing a reload means you're making decisions on stale balances or state — a classic logic error.

### 5.3 Signer Pass-Through Sanitization
- Any account marked as a signer in your current transaction **remains a signer** in CPIs you make.
- Before passing accounts into an external CPI call, iterate through them and verify `!account.is_signer` unless that privilege is explicitly required.
- Use **account isolation**: derive user-specific PDAs so a compromised CPI signer only has authority over one user's "blast radius," not the entire protocol.

### 5.4 SOL Balance Checks Around CPI (Slippage for SOL)
- Solana has no `msg.value` equivalent — a callee can spend SOL from a signing account.
- Record the signer's balance **before** the CPI: `let balance_before = ctx.accounts.signer.lamports();`
- After the CPI, verify: `require!(balance_before <= balance_after + max_spendable, ErrorCode::ExcessiveSpend);`

### 5.5 Post-CPI Ownership Verification
- An attacker-controlled program can use the `assign` instruction to change an account's owner during a CPI.
- **After any CPI involving an account you care about, verify the owner is still the expected program.**
- `require_keys_eq!(account.owner, &system_program::ID)` (or your program's ID as appropriate).

### 5.6 CPI Return Values — Always Propagate Errors
- **Always wrap CPI calls with the `?` operator** to ensure that if the inner call fails, the entire transaction reverts.
- Never call a CPI and discard its result. Be aware that some programs return "Success" even if their internal conditional logic (like a guarded transfer) did not execute.

### 5.7 invoke vs invoke_signed
- **Prefer `invoke` over `invoke_signed`** wherever possible. Only use `invoke_signed` when a PDA must sign.
- With `invoke_signed`, only extend signer privileges to accounts that are already signers in the current instruction — never elevate non-signers.
- Minimize the accounts passed to any CPI call — pass only what is required, nothing more.

### 5.8 Architecture: Defense-in-Depth
- **Avoid a single "Global Vault" PDA for all users.** If exploited, all user funds are at risk.
- Use **user-specific PDAs for deposits.** A CPI exploit then drains only the affected user's funds — not the entire protocol.

---

## 6. ACCOUNT STORAGE & LIFECYCLE

### 6.1 Storage Rules
- Never store program state in the program account itself. Always use separate data accounts.
- Always set the `owner` field of state accounts to your program's address. This is your primary access control for account data.
- Never allow an account's data to be modified by a program that does not own it.
- Never allow accounts to exceed **10 MiB** of data. Never allow total per-transaction resize to exceed **20 MiB**.
- Size accounts using the serialized layout, not Rust in-memory layout. For Anchor accounts, prefer explicit `INIT_SPACE`/max-len-based sizing over `size_of::<T>()`.
- `size_of::<T>()` is a memory-layout metric (alignment/padding/container metadata), not an on-chain encoding guarantee. Using it for account allocation can under-allocate after schema changes and cause init/write DoS.

### 6.2 Rent Exemption
- **Always fund new accounts with at least two years' worth of rent** (the rent-exempt threshold).
- Never leave an account in the `0 < balance < minimum_balance` range — it becomes eligible for garbage collection.

### 6.3 Account Closing (Anti-Revival)
- **Never close an account by only draining its lamports.** The account can be "revived" by refunding its rent.
- Proper close sequence:
  1. Set all data bytes to zero (`memset` / `fill(0)`)
  2. Transfer all lamports to the recipient
  3. Transfer ownership back to the System Program
- The destination for rent lamports must be a **trusted address** (original initializer or a controlled account) — never arbitrary.

### 6.4 Sysvar Verification
- When reading from a sysvar (Clock, Rent, SlotHashes, etc.), always verify the account's public key matches the known sysvar address.
- Never trust a sysvar account passed by the user without verification. (The Wormhole hack involved sysvar spoofing.)

---

## 7. TOKEN-2022 COMPATIBILITY

Mixing legacy token functions with Token-2022 mints causes silent DoS.

- **Never use `anchor_spl::token::transfer` (or its native equivalent) for programs that may encounter Token-2022 mints.**
- It hardcodes the legacy Token Program ID and will fail or misbehave with Token-2022 accounts.
- **Always use `transfer_checked`** and the interface-aware versions that dynamically detect the correct program.
- Always provide the `mint` account and `decimals` in transfers — required by `transfer_checked`.
- Token-2022 features (transfer hooks, confidential transfers, interest-bearing tokens) have **expanded attack surface** — flag them in the security checklist for extra manual review.

---

## 8. TRANSACTION MODEL SAFETY

### 8.1 Atomicity
- Compose multiple operations into a single transaction when you need all-or-nothing guarantees.
- Solana's transaction atomicity means either all instructions succeed or all revert — design your program to take advantage of this.

### 8.2 Compute Budget
- Never assume a transaction will succeed past compute budget limits.
- For complex instructions, use `SetComputeUnitLimit` and budget compute units accordingly.
- Unbounded loops over `remaining_accounts` or variable-length collections are a compute DoS vector.

### 8.3 Address Lookup Tables
- Never include signer accounts in an Address Lookup Table. Signer pubkeys must always be inline in the transaction.

### 8.4 Durable Nonces
- Always place `AdvanceNonceAccount` as the **first instruction** in the transaction.
- Never use a nonce account whose blockhash is already recent — this defeats its purpose.

---

## 9. SAFE RUST PATTERNS

### 9.1 Vector Initialization
- To declare a vector of length `N` filled with zeros: use `vec![0; N]` **(semicolon)**.
- **Never use `vec![0, N]` (comma)** — this creates a two-element vector `[0, N]`, not N zeroes. Accessing index 2+ will panic.

### 9.2 Avoid Unsafe Rust
- Unless absolutely necessary for performance, stay within safe Rust.
- The Rust compiler's memory protections are your last line of defense against memory corruption bugs.
- Every `unsafe` block requires an explicit justification comment.

### 9.3 Handle `remaining_accounts` With Full Rigor
- If you iterate over `ctx.remaining_accounts`, apply the **same ownership, signer, and type checks** as you do for named accounts.
- `remaining_accounts` is the easiest place to inject malicious accounts because developers assume they've already been validated.

### 9.4 Never `unwrap()`/`expect()` on User-Controlled Option/Result Paths
- Instruction handlers must return typed program errors, not panic. Avoid `unwrap()`/`expect()` on `Option`/`Result` values influenced by accounts or instruction data.
- This is especially important for optional accounts (`Option<Account<...>>`): missing inputs should map to explicit custom errors via `ok_or(...)`.
- Treat panic paths as reliability/security bugs because they produce opaque client failures and bypass normal error semantics.

```rust
let account_state = ctx
    .accounts
    .optional_account
    .as_ref()
    .ok_or(ErrorCode::MissingRequiredAccount)?;
```

---

## 10. THE CURIOSITY PRINCIPLE (Mindset)

Security is not a static checklist — it is an adversarial mindset applied at design time.

For every account input in your program, ask:
1. **"What happens if I pass the same account twice?"** → Duplicate mutable account attack.
2. **"What happens if this account is owned by a different program?"** → Type cosplay / ownership bypass.
3. **"What happens if this is a Token-2022 mint instead of a legacy mint?"** → DoS / wrong program invoked.
4. **"What happens if the CPI I'm calling returns success but didn't actually do anything?"** → Silent logic failure.
5. **"What happens if an attacker passes a valid-looking but malicious program ID?"** → Arbitrary CPI.
6. **"What's the worst-case scenario if this account's bump is not canonical?"** → PDA collision.

Apply this curiosity to every design decision, not just during code review.

---

## 11. ORACLE VALIDATION

- **Validate oracle confidence interval**: reject prices where `conf / price` exceeds a configurable threshold (e.g., 2–5%). Wide confidence means the price is unreliable — acting on it enables oracle manipulation.
- **Check staleness**: verify the price timestamp is within a configurable max age. Never use a stale feed.
- Make confidence and staleness thresholds admin-configurable, not hardcoded.
- **Never use the current oracle price retroactively for settled positions.** Store the reference price at action time (borrow, deposit) in the account data and use it at settlement — not the live price.

---

## 12. FEE COMPLETENESS

- Apply all fees to **every code path** — redemption, withdrawal, single-asset, multi-asset. Fee bypasses on edge-case routes are a consistent source of protocol drain.
- Deduct fees from tracked totals (collateral value, pool balance) **atomically with the principal deduction** — never in a separate step that can be skipped or reordered.
- Use a **consistent amount** (pre-fee or post-fee) for both capacity checks and execution. Mixing them causes overfills or incorrect limit-order behavior.
- Apply fee calculations to the **input token** unless the protocol explicitly specifies output-side fees.

---

## 13. TOKEN DUST & TIME-LIMITED ACCOUNT DoS

> Account close sequence (zero → lamports → assign to system program) is in §6.3. This section covers dust and lifecycle timing.

- **Before closing any token account, sweep or burn the residual balance.** An attacker can deposit a dust amount to make `close` permanently fail (account poisoning DoS). Never assume balance is zero.
- After any transfer, reload and verify the account balance to detect unexpected deposits.
- Define a dust threshold. Either sweep dust to the protocol treasury or reject operations where remaining amount is below threshold. Never let dust block a settlement or close.
- **Close time-limited accounts (offers, escrows, locks) at expiry.** Leaving expired accounts open leaks rent and enables griefing. Allow anyone — not just the creator — to trigger closure after expiry.
- Avoid `init_if_needed` for accounts an adversary can pre-initialize with harmful state (also in anchor.md §2.4). Use `init` for one-time initialization.

---

## 14. STATE MANAGEMENT — COUPLED FIELDS & COUNTERS

- Reset **all logically coupled fields atomically** in completion and close paths. Never leave a derived field (e.g., `shares_pending`, `rewards_owed`) non-zero after its parent quantity is zeroed. Inconsistent state breaks protocol invariants permanently.
- When migrating positions, transfer **pending (locked)** and **withdrawable (matured)** balances as separate quantities. Never merge them or reapply a lockup to already-unlocked amounts.
- Update all counters and statistics **atomically with the operation that triggers them** (fill count, volume, total supply). A counter that drifts out of sync is a protocol invariant violation and a potential exploit surface.

---

## 15. SHARED POSITION & POOL LOGIC

- Before transferring shares or liquidity between positions, **preprocess both source and destination** (settle pending fees, snapshot reward accumulators). Skipping the destination lets a user claim fees they never earned, potentially draining the pool.
- Never allow a no-op or self-transfer pattern to inflate fee claims. Verify `source != destination` before any share movement (also see §4 on duplicate accounts).
- If directional fee asymmetry (buy vs. sell) is intentional, document and test it explicitly. If symmetry is required, apply fees on the input side for both directions.

---

## 16. CLOCK & TIMING

- Use a **single canonical time unit** (slots *or* seconds) throughout all time-dependent logic. Mixing units silently corrupts comparisons — a vesting window in seconds compared to raw slots can unlock 4× earlier than intended.
- When comparing durations across unit boundaries, apply the correct scale factor explicitly (e.g., multiply slot count by `SLOTS_PER_SECOND` before comparing to a seconds-based deadline).
- Annotate time fields with their unit in code (`vesting_end_slot: u64`, `unlock_timestamp_secs: i64`) to prevent silent misuse as code evolves.

---

## 17. TOKEN / MINT INTEGRITY

- Assert that the **mint close authority is `None`** during mint initialization. A mint with a close authority can be closed and re-initialized at the same address with different decimals, silently breaking all downstream accounting.
- Store immutable mint properties (decimals, supply cap, authorities) at account creation. Re-validate them on **every instruction** that depends on them — do not assume they cannot change between calls.
- Never allow a reinitialized account at a recycled address to inherit state from its previous lifetime. Validate all fields as if the account is fresh.

---

## 18. INPUT VALIDATION — PROTOCOL-LEVEL

> Data length and instruction data validation are in native-rust.md §2 / anchor.md §1. This section covers protocol-semantic validation.

- Validate token mints against a protocol allowlist or framework constraints (`mint::authority`, `mint::decimals`). An unconstrained mint allows arbitrary tokens to be injected into protocol flows.
- Reject same-asset operations where distinct assets are required: `require!(input_mint != output_mint)`. Same-token operations can be exploited to manipulate fee accounting or pool invariants.
- Enforce maximum sizes on variable-length inputs (messages, payloads, URIs) **before encoding**. Unbounded inputs cause compute overruns and silent log truncation.
- For user-supplied metadata strings (for example name/symbol/URI), enforce protocol-level hygiene: non-empty required fields, explicit length bounds, and URI scheme allowlists. Do not rely only on downstream program/library maximums.
- Verify protocol-owned addresses (fee recipients, config accounts) are the expected, constrained accounts **before updating them**. An unconstrained update enables fee redirection to attacker-controlled accounts.

---

## 19. TYPE NARROWING & INTEGER SAFETY

> Checked arithmetic and multiply-before-divide are in §3. This section covers type conversion safety.

- Keep numeric types **consistent across instruction params, on-chain state, and emitted events**. Never silently narrow a wider integer type (e.g., `u64 → u32`). On-chain state and events diverge, breaking auditability.
- Before any narrowing cast, assert an explicit upper-bound: `require!(val <= u32::MAX as u64, ErrorCode::Overflow)`.
- Validate all amounts at **instruction entry** (`> 0`, within protocol min/max bounds) before passing them into math helpers. Deep validation catches bugs late and produces confusing error codes.

---

## 20. EVENT LOGGING

- Keep individual log messages concise. Solana truncates transaction logs at ~10 KB per transaction — long free-form strings are silently dropped mid-audit trail.
- Emit critical state (amounts, authorities, timestamps, before/after balances) as **structured, fixed-size on-chain events** — not free-form strings.
- Never rely solely on logs for auditability. Persist critical state in on-chain accounts — logs are ephemeral and truncatable by the runtime.

---

## 21. REWARD ACCOUNTING — PROPORTIONAL SCALING & DEBT SETTLEMENT

Reward math is the single most exploited category in staking and yield protocols. Every pattern below maps to a validated Critical or High finding.

### 21.1 Settle Before Shrinking (Rounding Mismatch in Partial Unstake)
- **Never scale `reward_debt` proportionally when reducing a position without settling first.**
- Independent floor divisions create a gap: `attacker calls partial_unstake(1) + claim_rewards` in a loop to manufacture rewards with zero new time elapsed.
- Fix: settle all pending rewards (compute `pending = accrued - reward_debt`, pay out) **before** shrinking the position, then reset `reward_debt` to a fresh checkpoint against the new, smaller principal.

### 21.2 Reward Debt Must Be Updated on Every Payout Path — No Exceptions
- If `claim_rewards` subtracts `reward_debt` but `unstake_locked` does not, a user who claims then unstakes receives the same rewards twice.
- **Every instruction that pays out rewards must follow the same formula:** `pending = total_accrued - reward_debt`, pay `pending`, then set `reward_debt = total_accrued`.
- Audit every code path that touches balances: claim, unstake, withdraw, liquidate, emergency exit. Missing even one is a Critical.

### 21.3 Never Retroactively Apply a Changed Rate
- Never store a single mutable global `reward_rate` and multiply it by `total_elapsed` across the full duration.
- When `update_reward_rates` overwrites the rate, every rate change retroactively alters all existing positions — attackers front-run rate increases to steal yield.
- Use one of:
  - **Per-position rate snapshots**: store `rate_at_stake_time` in the position account, compute rewards against that.
  - **Global accumulator pattern**: maintain `reward_per_token_stored` (updated atomically on every rate change or interaction), store `reward_per_token_paid` per position; `pending = (reward_per_token_stored - reward_per_token_paid) * position_size`.

### 21.4 Dead Share Price — Yield Must Update the Exchange Rate
- In share-based (stX/totalStaked) models, there must be a code path that increases the accounting numerator (`total_staked`) independently of the share supply.
- If yield enters the vault but the exchange rate variable is never updated, the share price is permanently frozen — new depositors receive the same shares as if no yield had accumulated.
- Any yield accrual instruction must call `total_staked = total_staked.checked_add(yield_amount)?` before any share math.

### 21.5 Inflation Attack / First Depositor
- In share-based pools, the first depositor can stake a dust amount, burn most receipt tokens directly via SPL, inflate the exchange rate, then steal from subsequent depositors via rounding.
- **Fix (require one of):**
  - Mint dead shares to a burn address on the first deposit (e.g., 1000 locked shares).
  - Enforce a minimum initial deposit large enough to make the inflation attack economically infeasible.
  - Use virtual balances: add a virtual offset to both numerator and denominator before computing shares.

### 21.6 Fee-on-Transfer Delta Accounting (Token-2022)
- When using Token-2022 mints with transfer fees, the vault receives `amount - fee` but a naive implementation records `amount`.
- **Always use balance-delta accounting:**
  ```rust
  let before = ctx.accounts.vault.amount;
  token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
  ctx.accounts.vault.reload()?;
  let actual_received = ctx.accounts.vault.amount.checked_sub(before).ok_or(ErrorCode::Arithmetic)?;
  // Use actual_received for all state updates — never `amount`
  ```
- Call `reload()` after every CPI before reading any account field.

### 21.7 Rewards Must Come from a Funded Reward Source — Not Principal
- If reward payouts are sourced from the same vault that holds user principal, the protocol is structurally insolvent from the first claim — rewards come from other users' deposits.
- Rewards must come from a **dedicated rewards vault**, a funded reserve, or an external yield source.
- At `initialize` time, assert that a rewards vault exists and is sufficiently funded for the program's stated duration.
- Add a `check_solvency` view instruction that clients can call before staking.

---

## 22. VAULT & POOL ARCHITECTURE — WITHDRAWAL PATHS & SOLVENCY

### 22.1 Every PDA-Controlled Vault Must Have a Withdrawal Path
- If an instruction creates a PDA-controlled token vault (e.g., donation vault, insurance fund, fee accumulator), there must be a corresponding instruction to withdraw from it.
- Without a withdrawal path, tokens sent to that vault are permanently locked with no recovery mechanism.
- Before shipping: trace every token flow into PDA-controlled accounts and confirm a corresponding outflow instruction exists with appropriate access control.

---

## 23. TOKEN-2022 EXTENSION VALIDATION AT INITIALIZATION

Accepting an arbitrary Token-2022 mint without extension whitelisting opens critical attack surface.

### 23.1 Validate Extensions at `initialize` — Reject Dangerous Ones
At program initialization (or when a new mint is registered), validate the mint's Token-2022 extensions:

- **Reject `PermanentDelegate`**: a permanent delegate can seize tokens from any account associated with the mint — including your vault. This is a complete vault drain vector.
- **Reject uncontrolled `FreezeAuthority`**: an external freeze authority can freeze your vault's token account, permanently DoS-ing withdrawals.
- **Require `TransferHook`-compatible CPI patterns**: if the mint uses a transfer hook, your `transfer_checked` CPI must forward `remaining_accounts` containing the hook's accounts. Skipping this causes the CPI to fail silently or revert.
- **Reject `ConfidentialTransfers`** unless your program explicitly handles the confidential transfer protocol.

```rust
// Example: reject PermanentDelegate at init
let mint_data = ctx.accounts.staking_mint.to_account_info();
if let Ok(Some(_)) = get_extension::<PermanentDelegate>(&mint_data.data.borrow()) {
    return Err(ErrorCode::UnsupportedMintExtension.into());
}
```

- Maintain an explicit **extension allowlist** in your program's config: only mints with approved extension sets can be registered.

---

## 24. ACCESS CONTROL — LOCKUP ENFORCEMENT & ADMIN KEY ROTATION

### 24.1 Lockup Must Be Enforced on ALL Reward Claim Paths
- If a locked staking protocol offers both `claim_rewards` (mid-lockup, yield only) and `instant_unlock` (no yield, principal only), the `claim_rewards` instruction must explicitly enforce lockup expiry.
- Without this check, users collect full yield then instantly exit — the lockup incentive mechanism is entirely bypassed.
- Fix: add `require!(clock.unix_timestamp >= entry.unlock_at, ErrorCode::LockupNotExpired)` to **every** yield-paying instruction, not just `unstake`.

### 24.2 Admin Key Must Be Rotatable (Two-Step Pattern)
- A single immutable admin key is a permanent single point of failure. Key compromise = full protocol takeover with no recovery.
- **Always implement a two-step rotation:**
  ```rust
  // Step 1: current admin proposes a new admin
  pub fn propose_admin(ctx: Context<ProposeAdmin>, new_admin: Pubkey) -> Result<()> { ... }
  // Step 2: new admin accepts (proves key control)
  pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> { ... }
  ```
- Store `pending_admin: Option<Pubkey>` in your config account.
- For 🔴 Critical programs: wrap admin key rotation in a timelock (e.g., 48-hour delay before acceptance is valid).

---

## 25. BPF RUNTIME — STACK FRAME LIMIT

### 25.1 Stack Frame Hard Limit: 4096 Bytes
- The BPF VM enforces a hard **4096-byte stack frame limit** per instruction invocation.
- Anchor instruction contexts with 6+ `InterfaceAccount` or `Account` fields — especially alongside large state accounts — can exceed this limit, causing **runtime access violations** (not compile-time errors).
- This is a complete DoS: the instruction always reverts. There is no graceful degradation.

**Detection:** After `anchor build`, check for:
```
Stack offset of XXXX exceeded max offset of 4096 by YYY bytes
```
Treat this as a hard blocker — it must be resolved before deployment.

**Fix:** Wrap large account fields in `Box<>` to move them from the stack to the heap:
```rust
// Before (stack allocated — dangerous with many accounts)
pub vault: Account<'info, VaultState>,

// After (heap allocated — safe)
pub vault: Box<Account<'info, VaultState>>,
```
- Apply `Box<>` to the largest account types first (`InterfaceAccount<Mint>`, `InterfaceAccount<TokenAccount>`, large custom state accounts).
- For Native Rust / Pinocchio: avoid large local variable declarations inside instruction handlers; pull complex structs behind references or allocate on the heap explicitly.

---

## 26. STATE MACHINE & LIFECYCLE INTEGRITY

### 26.1 Sentinel Timestamps Must Be Valid Unix Times
- Never use `0` or any epoch-era value as a sentinel for a timestamp that feeds arithmetic comparisons with current time.
- If `expiry_ts = 0` and you compute `expiry_ts + grace_period`, the grace window anchors to 1970 and expires immediately.
- For immediate expiry, use `clock.unix_timestamp` (now), not `0`.
- If a special sentinel is truly needed, branch explicitly and bypass timestamp arithmetic for that case.

```rust
// WRONG
expiry_ts = if immediate { Some(0) } else { Some(clock.unix_timestamp) };
// Later: require!(clock < expiry_ts + grace_period) — fails instantly for 0

// RIGHT
expiry_ts = Some(clock.unix_timestamp);
// Or for truly instant expiry:
expiry_ts = Some(clock.unix_timestamp.checked_sub(grace_period).unwrap_or(0));
```

### 26.2 Every Path to a Terminal State Must Execute the Same Cleanup
- If multiple paths transition to the same terminal state (`Failed`, `Closed`, `Settled`), all must apply identical side effects.
- Missing cleanup on one path can trap funds or leave accounting inconsistent.
- Extract shared termination logic into a single helper (for example, `_on_terminate()`) and call it from every terminal transition.

### 26.3 Zero Accounting Fields After Draining Assets
- Any instruction that drains assets from a PDA (withdrawal, migration, completion) must zero matching accounting fields in the same transaction.
- Stale reserves let later logic operate on phantom liquidity.
- Prefer a post-drain invariant check (`actual == expected`) before finalizing state.
- Any action that prices, redeems, or pays from tracked reserves must assert a **backing invariant** against real balances before execution. Status flags alone are not sufficient safety gates.
- If liquidity is externalized/migrated, disable reserve-based actions until reserves are re-seeded and accounting is reinitialized atomically.

```rust
// After transferring all assets out:
state.sol_balance = 0;
state.token_balance = 0;
```

### 26.4 Status Transition Guards Must Use Allowlists, Not Denylists
- For actions limited to "active" entities, check an explicit allowlist of valid source states.
- Denylist checks like `status != Initial` accidentally permit terminal states.

```rust
// WRONG — denylist
require!(status != Status::Initial);

// RIGHT — allowlist
require!(
    status == Status::Active || status == Status::Pending,
    "action only applies to active or pending entities"
);
```

### 26.5 Preserve Sub-State on Transitions Instead of Hardcoding
- Primary-state transitions should not blindly reset secondary status.
- Hardcoding a sub-state can remove lifecycle locks (for example, migration readiness).
- Restore prior sub-state from persisted data or conditionally retain it.

```rust
// WRONG — hardcodes sub-state
entity.secondary_status = SecondaryStatus::Open;

// RIGHT — restore from saved state
entity.secondary_status = entity
    .saved_secondary_status
    .unwrap_or(SecondaryStatus::Open);
```

### 26.6 Paired Time Gates Must Share One Deadline Source
- When one lifecycle timestamp controls two opposite permissions (for example, **action allowed until deadline** and **cleanup allowed after deadline**), compute one canonical `deadline_ts` and reuse it everywhere.
- Never duplicate time-gate math inline across handlers. Divergent inequality direction, stale assumptions, or sentinel handling can invert intended permissions and violate lifecycle guarantees.
- If an "immediate", "no grace", or special mode exists, model it with an explicit enum/flag and dedicated branching. Do not overload timestamp fields with magic values.

```rust
let deadline_ts = event_ts.checked_add(grace_period).ok_or(ErrorCode::Arithmetic)?;
let can_action = now <= deadline_ts;
let can_finalize = now > deadline_ts;
```

### 26.7 Terminal States Must Be Absorbing (Non-Rewritable)
- Treat terminal states as **absorbing nodes** in the state machine: once entered, they cannot transition to non-terminal states by default.
- Enforce transitions from a single canonical transition matrix (or helper), and validate `(current_state, next_state)` before any side effects.
- Access control is not a substitute for transition validation. An authorized actor can still perform an invalid lifecycle rewrite if transition guards are permissive.
- Avoid exclusion-style predicates (`state != X`). Use explicit allowlists of valid source states per instruction.
- If a recovery path is intentionally supported, model it as a distinct transition with strict preconditions and explicit audit-trail events.

```rust
require!(is_allowed_transition(current_state, next_state), ErrorCode::InvalidTransition);
```

---

## 27. SLIPPAGE & FEE ORDERING

### 27.1 Slippage Guards Must Protect Net Amount, Not Gross
- If fees are deducted from user proceeds (or added to user cost), slippage validation must compare against net user outcome.
- Checking only gross AMM output can pass while user receives less than `min_output`.
- Keep API/event naming unambiguous (`gross_out`, `fee_amount`, `net_out`) so clients cannot misinterpret slippage-protected values.
- Enforce slippage on the user's final net outcome, independent of how fees are collected. Separate fee transfers in the same instruction must be counted in that net result.

```rust
// WRONG — checks gross
let output = amm_swap(input, ...);
require!(output >= min_output); // user gets output - fee

// RIGHT — checks net
let output = amm_swap(input, ...);
let fee = calculate_fee(output, fee_bps);
let net = output - fee;
require!(net >= min_output);
```

### 27.2 Fee Base Must Match the Actual Swapped Amount
- Charge fees on `source_amount_swapped` (actual consumed amount), not always on raw user input.
- Partial fills and rounding make input and consumed amount diverge.
- Use one canonical executed base amount for fee calculation, state/accounting updates, and events. Mixing requested and executed amounts across these paths causes silent economic drift.

```rust
// WRONG — fees on raw input
let fee = calculate_fee(user_input, fee_bps);

// RIGHT — fees on actual swapped amount
let fee = calculate_fee(actual_swapped, fee_bps);
```

### 27.3 Fee Collection Must Not Block the User's Payout
- Charging fees from wallet balance before payout can block exits for users with no spare SOL.
- Prefer deducting fee from proceeds to avoid requiring upfront wallet SOL.

```rust
// WRONG — fee before payout
system_program::transfer(user → treasury, fee)?; // user needs SOL upfront
vault.lamports -= proceeds;
user.lamports += proceeds;

// RIGHT — fee deducted from payout
let net = proceeds - fee;
vault.lamports -= proceeds;
user.lamports += net;
treasury.lamports += fee;
```

---

## 28. BONDING CURVE & AMM INTEGRITY

### 28.1 Cap Purchases at the Completion Threshold
- If a curve has a completion threshold, clamp buys so sold amount never exceeds remaining capacity.
- Overshoot can consume reserves needed for downstream actions (LP seeding, withdrawals, fees), causing reverts or underflows.
- After applying any cap/clip to execution size, recompute outputs and re-check user slippage bounds against the **actual executed output**. Input-side limits alone do not protect output guarantees.
- Completion-triggering trades must preserve completion-path solvency invariants (for example, reserves needed by settlement/fee logic). Do not allow a trade to mark terminal state if terminal handlers would immediately fail arithmetic or accounting checks.

```rust
let sold_so_far = total_supply - remaining_reserves;
let remaining_capacity = threshold.saturating_sub(sold_so_far);
let effective_buy = std::cmp::min(requested_amount, remaining_capacity);
// Execute swap with effective_buy
```

### 28.2 Reserve Subtraction Must Target the Correct Accounting Layer
- In virtual/real reserve models, subtraction must align with the layer used for output math.
- If output uses `virtual + real` but subtraction only hits `real`, underflow is possible.
- Either cap output at `real_reserves` or subtract from both reserve layers consistently.
- When executable balance and restricted balance share one pool, enforce explicit spendable-balance bounds (`output <= spendable_balance`) and never consume restricted allocations.

### 28.3 Validate Interdependent Config Fields Against Each Other, Not Stale State
- For multi-field config updates, validate all new values against each other before writing state.
- Writing one field early then validating against an unchanged sibling compares new-vs-old and can pass invalid configs.
- Validate all new config values first, then write them together in one commit. Do not mix partial writes with validation.

```rust
// WRONG — writes A, then validates stale B against new A
state.field_a = params.field_a;
require!(state.field_b <= state.field_a); // field_b is still the OLD value
state.field_b = params.field_b;

// RIGHT — validate from params first
require!(params.field_b <= params.field_a);
state.field_a = params.field_a;
state.field_b = params.field_b;
```

---

## 29. PERMISSIONLESS INITIALIZATION & USER-CONTROLLED PARAMETERS

### 29.1 Frontrunnable Initialization Without Identity Check
- `init` prevents re-initialization but does not ensure the intended party is the initializer.
- If initializer is auto-assigned as admin with no identity check, anyone can frontrun and seize control.
- Constrain expected admin identity, use atomic deploy+configure flows, or use two-step ownership acceptance.
- First-writer-wins initialization of shared control state is a namespace-capture risk. If identity is not authenticated at creation, an arbitrary actor can permanently claim control over that state and all downstream flows that trust it.
- If initialization is permissionless, decouple creator from privileged authority and require an explicit authority-acceptance step before privileged instructions become active.

### 29.2 User-Controlled Parameters That Affect Protocol Operations
- Permissionless creation parameters that control protocol behavior can become griefing vectors if unbounded.
- Extreme values can break fee collection, completion, cooldown semantics, or pricing.
- Enforce bounded ranges at creation time.
- Never let user-controlled parameters define release gates for assets or critical state transitions. Unlock conditions and time gates for restricted flows must be protocol-defined (or strictly bounded by protocol policy), not creator-defined.
- User-chosen parameters must preserve state-machine reachability: while an entity is active, at least one valid forward path must remain. Reject parameter sets that can leave entities active but unable to progress.

```rust
require!(params.virtual_offset >= MIN_OFFSET, "offset too low — breaks pricing");
require!(params.virtual_offset <= MAX_OFFSET, "offset too high — unreachable threshold");
require!(
    params.cooldown_timestamp <= clock.unix_timestamp + MAX_COOLDOWN,
    "cooldown too far in the future"
);
```

### 29.3 Unbounded Admin Config Parameters That Retroactively Break Live Entities
- Mutable global config values read at execution time can brick already-live entities.
- Example: cancellation fee greater than deposit causes refund underflow.
- Either snapshot critical economics per entity at creation, or enforce config invariants on every update.
- Validate parameter bounds in **every write path** (initialize, update, and migration/setup helpers). Never assume checks in one entrypoint protect all others.
- When global parameters are snapshotted into per-entity state, validate at snapshot time too. Invalid captured values can permanently break that entity even after global settings are fixed.
- Enforce both per-field domains and cross-field invariants before persisting any config change.
- For fixed-total reserve/accounting models, enforce `sum(parts) <= total` and compute derived remainder fields with checked arithmetic (`checked_add`/`checked_sub`) to prevent wraparound-built invalid states.
- For safety-critical economic/control parameters, enforce non-degenerate lower bounds (not just upper bounds). Zero or near-zero values can create pathological behavior and permanently poison newly snapshotted entities.

```rust
require!(config.cancel_fee <= config.min_deposit, "fee would brick refunds");
require!(config.completion_fee < config.completion_threshold, "fee exceeds threshold");
```

### 29.4 Config Update APIs Must Preserve "No Change" Semantics
- Partial config updates need tri-state behavior per field: **unchanged**, **set to value**, and (if supported) **explicitly clear**.
- Never overload a single `Option<T>` parameter to mean both "not provided" and "clear the stored optional field." This causes silent config corruption on unrelated updates.
- For optional stored fields, use an explicit patch enum or separate `clear_*` flags so callers can update one field without mutating others.
- Keep semantics uniform across all fields in the same admin update instruction.
- Avoid full-struct rewrites for routine admin changes. Prefer granular setters or patch-style updates so one-field changes cannot silently overwrite unrelated live config.

```rust
enum Patch<T> { Unchanged, Set(T), Clear }
```

---

## 30. WITHDRAW & DRAIN SAFETY

### 30.1 Withdrawal Amount Must Be Validated Against Protocol Allocation
- If admin/user-supplied withdraw amounts are not capped by tracked allocation, over-withdrawal can steal assets reserved for other flows.
- Withdrawal eligibility must also require that all earmarked liabilities are settled (pending payouts, rebates, escrowed distributions, accrued obligations). Do not permit residual-balance extraction while reserved liability fields remain nonzero.
- Reconcile liabilities to their intended recipients before any residual transfer.
- For repeat/partial withdrawals, enforce cumulative caps (`already_withdrawn + requested <= allocated`) and update accounting in the same transaction. Never let balance transfers and internal reserve/liability tracking diverge.

```rust
require!(withdraw_amount <= state.allocated_fee_balance, "exceeds allocated amount");
require!(state.pending_liabilities == 0, "unsettled obligations");
```

### 30.2 Zero Accounting Fields After Completing a Drain
- After full settlement/completion drains, zero all reserve/balance accounting fields.
- Stale nonzero values confuse indexers, break invariants, and create upgrade-time hazards.
- If a flow intentionally leaves a reserved remainder, set accounting fields to the exact post-transfer remainder (not pre-drain values) and assert they match on-chain balances.

```rust
// After draining all assets:
state.sol_reserves = 0;
state.token_reserves = 0;

// If a reserved remainder intentionally stays:
state.sol_reserves = 0;
state.token_reserves = reserved_remainder;
```

---

## 31. MISCELLANEOUS PATTERNS

### 31.1 Mutable Shared Config Retroactively Affects Live Entities
- If live entities reference shared mutable config at execution time, config updates can silently change active user economics.
- Snapshot critical fee and threshold terms into per-entity state during creation.

### 31.2 BPF Stack Frame DoS on Large Account Contexts
- BPF instruction stack frames are capped at 4096 bytes; large `Accounts` contexts can exceed this and hard-revert.
- Treat stack offset build warnings as blockers.
- Use `Box<>` around large account fields to move them off stack.

### 31.3 Unclosed Accounts Permanently Lock Rent
- Terminal lifecycle instructions should close obsolete PDAs and return rent-exempt lamports to a trusted recipient.
- Otherwise rent remains locked indefinitely.

### 31.4 Fee Treasury Must Be Capable of Receiving Tokens
- If treasury is stored as raw `Pubkey` and ATA is derived at runtime, that address must be capable of owning token accounts.
- Misconfigured treasury ownership can permanently lock withdrawn tokens.
- Validate treasury compatibility at config-time or store explicit ATA addresses.
- Treasury authorities must also be sweepable: there must be a valid signer path (wallet/multisig or program signer seeds) to move tokens out after receipt.

### 31.5 Token-2022 Mint Space Must Be Computed After All Extensions Are Declared
- Account size must be computed from the final extension list.
- Calculating size before optional extensions are added creates undersized mint accounts and initialization failure.

```rust
// WRONG — space computed before extensions are added
let extensions: Vec<ExtensionType> = vec![];
let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)?;
create_account(..., space, ...)?;
if has_metadata { extensions.push(ExtensionType::MetadataPointer); } // too late

// RIGHT — declare all extensions first
let mut extensions: Vec<ExtensionType> = vec![];
if has_metadata { extensions.push(ExtensionType::MetadataPointer); }
let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)?;
create_account(..., space, ...)?;
```

### 31.6 Signer-as-New-Account Pattern Is Griefable
- Creating new accounts from signer-supplied fresh keypairs is frontrunnable (attacker funds target address first).
- This can force create-account failure and user retries.
- Mitigate by preferring PDAs, generating keys just-in-time, and documenting retry semantics.

### 31.7 Repeated Privileged Actions That Reset Time-Sensitive State
- Privileged instructions that can be called repeatedly must not keep resetting expiry/cooldown timestamps.
- Only set timestamps on first transition to prevent indefinite extension.

```rust
if state.expiry_ts.is_none() {
    state.expiry_ts = Some(clock.unix_timestamp as u64);
}
// Subsequent calls leave the timestamp unchanged
```
