# Native Rust — Solana-Specific Patterns & Pitfalls
# Frank Castle — Safe Solana Builder
# Read this AFTER shared-base.md when the user selects Native Rust.
# Claude: every rule here is in addition to — not instead of — shared-base.md.

---

## 1. ACCOUNT DESERIALIZATION & VALIDATION

In native Rust, there is no framework to catch you. Every check that Anchor does automatically, you do by hand. Miss one and you ship a vulnerability.

### 1.1 The Mandatory Validation Sequence
For every account passed into your instruction, perform all applicable checks in this order before touching any data:

```
1. Key check       — is this the account I expect (if fixed)?
2. Owner check     — does the right program own this account?
3. Signer check    — does this account need to have signed?
4. Writable check  — does this account need to be writable?
5. Discriminator   — does the data belong to the expected type?
6. Data validation — are fields within expected ranges?
```

Never skip steps. Never reorder them. Perform all applicable checks before proceeding.

### 1.2 Owner Check — The Most Commonly Missed
```rust
if account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```
- Check this before deserializing. Deserializing data from the wrong program is a type cosplay attack.
- For accounts owned by the System Program (e.g., user wallets): `account.owner == &system_program::ID`.
- For token accounts: `account.owner == &spl_token::ID` (or `spl_token_2022::ID`).

### 1.3 Signer Check
```rust
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```
- Perform this for every account that represents an authority, admin, or user authorizing an action.
- Never assume a keypair account signed just because it's listed.

### 1.4 Discriminator / Type Check
- Native Rust accounts don't get automatic discriminators. You must manage them.
- Design pattern: reserve the first byte(s) of every account's data as a type tag.
```rust
const VAULT_DISCRIMINATOR: u8 = 1;
const USER_DISCRIMINATOR: u8 = 2;

let data = account.try_borrow_data()?;
if data[0] != VAULT_DISCRIMINATOR {
    return Err(MyError::InvalidAccountType.into());
}
```
- Without discriminators, an attacker can pass a `UserAccount` where a `VaultAccount` is expected if they have the same shape.
- If discriminators/tags do not exist yet, add them before relying on deserialization for security checks.

### 1.5 Key Check (for Fixed Accounts)
```rust
if clock_sysvar.key != &sysvar::clock::ID {
    return Err(ProgramError::InvalidArgument);
}
```
- Hardcode expected pubkeys for all fixed accounts: sysvars, known program IDs, config accounts.
- Never trust position alone to identify a fixed account.
- For System Program CPIs, always assert:
```rust
if system_program.key != &system_program::ID {
    return Err(ProgramError::InvalidArgument);
}
```
- Do this before constructing or invoking any `system_instruction::*` CPI.

---

## 2. DESERIALIZATION

### 2.1 Use `try_from_slice` — Never Assume Layout
```rust
let vault = Vault::try_from_slice(&account.data.borrow())?;
```
- Always use Borsh deserialization (`try_from_slice`) rather than manual byte casting.
- Manual byte casting with transmutes or raw pointer reads is undefined behavior territory.
- Only deserialize the full account after the discriminator or type tag has been validated.

### 2.2 Verify Data Length Before Deserializing
```rust
if account.data_len() < Vault::LEN {
    return Err(ProgramError::InvalidAccountData);
}
```
- An undersized account will panic or misread data during deserialization.
- Define a `LEN` constant for every struct.

### 2.3 Borrow Data Carefully
```rust
let data = account.try_borrow_data()?;   // immutable borrow for reading
let mut data = account.try_borrow_mut_data()?;  // mutable borrow for writing
```
- Never hold both a mutable and immutable borrow of the same account simultaneously — this will panic at runtime.
- Drop borrows before taking new ones on the same account.
- In instruction handlers, prefer `try_borrow_data()` / `try_borrow_mut_data()` over raw `borrow()` / `borrow_mut()` so failed borrow returns custom error instead of panicking.

---

## 3. PDA DERIVATION — NATIVE RUST

### 3.1 Find and Store Canonical Bump at Init Time
- On initialization, derive the expected PDA on-chain and verify the client-supplied account matches it before creating or writing any state.
```rust
// At initialization
let (vault_pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key.as_ref()],
    program_id,
);

// Verify the passed-in vault account matches the derived PDA
if vault_pda != *vault.key {
    return Err(ProgramError::InvalidArgument);
}

// Store bump in account data
vault_state.bump = bump;
```

### 3.2 Re-derivation on Subsequent Calls (Use Stored Bump)
```rust
// On subsequent instructions, use the stored bump — don't re-find it
let expected_vault = Pubkey::create_program_address(
    &[b"vault", user.key.as_ref(), &[vault_state.bump]],
    program_id,
)?;

if expected_vault != *vault.key {
    return Err(ProgramError::InvalidArgument);
}
```
- `create_program_address` is cheaper than `find_program_address` (no iteration).
- Never allow the user to supply a bump — they must use the one you stored.

### 3.3 Verify PDA is not a Signer Unless Expected
- PDAs cannot sign transactions initiated externally. If you receive a PDA that claims `is_signer = true` in a user-submitted transaction, something is wrong — reject it.

---

## 4. CPI IN NATIVE RUST

### 4.1 invoke — For Non-PDA-Signed CPIs
```rust
if system_program.key != &system_program::ID {
    return Err(ProgramError::InvalidArgument);
}

invoke(
    &system_instruction::transfer(from.key, to.key, lamports),
    &[from.clone(), to.clone(), system_program.clone()],
)?;
```
- Pass only the accounts the callee needs — nothing more.
- Always verify the callee's program ID before calling: `if callee_program.key != &expected_program::ID { ... }`.

### 4.2 invoke_signed — For PDA-Signed CPIs
```rust
let seeds = &[b"vault", user.key.as_ref(), &[vault_state.bump]];
invoke_signed(
    &instruction,
    &[account_a.clone(), account_b.clone()],
    &[seeds],
)?;
```
- Only use `invoke_signed` when your PDA must authorize the CPI.
- The seeds you provide must exactly match the PDA's derivation — any mismatch causes a runtime error.
- Never elevate non-signer accounts to signer status through `invoke_signed`.

### 4.3 Post-CPI Account Data Refresh
```rust
// CPI may have modified vault — refresh data manually
let vault_data = vault.try_borrow_data()?;
let updated_vault = Vault::try_from_slice(&vault_data)?;
```
- Unlike Anchor's `.reload()`, in native Rust you must manually re-borrow and re-deserialize the account data after a CPI.
- Never use a local variable that was deserialized before the CPI to make decisions after the CPI.
- After CPI, any cached assumptions about externally touched accounts may be stale. Re-read data and revalidate any invariants you still depend on before continuing.

---

## 5. ACCOUNT CREATION & RENT

### 5.1 Creating Accounts via System Program CPI
```rust
let rent = Rent::get()?;
let lamports = rent.minimum_balance(Vault::LEN);

invoke(
    &system_instruction::create_account(
        payer.key,
        new_account.key,
        lamports,
        Vault::LEN as u64,
        program_id,  // owner = your program
    ),
    &[payer.clone(), new_account.clone(), system_program.clone()],
)?;
```
- Always fund with `rent.minimum_balance(size)` — never a hardcoded lamport value.
- Set `owner = program_id` immediately — the System Program creates the account, your program owns the data.

### 5.2 Pre-allocated Accounts (User-Created Externally)
- If a user pre-creates the account before calling your instruction, verify:
  1. `account.owner == program_id` (after `create_account`, it should be)
  2. `account.data_len() >= expected_len`
  3. `account.lamports() >= rent.minimum_balance(account.data_len())`
  4. Data is all zeros (not previously initialized)

---

## 6. ACCOUNT CLOSING — NATIVE RUST

Proper close sequence — never skip any step:

```rust
// Step 1: Transfer lamports to recipient
let dest_lamports = recipient.lamports();
**recipient.lamports.borrow_mut() = dest_lamports
    .checked_add(account_to_close.lamports())
    .ok_or(MyError::Overflow)?;
**account_to_close.lamports.borrow_mut() = 0;

// Step 3: Assign ownership back to System Program
account_to_close.assign(&system_program::ID);

// Step 4: Realloc to 0 data len
info.realloc(0, false)?;
```

- Skipping step 1 (zero lamports) recover all the lamports that were deposited for rent or other purposes
- Skipping step 2 (reassigning owner) means your program still "owns" a zero-balance account, wasting space.
- Skipping step 3 (realloc) we must realloc to zero bytes otherwise rent must be deposited
- The recipient must be a trusted address — never arbitrary user-supplied.
- Centralize account closure in a shared helper so every close path applies the same sequence consistently.
- The helper should perform the full native reclaim flow:
  1. transfer lamports to the recipient
  2. zero the source lamports
  3. clear or zero the account data
  4. reassign ownership to the System Program
  5. reduce the data length to zero

---

## 7. ERROR HANDLING

### 7.1 Define a Custom Error Enum
```rust
use thiserror::Error;
use solana_program::program_error::ProgramError;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("Authority mismatch")]
    AuthorityMismatch,
    #[error("Insufficient vault balance")]
    InsufficientBalance,
    #[error("Account already initialized")]
    AlreadyInitialized,
    #[error("Invalid account discriminator")]
    InvalidAccountType,
    #[error("Arithmetic overflow")]
    Overflow,
}

impl From<MyError> for ProgramError {
    fn from(e: MyError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
```

- Every error must have a descriptive message — `Custom(0)` is meaningless to an auditor or debugger.
- Use `?` with `map_err` to convert errors cleanly: `.ok_or(MyError::Overflow)?`.

### 7.2 Never Panic in Production Code
- `unwrap()` and `expect()` are banned in instruction handlers — they crash the entire program.
- Use `?`, `ok_or()`, `unwrap_or_else()`, or explicit match patterns everywhere.

### 7.3 Logging Discipline
- Logging raw account metadata is useful for learning and debugging, but production code should avoid leaking unnecessary operational details.
- Keep logs minimal, purposeful, and safe to expose in public transaction traces.

---

## 8. INSTRUCTION PARSING

### 8.1 Deserialize Instruction Data Safely
```rust
#[derive(BorshDeserialize)]
pub struct TransferArgs {
    pub amount: u64,
    pub min_expected: u64,
}

let args = TransferArgs::try_from_slice(instruction_data)
    .map_err(|_| ProgramError::InvalidInstructionData)?;
```

### 8.2 Validate All Instruction Arguments
- After parsing, validate all fields: ranges, non-zero requirements, flag combinations.
- `amount == 0` should be explicitly rejected if not meaningful.
- Never trust instruction data — it's user-supplied and can be anything.

---

## 9. NATIVE RUST SECURITY CHECKLIST (Quick Reference)

Before submitting any instruction handler for review, verify:

- [ ] Owner check on every data account before deserialization
- [ ] Signer check on every authority account  
- [ ] Discriminator check on every deserialized account
- [ ] Foreign-program accounts validate type tag/discriminator
- [ ] Key check on every fixed/known account (sysvars, programs)
- [ ] Duplicate mutable account check between any two mutable accounts
- [ ] Canonical bump stored at init, reused on subsequent calls
- [ ] `try_from_slice` used for all deserialization (no raw byte casting)
- [ ] Data length verified before deserialization
- [ ] Account data borrows use `try_borrow_data` / `try_borrow_mut_data`
- [ ] No `unwrap()` or `expect()` in instruction handlers
- [ ] Checked arithmetic on all financial math
- [ ] CPI callee program ID verified before invoke
- [ ] `system_program.key == &system_program::ID` enforced before any System Program CPI
- [ ] Account data re-read after every CPI
- [ ] Account close performs: zero data → transfer lamports → assign to system program
- [ ] Parent close either closes all dependent child accounts or rejects while children exist
- [ ] All close paths use a shared helper that completes the full native close sequence
- [ ] New accounts funded with `rent.minimum_balance(size)`, not hardcoded lamports
- [ ] Initialization guard (check data is zeroed / flag is false before init)

---

## 10. COMMON NATIVE BUILD & TOOLING ERRORS

### `cargo build-sbf` Not Found
Solana CLI not installed or not on PATH.
**Fix:** `sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"` then add to PATH:
`export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"`

### `cargo build-bpf` Deprecation Warning
Expected — BPF is deprecated in favor of SBF. Use `cargo build-sbf`. Anchor 0.30+ handles this automatically.

### Platform Tools Corruption After Install
```
[ERROR] The Solana toolchain is corrupted. Run cargo-build-sbf with --force-tools-install
```
Caused by insufficient disk space during platform-tools extraction (~2 GB needed).
**Fix:** `cargo build-sbf --force-tools-install`. If root partition is small, symlink `~/.cache/solana/` to a larger disk.

### `feature edition2024 is required` (Cargo 1.84 / platform-tools v1.48)
Platform-tools v1.48 bundles `cargo 1.84.0` which does not support `edition = "2024"`. Pin known breaking crates:
```bash
cargo generate-lockfile
cargo update -p blake3          --precise 1.8.2
cargo update -p constant_time_eq --precise 0.3.1
cargo update -p base64ct        --precise 1.7.3
cargo update -p indexmap        --precise 2.11.4
```
**Always commit `Cargo.lock`** — this is the single most effective prevention.

### `No space left on device`
Solana CLI + platform tools need 2–5 GB. Clean old versions:
```bash
rm -rf ~/.local/share/solana/install/releases/<old_version>/
rm -rf ~/.cache/solana/
```

### `agave-install not found`
Anchor 0.31+ migrates to `agave-install` for Solana ≥1.18.19.
**Fix:** Install via `sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"`.

### `solana-test-validator` Crashes or Hangs
```bash
pkill -f solana-test-validator && rm -rf test-ledger/
```
Check ports: `lsof -i :8899`. Consider **Surfpool** as a modern alternative.

### LiteSVM `undefined symbol: __isoc23_strtol`
LiteSVM 0.5.0 npm binary requires GLIBC ≥2.38. On Debian 12 / Ubuntu 22.04 (GLIBC 2.36) it fails.
**Fix:** Use `solana-bankrun` instead — verified working on GLIBC 2.36:
```bash
pnpm remove litesvm anchor-litesvm
pnpm add -D solana-bankrun anchor-bankrun
```
