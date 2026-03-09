# LiteSVM — Testing Reference
# Frank Castle — Safe Solana Builder
# Use this file when the developer chooses LiteSVM for testing.
# Applies to ALL frameworks: Native Rust, Anchor, and Pinocchio.

---

## Overview

LiteSVM is a fast, in-process Solana VM for testing programs without starting
a validator. It embeds the full Solana runtime inside your Rust test process,
giving you deterministic, fast, zero-external-process tests.

### LiteSVM vs. the Alternatives

| Concern | `solana-test-validator` | `solana-program-test` | `litesvm` |
|---|---|---|---|
| **Speed** | Slowest (full validator) | Moderate | Fastest (in-process) |
| **Setup** | External process required | Async runtime required | None — `LiteSVM::new()` |
| **Sysvar control** | Limited | Limited | Full — set Clock, Rent, Slot freely |
| **Account injection** | Via RPC | Manual | `svm.set_account()` one-liner |
| **Devnet account replay** | Native | Manual | `svm.set_account()` with RPC data |
| **CI-friendliness** | Poor | Good | Excellent |
| **RPC method coverage** | Full | Partial | Partial — use validator for RPC tests |
| **Real validator behaviour** | ✅ | Approximation | Approximation |

**Use `litesvm` for:** unit and integration tests of program logic, security edge cases,
CU profiling, and CI pipelines.

**Use `solana-test-validator` for:** RPC method testing, wallet integration tests,
or any case where real-life validator behaviour matters.

---

## 1. PROJECT SETUP

### Cargo.toml (dev dependencies)

```toml
[dev-dependencies]
litesvm = "0.9.1"
litesvm-token = "0.9.1"

solana-instruction = "3.1.0"
solana-keypair = "3.1.0"
solana-native-token = "3.0.0"
solana-pubkey = "4.1.0"
solana-signer = "3.0.0"
solana-transaction = "3.0.2"
solana-message = "3.0.1"
solana-sdk-ids = "3.1.0"
spl-token-2022 = { version = "10.0.0", features = ["no-entrypoint"]}
spl-associated-token-account = "8.0.0"
solana-rpc-client = "3.1.9"
solana-address = "2.2.0"
solana-account = "4.1.0"
```

### Running tests

```bash
# Run all tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_make -- --nocapture

# Run serially (required if using a global CU summary Mutex)
cargo test -- --nocapture --test-threads=1
```

---

## 2. CORE PATTERNS

### 2a. Setup — Initialize and Fund

```rust
use litesvm::LiteSVM;
use litesvm_token::{CreateMint, CreateAssociatedTokenAccount, MintTo};
use solana_keypair::Keypair;
use solana_native_token::LAMPORTS_PER_SOL;
use solana_signer::Signer;
use std::path::PathBuf;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();

    // Airdrop SOL to payer
    svm.airdrop(&payer.pubkey(), 50 * LAMPORTS_PER_SOL)
        .expect("Airdrop failed");

    // Load the compiled program .so
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy/my_program.so");
    let program_data = std::fs::read(&so_path)
        .unwrap_or_else(|_| panic!("Cannot read SO at {:?} — run cargo build-sbf first", so_path));

    svm.add_program(MY_PROGRAM_ID, &program_data);

    (svm, payer)
}
```

**Security notes:**
- Build the `.so` with `cargo build-sbf` before running tests — missing SO gives a
  confusing panic, not a compile error.
- Always use `LAMPORTS_PER_SOL` — never hardcode lamport values in tests.
- Use a dedicated `payer` per test via `Keypair::new()` — never share mutable state
  between tests.

---

### 2b. Loading Accounts from Devnet (Account Replay)

LiteSVM has no network access. To test against real devnet/mainnet accounts,
fetch the account data with an RPC client and inject it:

```rust
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use std::str::FromStr;

fn inject_devnet_account(svm: &mut LiteSVM, address: &str) {
    let rpc = RpcClient::new("https://api.devnet.solana.com");
    let pubkey = Pubkey::from_str(address).unwrap();
    let fetched = rpc.get_account(&pubkey).expect("Failed to fetch account");

    svm.set_account(
        pubkey,
        Account {
            lamports:   fetched.lamports,
            data:       fetched.data,
            owner:      Pubkey::from(fetched.owner.to_bytes()),
            executable: fetched.executable,
            rent_epoch: fetched.rent_epoch,
        },
    ).unwrap();
}
```

**Security notes:**
- Devnet account data can be stale — note the fetch timestamp in a comment.
- Never rely on devnet accounts for security-critical assertions; use injected
  accounts only for environment setup (e.g. price oracle fixtures, SPL mints).
- Do not hardcode private keys or funded keypairs from devnet in test files —
  generate fresh `Keypair::new()` per test.

---

### 2c. Token Setup with litesvm-token

```rust
use litesvm_token::{
    spl_token::ID as TOKEN_PROGRAM_ID,
    CreateMint, CreateAssociatedTokenAccount, MintTo,
};

// Create a mint (6 decimals, authority = maker)
let mint_a = CreateMint::new(&mut svm, &payer)
    .decimals(6)
    .authority(&maker.pubkey())
    .send()
    .unwrap();

// Create an associated token account for owner
let maker_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint_a)
    .owner(&maker.pubkey())
    .send()
    .unwrap();

// Mint tokens (raw units — 1_000_000 = 1 token at 6 decimals)
MintTo::new(&mut svm, &payer, &mint_a, &maker_ata, 1_000_000_000)
    .send()
    .unwrap();
```

---

### 2d. Building and Sending Transactions

```rust
use solana_instruction::Instruction;
use solana_message::Message;
use solana_transaction::Transaction;

// Build instruction
let ix = Instruction {
    program_id: MY_PROGRAM_ID,
    accounts:   /* account metas */,
    data:       /* serialized instruction data */,
};

// Build, sign, send — always use latest_blockhash()
let message = Message::new(&[ix], Some(&payer.pubkey()));
let blockhash = svm.latest_blockhash();
let tx = Transaction::new(&[&payer], message, blockhash);

let result = svm.send_transaction(tx).unwrap();
println!("CUs consumed: {}", result.compute_units_consumed);
println!("Logs: {:?}", result.logs);
```

#### TransactionMetadata fields

```rust
pub struct TransactionMetadata {
    pub signature:             Signature,
    pub logs:                  Vec<String>,
    pub inner_instructions:    InnerInstructionsList,
    pub compute_units_consumed: u64,
    pub return_data:           TransactionReturnData,
}
```

#### Handling failures

```rust
use solana_transaction_error::TransactionError;
use solana_instruction::error::InstructionError;

match svm.send_transaction(tx) {
    Ok(meta) => { /* success */ }
    Err(failed) => {
        match failed.err {
            TransactionError::InsufficientFundsForFee => { /* ... */ }
            TransactionError::InstructionError(idx, err) => {
                // idx = which instruction in the tx failed
                // err = the InstructionError variant
                eprintln!("Instruction {} failed: {:?}", idx, err);
            }
            other => eprintln!("Transaction error: {:?}", other),
        }
    }
}
```

---

### 2e. Sending a Helper Function (Recommended Pattern)

Wrap send logic to reduce boilerplate across tests. Call `expire_blockhash()`
after every transaction to prevent "blockhash not found" errors on the next call:

```rust
fn send_tx(
    svm: &mut LiteSVM,
    instructions: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> u64 {
    let message = Message::new(instructions, Some(payer));
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new(signers, message, blockhash);
    let result = svm.send_transaction(tx).expect("Transaction failed");
    svm.expire_blockhash(); // advance blockhash after every tx
    result.compute_units_consumed
}
```

> **Why `expire_blockhash()`?** LiteSVM keeps a single current blockhash. If you
> send multiple transactions without advancing it, subsequent transactions will fail
> with `BlockhashNotFound`. Always expire after each send in multi-transaction tests.

---

## 3. SYSVAR & TIME CONTROL 

Full sysvar manipulation is one of LiteSVM's most powerful capabilities —
essential for testing time locks, deadlines, and slot-dependent logic.

### 3a. Time Travel (Clock) if the instructions require time manipulation

```rust
use anchor_lang::prelude::Clock; // or solana_clock::Clock for native

// Read current clock
let mut clock: Clock = svm.get_sysvar();

// Advance time (e.g. 5 days forward)
let five_days_secs = 5 * 24 * 60 * 60 + 1;
clock.unix_timestamp += five_days_secs;
svm.set_sysvar(&clock);

// Jump to a specific slot
svm.warp_to_slot(500);
```

**Security notes:**
- Always test both before and after a deadline — `test_X_before_deadline_fails`
  and `test_X_after_deadline_succeeds`. Both tests are required to validate a
  time lock is actually enforced.
- When warping time, also `expire_blockhash()` if subsequent transactions
  need a fresh blockhash.

### 3b. Rent sysvar

```rust
use solana_rent::Rent;

let rent: Rent = svm.get_sysvar();
let min_balance = rent.minimum_balance(data_size);
```

---

## 4. ACCOUNT INSPECTION

```rust
// Get raw account (returns Option<Account>)
let account = svm.get_account(&pubkey).expect("Account not found");
println!("lamports: {}", account.lamports);
println!("data len: {}", account.data.len());
println!("owner:    {}", account.owner);

// Get lamport balance directly
let balance = svm.get_balance(&pubkey).unwrap();

// Read SPL token balance (amount at offset 64 in token account layout)
fn get_token_balance(svm: &LiteSVM, token_account: &Pubkey) -> u64 {
    let acc = svm.get_account(token_account).expect("Token account not found");
    u64::from_le_bytes(acc.data[64..72].try_into().unwrap())
}

// Inject or override an account
use solana_account::Account;
svm.set_account(
    pubkey,
    Account {
        lamports:   1_000_000,
        data:       vec![/* serialized state */],
        owner:      MY_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    },
).unwrap();
```

---

## 5. COMPUTE UNIT PROFILING

Track CU consumption across instructions — a natural fit alongside Pinocchio's
CU-reduction goals.

```rust
use std::sync::Mutex;

// Global CU collector (run tests with --test-threads=1 for accurate aggregation)
static CU_RESULTS: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

fn record_cu(label: &'static str, cu: u64) {
    CU_RESULTS.lock().unwrap().push((label, cu));
}

// In your test:
let cu = send_tx(&mut svm, &[ix], &payer.pubkey(), &[&payer]);
record_cu("initialize/base", cu);

// Summary test (name with zz_ prefix so it runs last)
#[test]
fn zz_cu_summary() {
    let results = CU_RESULTS.lock().unwrap();
    if results.is_empty() {
        println!("No CU results (run tests with --test-threads=1)");
        return;
    }
    println!("\n=== Compute Unit Summary ===");
    for (label, cu) in results.iter() {
        println!("  {:<40} {:>8} CUs", label, cu);
    }
}
```

### Custom compute budget

```rust
let mut budget = litesvm::ComputeBudget::default();
budget.compute_unit_limit = 2_000_000; // raise ceiling for profiling
svm.with_compute_budget(budget);
```

---

## 6. SIMULATION (DRY-RUN)

Simulate a transaction without committing state changes — useful for pre-flight
checks and failure path verification:

```rust
match svm.simulate_transaction(tx) {
    Ok(sim_result) => {
        println!("Would succeed");
        println!("CUs: {}", sim_result.meta.compute_units_consumed);
        println!("Logs: {:?}", sim_result.meta.logs);
    }
    Err(err) => {
        println!("Would fail: {:?}", err.err);
        println!("Logs: {:?}", err.meta.logs);
    }
}
```

---

## 7. FRAMEWORK-SPECIFIC PATTERNS

### 7a. Anchor — Building Instructions

With raw LiteSVM + Anchor, use the generated `accounts::` and `instruction::`
types to get proper account metas and discriminated instruction data:

```rust
use anchor_lang::{InstructionData, ToAccountMetas};

let ix = Instruction {
    program_id: PROGRAM_ID,
    accounts: crate::accounts::Make {
        maker,
        mint_a,
        vault,
        escrow,
        system_program: SYSTEM_PROGRAM_ID,
        token_program:  TOKEN_PROGRAM_ID,
        associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
    }
    .to_account_metas(None),
    data: crate::instruction::Make {
        seed:    123u64,
        deposit: 1_000_000,
        receive: 500_000,
    }
    .data(), // automatically adds Anchor's 8-byte discriminator
};
```

**Deserializing Anchor account state:**

```rust
use anchor_lang::AccountDeserialize;

let escrow_account = svm.get_account(&escrow_pda).unwrap();
let escrow_state = crate::state::Escrow::try_deserialize(
    &mut escrow_account.data.as_ref()
).unwrap();
assert_eq!(escrow_state.maker, maker_pubkey);
```

### 7b. Native / Pinocchio — Manual Instruction Data

Without a framework generating discriminators, encode instruction data manually.
Use a consistent first-byte discriminator scheme and document it:

```rust
// Instruction discriminators — must match processor.rs match arms
// 0 = Initialize, 1 = Contribute, 2 = CheckContributions, 3 = Refund

let init_data: Vec<u8> = [
    vec![0u8],                               // discriminator
    vec![bump],                              // PDA bump
    amount_to_raise.to_le_bytes().to_vec(),  // u64 LE
    vec![duration],                          // u8
]
.concat();

// Verify: data length must match exactly what the handler expects
// Document this comment next to every manual instruction build:
// discriminator(1) + bump(1) + amount(8) + duration(1) = 11 bytes
```

**Reading native account state (fixed-size layout):**

```rust
// Document field offsets matching the on-chain struct layout:
// [0..32]  = maker: Pubkey
// [32..64] = mint:  Pubkey
// [64..72] = amount_to_raise: u64
// [88]     = duration: u8
// [89]     = bump: u8
let fund_data = svm.get_account(&fundraiser_pda).unwrap().data;
let stored_amount = u64::from_le_bytes(fund_data[64..72].try_into().unwrap());
assert_eq!(stored_amount, expected_amount);
```

---

## 8. TEST STRUCTURE PATTERNS

### 8a. Shared Setup Helper (Recommended)

Extract common environment setup into a `setup()` function. Return everything the
test needs — never put shared mutable state in statics for LiteSVM:

```rust
fn setup() -> (LiteSVM, Keypair) { /* load program, airdrop, return */ }

fn setup_with_initialized_program(
    svm: &mut LiteSVM,
    maker: &Keypair,
) -> (Pubkey, Pubkey, Pubkey) {
    // create mints, ATAs, derive PDAs, send Initialize tx
    // return (mint, escrow_pda, vault_pda)
}
```

### 8b. Required Test Coverage Matrix

For every instruction, cover all four quadrants:

| | Success | Failure |
|---|---|---|
| **Happy path** | ✅ Full state verification | — |
| **Authorization** | — | ✅ Wrong signer → must fail |
| **Time / sequence** | ✅ After deadline | ✅ Before deadline |
| **Arithmetic edge** | — | ✅ Over-limit / zero-amount |
| **Reinit guard** | — | ✅ Double-initialize → must fail |
| **Account closure** | ✅ Verify lamports=0, data=0, owner=system | — |

### 8c. Account Closure Assertions

When a program closes an account, verify all three fields — not just lamports:

```rust
let closed = svm.get_account(&vault_pda).unwrap();
assert_eq!(closed.data.len(), 0,       "Closed account must have empty data");
assert_eq!(closed.lamports,    0,       "Closed account must have zero lamports");
assert_eq!(closed.owner,       SYSTEM_PROGRAM_ID, "Closed account must be owned by system");
```

---

## 9. LITESVM SECURITY TEST CHECKLIST

The following security tests must exist for every program using LiteSVM:

- [ ] Happy path succeeds end-to-end with full state verification
- [ ] Wrong signer → transaction fails
- [ ] Re-initialization of an existing account → fails
- [ ] Before-deadline action → fails (if time-locked)
- [ ] After-deadline action → succeeds (if time-locked)
- [ ] Over-contribution / over-limit arithmetic → fails
- [ ] Account closure verified: lamports=0, data.len()=0, owner=system_program
- [ ] Token balances verified after every transfer with explicit `assert_eq!`
- [ ] PDA derivation uses same seeds as on-chain — document them in test comments
- [ ] `expire_blockhash()` called after every transaction in multi-tx tests
- [ ] No `unwrap()` on `send_transaction` in tests that expect failure — use `assert!(result.is_err())`
- [ ] CU consumption logged at minimum for Initialize, primary action, and close

---

## 10. COMMON LITESVM ERRORS

| Error | Cause | Fix |
|---|---|---|
| `Failed to read SO file` | `cargo build-sbf` not run | Run `cargo build-sbf` first; check path in `PathBuf::from(env!("CARGO_MANIFEST_DIR"))` |
| `BlockhashNotFound` | Second tx uses same blockhash | Call `svm.expire_blockhash()` after each `send_transaction` |
| `InsufficientFundsForFee` | Payer has no SOL | `svm.airdrop(&payer.pubkey(), N * LAMPORTS_PER_SOL)` before test |
| `InvalidProgramForExecution` | Program not loaded or wrong ID | Verify `PROGRAM_ID` matches the `declare_id!` in `lib.rs` |
| `AccountNotFound` in assertion | Account never created or wrong pubkey | Check PDA derivation seeds match exactly; print pubkeys before asserting |
| GLIBC version error | Linux system < 2.38 | Use `solana-bankrun` instead |
| Token account not found | ATA not created before use | Create ATA with `CreateAssociatedTokenAccount` before minting or transferring |
| Wrong instruction data length | Manual data encoding off-by-one | Print `data.len()` and cross-check against handler's expected parse |
| Tests pass in isolation, fail together | Shared global state | Use `--test-threads=1`; never share `LiteSVM` across tests via globals |
