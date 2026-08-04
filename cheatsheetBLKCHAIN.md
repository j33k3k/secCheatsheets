# Blockchain CTF Cheatsheet

A reference for solving smart contract CTF challenges (HTB, Ethernaut, Damn Vulnerable DeFi, Paradigm CTF style). Covers fundamentals first, then vulnerability classes, then tooling/commands.

---

## 1. Core Concepts You Need First

### Accounts: EOA vs Contract
Ethereum has exactly two account types:

| Type | Controlled by | Has code? | Can initiate a tx? |
|---|---|---|---|
| **EOA** (Externally Owned Account) | A private key (you) | No | Yes |
| **Contract Account** | Its own code | Yes | No — only reacts to calls |

A contract can never *start* a transaction on its own. Every chain of calls, no matter how deep, ultimately traces back to one EOA that signed the original transaction.

### `msg.sender` vs `tx.origin`
This distinction is the single most important thing to internalize — it's the root of an entire vulnerability class.

- **`msg.sender`** — the address that made the *immediate* call to the current function. Changes at every hop.
- **`tx.origin`** — the EOA that signed the *original* transaction. Stays constant across the entire call chain, no matter how many contracts it passes through.

```
EOA (you) --calls--> Contract A --calls--> Contract B
```
Inside Contract B: `tx.origin` = you (EOA). `msg.sender` = Contract A.
Inside Contract A: `tx.origin` = you (EOA). `msg.sender` = you (EOA) — same as tx.origin, because you called it directly.

**Rule of thumb:** `tx.origin == msg.sender` is true only when the current function was called *directly* by an EOA, with no intermediate contract in between. This single boolean is what most `tx.origin` challenges hinge on.

### Units
- `1 ether = 10^18 wei`
- `1 gwei = 10^9 wei` (gas prices are usually quoted in gwei)
- Solidity has no floating point — everything is integer wei under the hood.

### Gas
- **Gas** = unit of computational work.
- **Gas price** = wei paid per unit of gas.
- **Gas limit** = max gas a tx is allowed to consume before it reverts (out-of-gas).
- Relevant for DoS challenges: a loop that grows unbounded can eventually exceed the block gas limit and become permanently uncallable.

### Nonce
- For an EOA: number of transactions sent (also determines the address of a contract it deploys via `CREATE`).
- For a contract: number of contracts *it* has deployed (relevant to `CREATE` address prediction, see §6).

### Function/State Visibility
| Keyword | Callable from |
|---|---|
| `public` | Anywhere (external calls + internally) |
| `external` | Only from outside the contract (cheaper for large calldata args) |
| `internal` | This contract + derived contracts only |
| `private` | This contract only — **NOT actually secret**, still readable on-chain (see §5.9) |

### Storage / Memory / Calldata
- **Storage**: persistent, written to the blockchain, expensive (this is your contract's "state").
- **Memory**: temporary, wiped after the function call ends, cheaper.
- **Calldata**: read-only, holds function arguments for `external` calls, cheapest.

### `payable`, `constructor`, `fallback`, `receive`
- **`payable`**: a function (or constructor) that can accept ETH. Without it, sending ETH to that function reverts.
- **`constructor`**: runs once at deployment.
- **`receive() external payable`**: triggered when the contract receives plain ETH with empty calldata.
- **`fallback()`**: triggered when no other function matches the called signature (or `receive` doesn't exist and calldata isn't empty). Often abused to intercept unexpected calls.

### ABI & Function Selectors
Every external function is identified on-chain not by name but by the first **4 bytes of `keccak256("functionName(argType1,argType2)")`**. This is why you'll see raw hex selectors in calldata — `cast sig` and `cast 4byte` translate between the two (see §7).

---

## 2. Call Types — `call` vs `delegatecall` vs `staticcall`

This matters enormously for proxy/storage-collision challenges.

| Type | Executes code from | Uses *whose* storage/msg.sender/msg.value | State changes allowed |
|---|---|---|---|
| `call` | Target contract | Target's own storage, target sees caller as `msg.sender` | Yes |
| `staticcall` | Target contract | Target's own storage | No (reverts on any write) |
| `delegatecall` | Target contract's **code** | **Caller's** storage, `msg.sender`/`msg.value` unchanged (preserved from original call) | Yes |

`delegatecall` is how proxy patterns work: a lightweight proxy contract holds the storage/balance, and `delegatecall`s into a logic contract for the actual code. If the proxy's storage layout doesn't exactly match the logic contract's expected layout, you get **storage collisions** — writing to what the logic contract thinks is `owner` might actually overwrite the proxy's `implementation` address slot. This was the root cause of the Parity multisig freeze.

---

## 3. Common Vulnerability Classes (What CTFs Actually Test)

### 3.1 `tx.origin` Authentication / Access Control Bypass
**Pattern:** Contract uses `tx.origin` instead of `msg.sender` for an auth check, or (like your Creature challenge) uses `tx.origin != msg.sender` as a "called through a contract" detector.

**Exploit:** Deploy a small intermediary contract. Trick/wait for the victim (or yourself) to call through it — `tx.origin` will be the original EOA while `msg.sender` is your contract, satisfying (or breaking) whatever check relies on that comparison.

**Real world:** Phishing — a malicious contract tricks a wallet with `tx.origin`-based auth into approving actions it shouldn't.

### 3.2 Reentrancy
**Pattern:** Contract sends ETH/tokens (external call) *before* updating its own state (checks-effects-interactions violated).

```solidity
function withdraw() external {
    uint bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}(""); // <-- external call FIRST
    require(ok);
    balances[msg.sender] = 0;                     // <-- state updated AFTER
}
```

**Exploit:** Your attacking contract's `receive()`/`fallback()` re-calls `withdraw()` before the balance is zeroed, draining more than you're entitled to, recursively.

**Fix pattern to recognize:** Checks-Effects-Interactions ordering, or a `nonReentrant` modifier (mutex/lock flag).

**Variants:** cross-function reentrancy (re-enter a *different* function that shares the vulnerable state), read-only reentrancy (re-enter during a view call that other protocols trust mid-update).

### 3.3 Integer Overflow / Underflow
**Pattern:** Arithmetic wraps around instead of reverting.
- Solidity **≥0.8.0**: overflow/underflow reverts automatically *unless* wrapped in an `unchecked { }` block.
- Solidity **<0.8.0**: silently wraps — a classic bug in older challenge contracts. `0 - 1` becomes `2^256 - 1`.

**Exploit:** Find an `unchecked` block or a pre-0.8 pragma, then force a subtraction below zero or addition past the max uint to wrap the value into something exploitable (e.g., inflate a token balance).

### 3.4 Weak Randomness / Predictable PRNG
**Pattern:** "Random" outcome derived from on-chain, publicly known/predictable values:
```solidity
uint random = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
```
Every input here is either known in advance or predictable within the block being mined (miners/validators can even influence `block.timestamp` slightly, and `block.difficulty`/`block.prevrandao` is visible before your tx lands).

**Exploit:** Compute the same value off-chain (or from within an attacking contract in the same call), predict the "random" result, and act accordingly before/in the same transaction.

**Real world:** This is conceptually the same class as the Coldcard RNG failure — insufficient entropy sourced from predictable inputs.

### 3.5 Access Control Misconfiguration
**Pattern:** Missing `onlyOwner`/role modifier on a sensitive function, a modifier that checks the wrong condition, or an `initialize()` function (common in upgradeable/proxy contracts) that can be called by anyone after deployment because the constructor pattern was replaced but nobody locked `initialize()` down.

**Exploit:** Just... call the unprotected function. Always check every state-changing function for what access control it *actually* enforces vs. what it's supposed to enforce.

### 3.6 Front-Running / MEV
**Pattern:** A transaction's outcome depends on it being mined first (e.g., a commit-less "first come" claim, or a price that hasn't updated yet).

**Exploit:** Watch the mempool for the victim's transaction, then submit your own with higher gas to get mined first (or in the same block, ordered favorably).

### 3.7 Price/Oracle Manipulation
**Pattern:** Contract derives a price directly from a single on-chain source (e.g., the reserves of one DEX liquidity pool) rather than a manipulation-resistant oracle (TWAP, Chainlink).

**Exploit:** Within a single transaction (often via flash loan), massively skew the pool's reserves, trigger the vulnerable contract to read the now-distorted price, profit, then restore/repay — all atomically.

### 3.8 Flash Loan Logic Abuse
**Pattern:** Not a bug in the flash loan itself — the flash loan just gives you temporary, uncollateralized capital *within one transaction* to amplify one of the other bugs above (oracle manipulation, governance vote manipulation, etc.).

**Exploit shape:** borrow → manipulate → exploit → repay, all atomic, all-or-nothing (if repayment fails, the whole tx reverts, so there's no real risk to the attacker beyond gas).

### 3.9 "Private" State Isn't Actually Private
**Pattern:** Challenge relies on a `private` variable (e.g., a password, secret number) being hidden.

**Reality:** `private` only restricts *Solidity-level* access from other contracts. All contract storage is **publicly readable** directly off-chain via RPC, regardless of visibility keyword.

**Exploit:** Read the raw storage slot directly:
```bash
cast storage <CONTRACT_ADDRESS> <SLOT_NUMBER> --rpc-url $RPC_URL
```
Figuring out which slot number a variable lives in requires understanding Solidity's storage layout (sequential slots, packing rules for small types, `mapping`/dynamic array slot hashing via `keccak256(slot)`).

### 3.10 Signature Replay / Malleability
**Pattern:** Contract verifies an ECDSA signature (`ecrecover`) to authorize an action but doesn't include a nonce, chain ID, or "used" tracking.

**Exploit:** Capture a valid signature (e.g., from an event log or a legitimate prior transaction) and resubmit it — on the same contract (replay), on a different contract with the same logic, or on a different chain (if chain ID isn't in the signed message).

**Malleability variant:** ECDSA signatures have two valid `(r,s,v)` representations for the same signer; if the contract uses the raw signature as a unique identifier (e.g., "has this sig been used") rather than tracking a nonce, you can flip `s` to `secp256k1n - s` and `v` to get a second valid signature for the same authorization.

### 3.11 `selfdestruct` Force-Feeding ETH
**Pattern:** A contract's logic assumes `address(this).balance` can only change via its own `payable` functions.

**Reality:** `selfdestruct(target)` force-sends the destructing contract's entire balance to `target`, bypassing `receive()`/`fallback()` entirely — no code execution happens on the receiving end, so no `payable` restriction can block it.

**Exploit:** Deploy a throwaway contract, fund it, call `selfdestruct(victimAddress)` to corrupt the victim's balance assumptions (e.g., break a `require(address(this).balance == expectedAmount)` check).

### 3.12 Denial of Service (Unbounded Loops / Revert-on-Transfer)
**Pattern A:** A function loops over a dynamic array (e.g., paying out all investors) that can grow without bound — eventually the loop costs more gas than the block limit, permanently bricking the function.

**Pattern B:** A function's logic depends on a `.transfer()`/`.send()` to an *arbitrary* address succeeding — if that address is a contract that deliberately reverts in its `receive()`, the whole transaction (and often the whole contract's core flow) gets stuck.

**Exploit:** Become the poison entry — either the array element that never resolves, or the recipient contract that always reverts.

### 3.13 Uninitialized Storage Pointers / Proxy Storage Collision
**Pattern:** Covered under `delegatecall` above — a proxy's storage layout must exactly mirror the logic contract's, slot-for-slot, in the same order. If a new state variable gets inserted anywhere but the very end in an upgrade, every subsequent slot shifts and effectively swaps meanings between proxy and logic contract.

**Exploit:** Find the slot mismatch, then write to a function that (unknowingly, from the logic contract's perspective) actually overwrites something critical, like the proxy's stored `owner` or `implementation` address.

---

## 4. General Solving Methodology

1. **Read every `.sol` file fully before touching anything.** Note every `external`/`public` function and what each one actually checks vs. what it seems designed to check.
2. **Find the win condition.** Almost always an `isSolved()` view function in a `Setup.sol` — read exactly what state it requires (`balance == 0`, `owner == attacker`, `solved == true`, etc.). This tells you your actual goal, which is sometimes different from "drain everything."
3. **Map out `msg.sender` / `tx.origin` / `address(this)` at every call boundary.** Draw the call chain on paper if it's more than 2 hops — this is where most bugs hide.
4. **Check the Solidity version (`pragma`).** <0.8.0 → overflow/underflow is in play. Note any `unchecked` blocks even on newer versions.
5. **Check every arithmetic operation and every external call ordering** (state updated before or after the call?).
6. **Grep for `tx.origin`, `block.timestamp`, `block.difficulty`/`block.prevrandao`, `blockhash`, `selfdestruct`, `delegatecall`, `.transfer(`/`.send(`/`.call(`.** These strings are disproportionately where CTF bugs live.
7. **Write the exploit as a Foundry contract/script**, not manual `cast send` calls one at a time — you often need multiple actions to happen atomically in one transaction (deploy attacker contract + call it, all in one tx) which plain `cast` alone can't do.
8. **Test locally first if possible.** Fork the target's RPC into a local `anvil` instance, iterate fast, then replay against the real target once it works.
9. **Verify with `isSolved()`** via `cast call` before assuming you're done.

---

## 5. Kali/Foundry Toolchain Setup

```bash
# Foundry (forge, cast, anvil, chisel)
curl -L https://foundry.paradigm.xyz | bash
source ~/.zshrc      # or ~/.bashrc — match your actual $SHELL
foundryup

# Python web3 (for scripting outside Foundry, or parsing HTB connection info)
pip3 install web3 --break-system-packages

# solc version manager (challenges often pin old compiler versions)
pip3 install solc-select --break-system-packages
solc-select install 0.8.19
solc-select use 0.8.19

# Utilities
sudo apt install -y jq netcat-traditional
```

New Foundry project:
```bash
forge init exploit --no-git
cd exploit
forge install foundry-rs/forge-std --no-git
```

---

## 6. `cast` Command Reference (Read/Write Chain State)

### Reading state
```bash
# Call a view function (no gas spent, no tx sent)
cast call <CONTRACT> "functionName(argType)(returnType)" <arg> --rpc-url $RPC_URL

# ETH balance of an address
cast balance <ADDRESS> --rpc-url $RPC_URL

# Raw bytecode deployed at an address (confirms it's a contract, not EOA)
cast code <ADDRESS> --rpc-url $RPC_URL

# Read a raw storage slot directly (bypasses `private` visibility)
cast storage <CONTRACT> <SLOT_NUMBER> --rpc-url $RPC_URL

# Current block number
cast block-number --rpc-url $RPC_URL

# Nonce of an address (also predicts next CREATE-deployed contract address)
cast nonce <ADDRESS> --rpc-url $RPC_URL
```

### Sending state-changing transactions
```bash
# Send a transaction calling a function
cast send <CONTRACT> "functionName(argType)" <arg> \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY

# Send with ETH value attached
cast send <CONTRACT> "deposit()" --value 1ether \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY
```

### Encoding / decoding / hashing helpers
```bash
# Get a function's 4-byte selector
cast sig "transfer(address,uint256)"

# Look up an unknown 4-byte selector's likely function signature (public DB)
cast 4byte 0xa9059cbb

# ABI-encode arguments (useful for building raw calldata)
cast abi-encode "f(address,uint256)" 0xAbc... 100

# keccak256 hash (e.g., for computing a storage slot for a mapping key)
cast keccak "someString"

# Unit conversions
cast --to-wei 1 ether
cast --from-wei 1000000000000000000
```

### Predicting deployed contract addresses
```bash
# CREATE (sequential nonce-based) address prediction
cast compute-address <DEPLOYER_ADDRESS> --nonce <NONCE> --rpc-url $RPC_URL
```

---

## 7. `forge` Command Reference

```bash
forge init <name> --no-git          # scaffold a new project
forge build                          # compile
forge test -vvvv                     # run tests with full call traces (great for debugging exploits locally)
forge script script/Solve.s.sol:Solve --rpc-url $RPC_URL --broadcast   # run + broadcast an exploit script
forge create src/Attacker.sol:Attacker --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args <TARGET_ADDR>   # deploy a single contract directly without a script
```

**`-vvvv` on `forge test` or `forge script`** gives you full execution traces — invaluable for seeing exactly what `msg.sender`/`tx.origin` resolved to at each call depth when something isn't behaving as expected.

Local forking for safe iteration before hitting the real target:
```bash
anvil --fork-url $RPC_URL
# then point your exploit script at http://localhost:8545 to test repeatedly for free
```

---

## 8. Exploit Contract Skeleton (Reusable Template)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ITarget {
    // declare only the functions you need to call
    function vulnerableFunction(uint256 x) external;
}

contract Attacker {
    ITarget public target;

    constructor(address _target) {
        target = ITarget(_target);
    }

    function exploit() external {
        target.vulnerableFunction(1000);
    }

    // needed if the exploit involves reentrancy or receiving ETH
    receive() external payable {
        // re-entrant call logic here, if applicable
    }
}
```

Foundry script skeleton:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {Attacker} from "../src/Attacker.sol";

contract Solve is Script {
    function run() external {
        address targetAddr = vm.envAddress("TARGET");
        uint256 pk = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(pk);
        Attacker atk = new Attacker(targetAddr);
        atk.exploit();
        vm.stopBroadcast();
    }
}
```

Run it:
```bash
export RPC_URL=<from nc session>
export PRIVATE_KEY=<from nc session>
export TARGET=<vulnerable contract address>

forge script script/Solve.s.sol:Solve --rpc-url $RPC_URL --broadcast
```

---

## 9. Quick Glossary

| Term | Meaning |
|---|---|
| EOA | Externally Owned Account — controlled by a private key |
| ABI | Application Binary Interface — how to encode calls to a contract |
| Selector | First 4 bytes of `keccak256` of a function's signature |
| Wei/Gwei/Ether | Units of ETH (10^18 / 10^9 / 1) |
| Gas | Computational cost unit for EVM execution |
| Nonce | Tx counter for an EOA; deployment counter for `CREATE` |
| `call` | Executes target's code in target's context |
| `delegatecall` | Executes target's code in **caller's** context/storage |
| `staticcall` | Read-only `call`, reverts on state change |
| Reentrancy | Re-entering a function before its state update completes |
| `tx.origin` | The original EOA that signed the transaction (constant across the whole call chain) |
| `msg.sender` | The immediate caller of the current function (changes every hop) |
| PRNG | Pseudo-random number generator — weak if seeded from predictable on-chain data |
| Flash loan | Uncollateralized loan valid only within a single atomic transaction |
| Oracle | On-chain source of external data (e.g., price feeds) |
| `selfdestruct` | Destroys a contract, force-sends its balance, bypasses `receive`/`fallback` |
| Storage slot | Fixed-size (32 byte) unit of persistent contract storage, sequentially indexed |
