# ⚡ ZeroClaw Solana RPC Trimmer & Security Plugin

An ultra-fast, zero-allocation WASM Component designed for the **ZeroClaw** ecosystem, targeting `wasm32-wasip2`.

This plugin acts as a lightweight intermediate layer between Solana RPC nodes and Large Language Models (LLMs) inside ZeroClaw. Its primary purpose is to **dramatically reduce token consumption** by stripping structural JSON bloat and **prevent Prompt Injection attacks** embedded within untrusted on-chain metadata.

---

## 🎯 Key Problems Solved

1. **Context Window Bloat (Token Waste):** Standard Solana RPC responses include hundreds of lines of non-essential metadata (slots, blockhashes, signatures) that exhaust the LLM context window.
2. **On-Chain Prompt Injection Defense:** Attackers can inject malicious system instructions into SPL token names, symbols, or account metadata (e.g., inside `mint` or `owner` fields). This plugin strips and neutralizes these control characters before they reach the model.
3. **Heterogeneous RPC Structures:** Safely handles variations across different Solana RPC endpoints (`getAccountInfo`, `getTokenAccountBalance`, or native SOL accounts) using a hierarchical fallback mechanism without throwing panics.

---

## 🚀 Technical Architecture

- **Zero-Copy Parsing (`serde`):** Direct byte/slice manipulation (`&str` / `&[u8]`) to minimize heap allocations during parsing.
- **Inlined Nano-Functions (`#[inline(always)]`):** Encapsulates atomic routines (byte sanitation, delimiter checks, character stripping) directly into the CPU/WASM execution pipeline with zero function-call overhead.
- **WASI Preview 2 (WASM P2):** Built natively as an isolated WASM component conforming to the WIT contract interface (`wit/plugin.wit`).

---

## 📊 Benchmarks & Stress Testing

Benchmarked locally using Rust's integrated test engine under simulated attack and heavy-payload conditions:

| Metric | Result |
| :--- | :--- |
| **Processed Iterations** | 100,000 heavy RPC JSON payloads |
| **Total Execution Time** | ~5.17 seconds |
| **Average Latency** | **~51 µs per operation** |
| **Estimated Throughput** | +20,000 JSONs / second |
| **Security Verification** | 100% suppression of backticks and nested control braces `{}` |

---

## 🛠️ Project Structure

```text
.
├── Cargo.toml          # Optimized release profile (opt-level = "s", LTO enabled)
├── wit/
│   └── plugin.wit      # WIT interface contract for ZeroClaw integration
└── src/
    └── lib.rs          # Core Rust logic, sanitation nano-functions, fallbacks & tests