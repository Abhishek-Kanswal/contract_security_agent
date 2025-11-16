# On-Chain Security Agent 🔐

A smart contract security scanner built on Sentient Agent Framework that provides AI-powered risk assessments across multiple blockchains..

## 🌟 Features

- **Multi-Provider Security Analysis**: Integrates GoPlus, Etherscan, DexScreener, and CoinGecko
- **AI-Powered Summaries**: Human-readable risk analysis with 5-star ratings
- **Real-Time Streaming**: Progressive updates via Server-Sent Events (SSE)
- **Multi-Chain Support**: Works across 12+ blockchain networks
- **Quantitative Risk Scoring**: 0-100 security score with severity classification
- **Comprehensive Checks**: Honeypot detection, source verification, liquidity analysis, sentiment tracking

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- API keys for GoPlus, Etherscan (required)
- Fireworks AI API key (optional, for AI summaries)

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd contract_security_agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install sentient-agent-framework anyio requests python-dotenv pycoingecko openai langchain-core
```

### Configuration

Create a `.env` file in the project root:

```env
# Required API Keys
GOPLUS_APP_KEY=your_goplus_api_key
GOPLUS_APP_SECRET=your_goplus_secret_key
ETHERSCAN_API_KEY=your_etherscan_api_key

# Optional (for AI summaries)
MODEL_API_KEY=your_fireworks_api_key
```

### Get API Keys

| Provider | Sign Up Link | Purpose |
|----------|-------------|---------|
| GoPlus | [gopluslabs.io](https://gopluslabs.io) | Security analysis |
| Etherscan | [etherscan.io/apis](https://etherscan.io/apis) | Contract verification |
| Fireworks AI | [fireworks.ai](https://fireworks.ai) | AI summaries (optional) |

### Run the Agent

```bash
python app.py
```

The server will start at: `http://localhost:8000/assist`

## 📡 API Reference

### Endpoint

```
POST http://localhost:8000/assist
Content-Type: application/json
```

### Request Format

```json
{
  "session": {
    "id": "01JH4000000000000000000001",
    "processor_id": "01JH4000000000000000000002",
    "activity_id": "01JH4000000000000000000003",
    "request_id": "01JH4000000000000000000004",
    "user_id": "user123",
    "interactions": []
  },
  "query": {
    "id": "01JH4000000000000000000005",
    "prompt": "{\"chain\": \"ethereum\", \"address\": \"0xFCa95aeb5bF44aE355806A5ad14659c940dC6BF7\"}"
  }
}
```

### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session.id` | string | Yes | Unique identifier for the session (ULID format) |
| `session.processor_id` | string | Yes | Processor identifier |
| `session.activity_id` | string | Yes | Activity tracking identifier |
| `session.request_id` | string | Yes | Request tracking identifier |
| `session.user_id` | string | Yes | User identifier |
| `session.interactions` | array | Yes | Array of previous interactions (can be empty) |
| `query.id` | string | Yes | Query identifier (ULID format) |
| `query.prompt` | string (JSON) | Yes | JSON string containing chain and address |
| `chain` | string | Yes | Blockchain network (see supported chains) |
| `address` | string | Yes | Smart contract address (0x...) |

### cURL Example

```bash
curl -N -X POST "http://localhost:8000/assist" \
  -H "Content-Type: application/json" \
  -d "{
    \"session\": {
      \"id\": \"01JH4000000000000000000001\",
      \"processor_id\": \"01JH4000000000000000000002\",
      \"activity_id\": \"01JH4000000000000000000003\",
      \"request_id\": \"01JH4000000000000000000004\",
      \"user_id\": \"user123\",
      \"interactions\": []
    },
    \"query\": {
      \"id\": \"01JH4000000000000000000005\",
      \"prompt\": \"{\\\"chain\\\": \\\"ethereum\\\", \\\"address\\\": \\\"0xFCa95aeb5bF44aE355806A5ad14659c940dC6BF7\\\"}\"
    }
  }"
```

### Python Example

```python
import requests
import json

url = "http://localhost:8000/assist"
payload = {
    "session": {
        "id": "01JH4000000000000000000001",
        "processor_id": "01JH4000000000000000000002",
        "activity_id": "01JH4000000000000000000003",
        "request_id": "01JH4000000000000000000004",
        "user_id": "user123",
        "interactions": []
    },
    "query": {
        "id": "01JH4000000000000000000005",
        "prompt": json.dumps({
            "chain": "ethereum",
            "address": "0xFCa95aeb5bF44aE355806A5ad14659c940dC6BF7"
        })
    }
}

response = requests.post(url, json=payload, stream=True)
for line in response.iter_lines():
    if line:
        print(line.decode('utf-8'))
```

## 🔍 Security Checks

The agent performs comprehensive security analysis using four data sources:

### 1. GoPlus Security API

**What it checks:**
- Honeypot detection
- Scam/fraud flags
- Owner privileges and control
- Liquidity lock status
- Trading restrictions

**Risk Impact:**
- Honeypot detected: **-40 points**
- Owner has privileges: **-20 points**
- Liquidity not locked: **-15 points**
- Scam flag active: **-50 points**

### 2. Etherscan Explorer API

**What it checks:**
- Source code verification
- Proxy contract detection
- Contract implementation details
- Compiler version

**Risk Impact:**
- Unverified source code: **-15 points**
- Proxy contract: **-10 points**

### 3. DexScreener Market API

**What it checks:**
- Active trading pairs
- Liquidity depth (USD)
- Price data and charts
- Chain/address validation

**Risk Impact:**
- No trading pairs found: **-10 points**

### 4. CoinGecko Sentiment API

**What it checks:**
- Community sentiment metrics
- Up/down vote percentages
- Social engagement data

**Risk Impact:**
- Negative sentiment dominance: **-10 points**

### 5. AI Analysis (Optional)

**What it provides:**
- Human-readable summary (3-6 bullet points)
- One-sentence verdict
- 5-star safety rating (★★★★☆)
- Risk driver explanation

## ⛓️ Supported Chains

The agent supports 12+ blockchain networks:

| Chain | Identifier | Chain ID | Network Type |
|-------|-----------|----------|--------------|
| Ethereum | `ethereum`, `eth` | 1 | EVM |
| Binance Smart Chain | `bsc` | 56 | EVM |
| Polygon | `polygon` | 137 | EVM |
| Arbitrum | `arbitrum` | 42161 | L2 |
| Optimism | `optimism` | 10 | L2 |
| Avalanche | `avalanche` | 43114 | EVM |
| Base | `base` | 8453 | L2 |
| Fantom | `fantom` | 250 | EVM |
| Gnosis | `gnosis` | 100 | EVM |
| Celo | `celo` | 42220 | EVM |
| Solana | `solana` | 501 | Non-EVM |
| Tron | `tron` | 195 | Non-EVM |

## 📊 Response Format

The agent streams responses in real-time using Server-Sent Events (SSE). Each event has a specific type:

### Event Types

#### 1. PLAN
Initial assessment strategy
```json
{
  "type": "text_block",
  "name": "PLAN",
  "content": "Start on-chain security scan for 0x... on ethereum"
}
```

#### 2. STEP
Progress updates during data collection
```json
{
  "type": "text_block",
  "name": "STEP",
  "content": "Querying GoPlus for security signals..."
}
```

#### 3. Provider Events (GOPLUS, EXPLORER, DEX, SENTIMENT)
Raw data from each provider
```json
{
  "type": "json",
  "name": "GOPLUS",
  "content": {
    "data": {
      "is_honeypot": false,
      "is_scam": false,
      "owner_has_privileges": true
    }
  }
}
```

#### 4. REPORT
Complete security analysis
```json
{
  "type": "json",
  "name": "REPORT",
  "content": {
    "security_score": 85,
    "severity": "Low",
    "final_verdict": "Safe",
    "honeypot": false,
    "lp_and_trading": {...},
    "proxy_risk": {...},
    "social_red_flags": {...},
    "raw_findings": {...}
  }
}
```

#### 5. AI_SUMMARY
Human-readable AI analysis (if MODEL_API_KEY is set)
```json
{
  "type": "text_block",
  "name": "AI_SUMMARY",
  "content": "SUMMARY:\n• Contract verified on Etherscan\n• No honeypot detected\n• Liquidity: $1.2M\n\nVERDICT: Safe with minor centralization risk\nRATING: ★★★★☆"
}
```

#### 6. FINAL_RESPONSE
Summary verdict and score
```json
{
  "type": "text_stream",
  "name": "FINAL_RESPONSE",
  "content": "Final verdict: Safe\nSecurity score: 85 (Low)"
}
```

### Complete Response Example

```
event: PLAN
data: {"type":"text_block","name":"PLAN","content":"Start on-chain security scan..."}

event: STEP
data: {"type":"text_block","name":"STEP","content":"Querying GoPlus..."}

event: GOPLUS
data: {"type":"json","name":"GOPLUS","content":{"data":{"is_honeypot":false}}}

event: STEP
data: {"type":"text_block","name":"STEP","content":"Querying Etherscan..."}

event: EXPLORER
data: {"type":"json","name":"EXPLORER","content":{"result":[{"SourceCode":"..."}]}}

event: REPORT
data: {"type":"json","name":"REPORT","content":{"security_score":85,"severity":"Low"}}

event: AI_SUMMARY
data: {"type":"text_block","name":"AI_SUMMARY","content":"SUMMARY:\n• Safe contract"}

event: FINAL_RESPONSE
data: {"type":"text_stream","name":"FINAL_RESPONSE","content":"Final verdict: Safe"}
```

## 📈 Risk Scoring

### Scoring Algorithm

The agent uses a deductive scoring system starting from 100 points:

```
Base Score: 100 points (Perfect)

Deductions:
├─ GoPlus Checks
│  ├─ Honeypot detected: -40
│  ├─ Owner privileges: -20
│  ├─ Liquidity unlocked: -15
│  └─ Scam flag: -50
│
├─ Etherscan Checks
│  ├─ Unverified source: -15
│  └─ Proxy contract: -10
│
├─ DexScreener Checks
│  └─ No trading pairs: -10
│
└─ CoinGecko Checks
   └─ Negative sentiment: -10

Final Score: max(0, min(100, score))
```

### Severity Classification

| Score Range | Severity | Verdict | Description |
|-------------|----------|---------|-------------|
| 75-100 | **Low** | Safe | Minimal risks detected |
| 40-74 | **Medium** | Caution | Some concerns present |
| 0-39 | **High** | Dangerous | Serious risks identified |

### Score Examples

| Score | Verdict | Typical Indicators |
|-------|---------|-------------------|
| 100 | Safe | All checks passed perfectly |
| 85 | Safe | Verified contract, minor warnings |
| 70 | Caution | Unverified or proxy detected |
| 50 | Caution | Owner privileges + unverified |
| 30 | Dangerous | Multiple red flags |
| 10 | Dangerous | Honeypot or scam detected |

## 🛠️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GOPLUS_APP_KEY` | ✅ Yes | - | GoPlus Security API key |
| `GOPLUS_APP_SECRET` | ✅ Yes | - | GoPlus Security API secret |
| `ETHERSCAN_API_KEY` | ✅ Yes | - | Etherscan API key |
| `MODEL_API_KEY` | ⚠️ Optional | - | Fireworks AI API key for summaries |



## 📚 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Client Application                    │
└────────────────────────┬────────────────────────────────┘
                         │ POST /assist
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Sentient Server (Port 8000)                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │          OnchainSecurityAgent                     │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │      Request Processing Pipeline            │  │  │
│  │  │  1. Parse → 2. Fetch → 3. Score → 4. AI   │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└──────────┬──────────────────────────────────────────────┘
           │
           │ Parallel API Calls
           ▼
┌─────────────────────────────────────────────────────────┐
│               External Data Sources                      │
├────────────┬────────────┬────────────┬──────────────────┤
│  GoPlus    │ Etherscan  │DexScreener │   CoinGecko      │
└────────────┴────────────┴────────────┴──────────────────┘
           │
           │ Security Data
           ▼
┌─────────────────────────────────────────────────────────┐
│           ModelProvider (Fireworks AI)                   │
└─────────────────────────────────────────────────────────┘
```


---

**Built with**: Sentient Agent Framework • Python 3.8+ • Multiple Blockchain APIs

**Disclaimer**: Always conduct thorough due diligence before making any investment decisions. This tool is for informational purposes only.
