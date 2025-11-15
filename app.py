# onchain_security_agent_with_ai.py
"""
On-Chain Security Sentient Agent + LLM Summary (AI_SUMMARY)

- Streams steps and returns a JSON REPORT.
- After REPORT is ready, calls the configured LLM provider to generate
  a human-friendly AI summary and rating and emits it as an `AI_SUMMARY` event.

Run:
  pip install sentient-agent-framework anyio requests python-dotenv pycoingecko openai langchain-core
  python onchain_security_agent_with_ai.py

Environment variables expected:
  GOPLUS_APP_KEY, GOPLUS_APP_SECRET, ETHERSCAN_API_KEY
  MODEL_API_KEY (for the OpenAI/Fireworks-like client used below)

Notes:
- The ModelProvider uses AsyncOpenAI (OpenAI-compatible async client).
- If MODEL_API_KEY is missing, the agent will still work but AI_SUMMARY will indicate the model was not available.
"""

# ---------------------------------------------------------------------------
# Minimal SSL shim (keeps imports working on restricted Python builds)
# ---------------------------------------------------------------------------
import sys
try:
    import ssl  # noqa
except ModuleNotFoundError:
    import types
    dummy_ssl = types.ModuleType("ssl")
    dummy_ssl.SSLContext = object
    dummy_ssl.CERT_NONE = 0
    dummy_ssl.CERT_REQUIRED = 1
    dummy_ssl.PROTOCOL_TLS = 0
    sys.modules["ssl"] = dummy_ssl
    print("[WARN] SSL not available; injected dummy 'ssl' module. HTTPS verify may fail.")

# ---------------------------------------------------------------------------
# Standard imports
# ---------------------------------------------------------------------------
import os
import math
import json
import logging
import re
from typing import Any, Dict, AsyncIterator

import requests
import anyio
from dotenv import load_dotenv
from pycoingecko import CoinGeckoAPI

from sentient_agent_framework import AbstractAgent, DefaultServer, Session, Query, ResponseHandler

# ---------------------------------------------------------------------------
# ModelProvider (integrated here)
# ---------------------------------------------------------------------------
from datetime import datetime
from langchain_core.prompts import PromptTemplate
try:
    from openai import AsyncOpenAI
except Exception:
    # If AsyncOpenAI is not installed, define a small shim that will produce errors at runtime.
    AsyncOpenAI = None  # type: ignore

class ModelProvider:
    """
    Minimal model provider wrapper using AsyncOpenAI (or compatible client).
    Provides streaming query and a convenience summarize_security_report(report) method.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.fireworks.ai/inference/v1"
        # default model id - replace if your provider uses a different identifier
        self.model = "accounts/sentientfoundation/models/dobby-unhinged-llama-3-3-70b-new"
        self.temperature = 0.0
        self.max_tokens = None
        self.system_prompt = "default"
        self.date_context = datetime.now().strftime("%Y-%m-%d")

        if AsyncOpenAI is None:
            self.client = None
        else:
            # initialize client
            self.client = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key)

        # prepare system prompt text
        if self.system_prompt == "default":
            sp = PromptTemplate(input_variables=["date_today"],
                                template="You are a helpful assistant that can answer questions and provide information.")
            self.system_prompt = sp.format(date_today=self.date_context)

    async def query_stream(self, query: str) -> AsyncIterator[str]:
        """Stream the model completion. Yields text chunks."""
        if self.client is None:
            # client not configured
            raise RuntimeError("Model client not available (AsyncOpenAI missing or not installed)")

        if self.model in ["o1-preview", "o1-mini"]:
            messages = [{"role": "user", "content": f"System Instruction: {self.system_prompt}\nInstruction:{query}"}]
        else:
            messages = [{"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": query}]

        stream = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True,
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        async for chunk in stream:
            # guard for different chunk shapes
            try:
                delta = chunk.choices[0].delta
                content = getattr(delta, "content", None)
                if content is None:
                    # some providers use "message" or "text"
                    content = getattr(chunk.choices[0], "text", None)
                if content:
                    yield content
            except Exception:
                # best-effort: try string conversion
                try:
                    yield str(chunk)
                except Exception:
                    continue

    async def query(self, query: str) -> str:
        """Return the full response as a string (concatenate streamed chunks)."""
        chunks = []
        async for c in self.query_stream(query=query):
            chunks.append(c)
        return "".join(chunks)

    async def summarize_security_report(self, report: dict) -> str:
        """
        Create a clear AI summary and a concise rating from the security report.
        Returns a plain text summary (LLM output).
        """
        # Compose the prompt: include the JSON (safely truncated if huge)
        raw = json.dumps(report, indent=2)
        if len(raw) > 10000:
            raw = raw[:10000] + "\n...TRUNCATED..."

        prompt = f"""
You are a blockchain security analyst assistant.

Below is a machine-generated security scan of a smart contract (JSON).
Interpret the important fields and produce:

1) A short human-readable SUMMARY (3-6 bullet points).
2) A one-sentence VERDICT.
3) A 5-star safety RATING (format: ★★★★☆).
4) A short explanation of the main risk drivers (1-2 sentences).

Security scan JSON:
{raw}

Respond with plain text. Start with the word "SUMMARY:".
"""
        # If model client not available, return an explanatory message
        if self.client is None:
            return "SUMMARY: Model client not available. Set MODEL_API_KEY and install an OpenAI-compatible async client."

        try:
            output = await self.query(prompt)
            return output
        except Exception as e:
            return f"SUMMARY: Error generating summary: {str(e)}"

# ---------------------------------------------------------------------------
# Load environment & keys
# ---------------------------------------------------------------------------
load_dotenv()
GOPLUS_APP_KEY = os.getenv("GOPLUS_APP_KEY")
GOPLUS_APP_SECRET = os.getenv("GOPLUS_APP_SECRET")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
COINGECKO_BASE = "https://api.coingecko.com/api/v3"
MODEL_API_KEY = os.getenv("MODEL_API_KEY")  # for ModelProvider

logger = logging.getLogger("onchain_agent")
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Chain mapping and CG client
# ---------------------------------------------------------------------------
CHAIN_MAP = {
    "ethereum": (1, 1, "ethereum"),
    "eth": (1, 1, "ethereum"),
    "bsc": (56, 56, "bsc"),
    "polygon": (137, 137, "polygon"),
    "avalanche": (43114, 43114, "avalanche"),
    "optimism": (10, 10, "optimism"),
    "arbitrum": (42161, 42161, "arbitrum"),
    "base": (8453, 8453, "base"),
    "fantom": (250, 250, "fantom"),
    "gnosis": (100, 100, "gnosis"),
    "celo": (42220, 42220, "celo"),
    "solana": (501, None, "solana"),
    "tron": (195, None, "tron"),
}

cg = CoinGeckoAPI()

# ---------------------------------------------------------------------------
# Provider helpers (unchanged)
# ---------------------------------------------------------------------------
def call_goplus(chain: str, address: str) -> Dict[str, Any]:
    if not GOPLUS_APP_KEY or not GOPLUS_APP_SECRET:
        return {"error": "missing_goplus_auth"}
    mapping = CHAIN_MAP.get(chain.lower())
    chain_id = mapping[0] if mapping else chain
    url = f"https://api.gopluslabs.io/api/v2/smart-contract/{chain_id}"
    params = {"contract_addresses": address}
    headers = {"X-API-KEY": GOPLUS_APP_KEY, "X-API-SECRET": GOPLUS_APP_SECRET}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug("GoPlus error", exc_info=e)
        return {"error": str(e)}

def call_etherscan_get_source(chain: str, address: str) -> Dict[str, Any]:
    if not ETHERSCAN_API_KEY:
        return {"error": "missing_etherscan_key"}
    mapping = CHAIN_MAP.get(chain.lower())
    etherscan_chainid = mapping[1] if mapping else None
    if etherscan_chainid is None:
        return {"error": f"etherscan_not_supported_for_chain:{chain}"}
    url = "https://api.etherscan.io/v2/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "chainid": etherscan_chainid,
        "apikey": ETHERSCAN_API_KEY,
    }
    try:
        r = requests.get(url, params=params, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug("Etherscan error", exc_info=e)
        return {"error": str(e)}

def call_dexscreener_token(chain: str, address: str) -> Any:
    mapping = CHAIN_MAP.get(chain.lower())
    slug = mapping[2] if mapping else chain.lower()
    url = "https://api.dexscreener.com/token-profiles/latest/v1"
    params = {"chain": slug, "address": address}
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        try:
            url2 = f"https://api.dexscreener.com/latest/dex/tokens/{slug}/{address}"
            r2 = requests.get(url2, timeout=10)
            r2.raise_for_status()
            return r2.json()
        except Exception as e2:
            logger.debug("DexScreener error", exc_info=e2)
            return {"error": str(e2)}

def call_coingecko_sentiment(chain: str, address: str) -> Dict[str, Any]:
    mapping = CHAIN_MAP.get(chain.lower())
    if not mapping:
        return {"error": "coingecko_not_supported_for_chain"}
    slug = mapping[2]
    platform = "ethereum"
    if slug == "bsc":
        platform = "binance-smart-chain"
    elif slug == "polygon":
        platform = "polygon-pos"
    url = f"{COINGECKO_BASE}/coins/{platform}/contract/{address}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "community": data.get("community_data", {}),
                "sentiment_up": data.get("sentiment_votes_up_percentage"),
                "sentiment_down": data.get("sentiment_votes_down_percentage"),
            }
        else:
            return {"error": f"coingecko_status_{r.status_code}"}
    except Exception as e:
        logger.debug("CoinGecko error", exc_info=e)
        return {"error": str(e)}

# ---------------------------------------------------------------------------
# Scoring logic (unchanged)
# ---------------------------------------------------------------------------
def synthesize_report(chain: str, address: str, providers: Dict[str, Any]) -> Dict[str, Any]:
    score = 100
    findings: Dict[str, Any] = {}

    g = providers.get("goplus", {})
    if "error" in g:
        findings["goplus"] = {"error": g["error"]}
    else:
        findings["goplus"] = g
        gp_risk = 0
        if isinstance(g, dict):
            data = g.get("data") if "data" in g else g
            if data.get("is_honeypot"):
                gp_risk += 40
            if data.get("owner_has_privileges"):
                gp_risk += 20
            if data.get("lp_locked") is False:
                gp_risk += 15
            if data.get("is_scam"):
                gp_risk += 50
        score -= gp_risk

    e = providers.get("explorer", {})
    if "error" in e:
        findings["explorer"] = {"error": e["error"]}
    else:
        findings["explorer"] = e
        result_list = (e.get("result") if isinstance(e, dict) else None) or []
        if result_list:
            r0 = result_list[0]
            if not r0.get("SourceCode"):
                score -= 15
            if str(r0.get("Proxy")).lower() in ("1", "true"):
                score -= 10

    d = providers.get("dexscreener", {})
    if isinstance(d, list):
        d = d[0] if len(d) > 0 else {}
    if not isinstance(d, dict):
        findings["dexscreener"] = {"error": "invalid_dexscreener_response"}
    else:
        findings["dexscreener"] = d
        pairs = d.get("pairs") or d.get("tokenPairs") or []
        chainid = d.get("chainId") or d.get("chain")
        tokenaddr = (d.get("tokenAddress") or d.get("address") or "").lower()
        mapping = CHAIN_MAP.get(chain.lower())
        slug = mapping[2] if mapping else chain.lower()
        if chainid and str(chainid).lower() != str(slug).lower():
            findings["dexscreener"] = {"error": "dex_chain_mismatch"}
        elif tokenaddr and tokenaddr != address.lower():
            findings["dexscreener"] = {"error": "dex_address_mismatch"}
        else:
            if not pairs:
                score -= 10

    s = providers.get("sentiment", {})
    if "error" in s:
        findings["sentiment"] = {"error": s["error"]}
    else:
        findings["sentiment"] = s
        up = s.get("sentiment_up")
        down = s.get("sentiment_down")
        if up is not None and down is not None and down > up:
            score -= 10

    score = max(0, min(100, int(math.ceil(score))))
    if score >= 75:
        severity = "Low"
        verdict = "Safe"
    elif score >= 40:
        severity = "Medium"
        verdict = "Caution"
    else:
        severity = "High"
        verdict = "Dangerous"

    return {
        "security_score": score,
        "severity": severity,
        "vulnerabilities": {},
        "owner_permissions": {},
        "honeypot": findings.get("goplus", {}).get("is_honeypot")
        or (findings.get("goplus", {}).get("data") or {}).get("is_honeypot"),
        "lp_and_trading": findings.get("dexscreener"),
        "proxy_risk": findings.get("explorer"),
        "social_red_flags": findings.get("sentiment"),
        "final_verdict": verdict,
        "raw_findings": findings,
    }

# ---------------------------------------------------------------------------
# Emit helpers (unchanged)
# ---------------------------------------------------------------------------
def normalize_for_emit(content: Any) -> Dict[str, Any]:
    if isinstance(content, dict):
        return content
    if isinstance(content, list):
        summary = {"__type": "list", "length": len(content)}
        if len(content) > 0 and isinstance(content[0], dict):
            summary["sample"] = content[0]
        else:
            summary["sample"] = str(content[0]) if len(content) > 0 else None
        return summary
    return {"value": content}

async def safe_emit_json(response_handler: ResponseHandler, name: str, content: Any):
    try:
        norm = normalize_for_emit(content)
        await response_handler.emit_json(name, norm)
    except Exception as e:
        logger.exception("emit_json failed for %s", name)
        await response_handler.emit_error("ERROR", {"event": name, "error": str(e), "content_preview": str(content)[:100]})

# ---------------------------------------------------------------------------
# Agent (integrated with ModelProvider to emit AI_SUMMARY)
# ---------------------------------------------------------------------------
class OnchainSecurityAgent(AbstractAgent):
    def __init__(self, name: str = "OnchainSecurityAgent"):
        super().__init__(name)

    async def assist(self, session: Session, query: Query, response_handler: ResponseHandler):
        try:
            # Parse query
            payload = query.prompt
            if isinstance(payload, str):
                payload = json.loads(payload)

            chain = payload.get("chain")
            address = payload.get("address")

            if not chain or not address:
                raise ValueError("missing chain or address")

            # Step 1: Plan
            await response_handler.emit_text_block(
                "PLAN",
                f"Start on-chain security scan for {address} on {chain}"
            )

            # Step 2: GoPlus
            await response_handler.emit_text_block("STEP", "Querying GoPlus for security signals...")
            goplus_res = await anyio.to_thread.run_sync(call_goplus, chain, address)
            await safe_emit_json(response_handler, "GOPLUS", goplus_res)

            # Step 3: Etherscan
            await response_handler.emit_text_block("STEP", "Querying Etherscan for source code & proxy info...")
            etherscan_res = await anyio.to_thread.run_sync(call_etherscan_get_source, chain, address)
            await safe_emit_json(response_handler, "EXPLORER", etherscan_res)

            # Step 4: DexScreener
            await response_handler.emit_text_block("STEP", "Querying DexScreener for liquidity & pairs...")
            dexscreener_raw = await anyio.to_thread.run_sync(call_dexscreener_token, chain, address)

            if isinstance(dexscreener_raw, list):
                dexscreener_for_emit = (
                    dexscreener_raw[0]
                    if len(dexscreener_raw) > 0 and isinstance(dexscreener_raw[0], dict)
                    else {"__type": "list", "length": len(dexscreener_raw)}
                )
            elif isinstance(dexscreener_raw, dict):
                dexscreener_for_emit = dexscreener_raw
            else:
                dexscreener_for_emit = {"error": "invalid_dexscreener_response"}

            await safe_emit_json(response_handler, "DEX", dexscreener_for_emit)

            # Step 5: CoinGecko
            await response_handler.emit_text_block("STEP", "Querying CoinGecko for sentiment...")
            coingecko_res = await anyio.to_thread.run_sync(call_coingecko_sentiment, chain, address)
            await safe_emit_json(response_handler, "SENTIMENT", coingecko_res)

            # Step 6: Synthesize Report
            providers = {
                "goplus": goplus_res,
                "explorer": etherscan_res,
                "dexscreener": dexscreener_raw,
                "sentiment": coingecko_res
            }

            await response_handler.emit_text_block("STEP", "Synthesizing final security report...")
            report = await anyio.to_thread.run_sync(synthesize_report, chain, address, providers)

            await safe_emit_json(response_handler, "REPORT", report)

            # ---------------------------------------------------------
            # Step 7: AI SUMMARY USING MODEL PROVIDER
            # ---------------------------------------------------------
            try:
                from providers.model_provider import ModelProvider
                ai_provider = ModelProvider(api_key=os.getenv("FW_API_KEY"))

                ai_prompt = (
                    "Provide a clear, human-friendly risk summary for the following "
                    "smart contract security scan.\n"
                    "Include:\n"
                    "- Overall risk level\n"
                    "- Main concerns and indicators\n"
                    "- Honeypot / scam evaluation\n"
                    "- Liquidity and trading risks\n"
                    "- Community sentiment interpretation\n"
                    "- Recommended next action\n\n"
                    f"Security Report:\n{json.dumps(report, indent=2)}"
                )

                ai_summary = await ai_provider.query(ai_prompt)

            except Exception as e:
                ai_summary = f"AI summary unavailable: {str(e)}"

            await response_handler.emit_text_block(
                "AI_SUMMARY",
                ai_summary
            )

            # ---------------------------------------------------------

            # Step 8: Final human-readable output
            summary = (
                f"Final verdict: {report['final_verdict']}\n"
                f"Security score: {report['security_score']} ({report['severity']})\n"
            )

            stream = response_handler.create_text_stream("FINAL_RESPONSE")
            await stream.emit_chunk(summary)
            await stream.complete()

            await response_handler.complete()

        except Exception as exc:
            logger.exception("Unhandled error in assist()")
            await response_handler.emit_error(
                "ERROR",
                {"message": "internal_error", "error": str(exc)}
            )
            try:
                await response_handler.complete()
            except Exception:
                pass
# ---------------------------------------------------------------------------
# Run server (port 8005)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    missing = [k for k, v in {"GOPLUS_APP_KEY": GOPLUS_APP_KEY, "GOPLUS_APP_SECRET": GOPLUS_APP_SECRET, "ETHERSCAN_API_KEY": ETHERSCAN_API_KEY}.items() if not v]
    if missing:
        logger.warning("Missing API keys: %s. Some providers may return limited/errored responses.", missing)

    # Inform about MODEL_API_KEY presence
    if not MODEL_API_KEY:
        logger.info("MODEL_API_KEY not set — AI summaries disabled.")
    else:
        logger.info("MODEL_API_KEY found — AI summaries enabled.")

    agent = OnchainSecurityAgent()
    server = DefaultServer(agent)
    logger.info("Starting OnchainSecurityAgent Sentient server (DefaultServer /assist) on port 8005...")
    server.run(port=8005)

