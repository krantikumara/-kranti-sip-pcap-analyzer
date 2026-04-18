"""
agent.py - AI Analysis Agent using Azure OpenAI
Analyzes SIP dialogs, answers chat questions about the PCAP.
"""

from openai import AzureOpenAI
from config import (
    AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT, AZURE_OPENAI_API_VERSION,
    credentials_ok,
)


def _get_client():
    if not credentials_ok():
        raise ConnectionError(
            "Azure OpenAI credentials not configured.\n"
            "Please set these in your .env file:\n"
            "  AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com\n"
            "  AZURE_OPENAI_API_KEY=your-api-key\n"
            "  AZURE_OPENAI_DEPLOYMENT=gpt-4o"
        )
    return AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
    )


# ─────────────────────────────────────────────────────────────────────────────
# PCAP context builder
# ─────────────────────────────────────────────────────────────────────────────

def build_pcap_context(result) -> str:
    if result is None:
        return "No PCAP file has been analyzed yet."

    lines = [
        f"=== PCAP FILE: {result.filename} ===",
        f"Duration: {result.duration_sec}s | Packets: {result.total_packets} "
        f"(SIP: {result.sip_packets}, RTP: {result.rtp_packets})",
        f"Endpoints: {', '.join(result.endpoints)}",
        f"SIP Methods: {', '.join(result.methods_seen)}",
        f"Error Codes: {', '.join(str(c) for c in result.error_codes) or 'None'}",
        f"TLS: {'Yes' if result.has_tls else 'No'} | SRTP: {'Yes' if result.has_srtp else 'No'}",
        "",
        "=== SIP MESSAGE FLOW ===",
    ]

    for m in result.all_messages[:200]:
        sdp_tag = ""
        if m.sdp and m.sdp.direction:
            sdp_tag = f" [SDP:a={m.sdp.direction}]"
        elif m.has_sdp:
            sdp_tag = " [SDP]"
        retx = " [RETX]" if m.retransmission else ""
        from_uri = m.from_user or f"{m.src_ip}:{m.src_port}"
        to_uri   = m.to_user   or f"{m.dst_ip}:{m.dst_port}"
        lines.append(
            f"Pkt#{m.packet_number} {m.timestamp} "
            f"From:{from_uri} -> To:{to_uri} | "
            f"{m.label}{sdp_tag}{retx} | CSeq:{m.cseq or ''} | CallID:{(m.call_id or '')[:30]}"
        )

    lines += ["", "=== DIALOGS ==="]
    for d in result.dialogs:
        hold_pkts   = [f"Pkt#{m.packet_number}({m.label},a={m.sdp.direction})" for m in d.hold_events]
        resume_pkts = [f"Pkt#{m.packet_number}({m.label},a={m.sdp.direction})" for m in d.resume_events]
        sdp_summary = []
        for m in d.sdp_messages:
            if m.sdp:
                sdp_summary.append(
                    f"Pkt#{m.packet_number}:{m.label}:"
                    f"a={m.sdp.direction or '?'},"
                    f"codecs={','.join(m.sdp.codecs[:2]) or '?'}"
                )
        lines.append(
            f"[{d.dialog_type}] {d.state} | CallID:{d.call_id[:40]} | "
            f"Msgs:{len(d.messages)} | Final:{d.final_response or 'none'}"
        )
        if hold_pkts:   lines.append(f"  HOLD: {', '.join(hold_pkts)}")
        if resume_pkts: lines.append(f"  RESUME: {', '.join(resume_pkts)}")
        if sdp_summary: lines.append(f"  SDP: {' | '.join(sdp_summary[:5])}")

    return "\n".join(lines)


SYSTEM_PROMPT = """You are an expert SIP protocol analyst embedded in Kranti's PCAP Analyzer.
You have deep knowledge of:
- RFC 3261 (SIP), RFC 4566 (SDP), RFC 3264 (Offer/Answer Model)
- Call Hold (a=sendonly RFC3264, c=0.0.0.0 RFC2543)
- Call Resume (a=sendrecv), Early Media (183+SDP)
- Codec negotiation, SRTP/DTLS, ICE, SBC troubleshooting

When answering questions about a PCAP:
- Reference specific packet numbers, timestamps, Call-IDs
- Explain SDP attributes clearly (a=sendonly = calling party holds)
- Identify issues with root cause and recommended action
- Be technically precise but also clear to non-experts
"""


# ─────────────────────────────────────────────────────────────────────────────
# Dialog analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_dialog(dialog, result) -> dict:
    msg_lines = []
    for m in dialog.messages:
        sdp_info = ""
        if m.sdp:
            sdp_info = f" [a={m.sdp.direction or '?'}, codecs={','.join(m.sdp.codecs[:2]) or '?'}]"
        elif m.has_sdp:
            sdp_info = " [SDP]"
        retx = " RETX" if m.retransmission else ""
        msg_lines.append(
            f"  {m.timestamp} Pkt#{m.packet_number} "
            f"{m.src_ip}->{m.dst_ip} {m.label}{sdp_info}{retx} CSeq:{m.cseq or ''}"
        )

    prompt = f"""Analyze this SIP dialog from PCAP file '{result.filename}':

Dialog Type: {dialog.dialog_type}
Call-ID: {dialog.call_id}
State: {dialog.state}
Final Response: {dialog.final_response or 'none'}
Messages ({len(dialog.messages)} total):
{chr(10).join(msg_lines)}

Provide analysis as JSON with these exact keys:
{{
  "category": "Normal Call Flow|Call Setup Failure|Call Hold/Resume|Authentication Failure|Network Issue|Codec Negotiation|Registration|Other",
  "severity": "Critical|High|Medium|Low|Info",
  "summary": "one sentence summary",
  "root_cause": "technical root cause explanation",
  "action": "recommended action",
  "confidence": "High|Medium|Low",
  "rfc_reference": "relevant RFC if any"
}}

Return ONLY the JSON object, no markdown, no extra text."""

    try:
        client = _get_client()
        resp = client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            max_tokens=500,
            temperature=0.1,
        )
        import json, re
        text = resp.choices[0].message.content or "{}"
        text = re.sub(r"```json|```", "", text).strip()
        return json.loads(text)
    except Exception as e:
        return {
            "category": "Manual Review Required", "severity": "Low",
            "summary": f"AI analysis unavailable: {e}",
            "root_cause": "", "action": "Review manually",
            "confidence": "Low", "rfc_reference": "",
        }


def analyze_all_dialogs(result, batch_size=5) -> list:
    results = []
    for i in range(0, len(result.dialogs), batch_size):
        for d in result.dialogs[i:i+batch_size]:
            r = analyze_dialog(d, result)
            r["call_id"]     = d.call_id
            r["dialog_type"] = d.dialog_type
            results.append(r)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Chat
# ─────────────────────────────────────────────────────────────────────────────

def chat(message: str, history: list, pcap_context: str) -> str:
    if not message.strip():
        return ""

    # Show credential status if not configured
    if not credentials_ok():
        return (
            "⚠️ **Azure OpenAI not configured.**\n\n"
            "Add these to your `.env` file in the project folder:\n"
            "```\n"
            "AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com\n"
            "AZURE_OPENAI_API_KEY=your-api-key-here\n"
            "AZURE_OPENAI_DEPLOYMENT=gpt-4o\n"
            "AZURE_OPENAI_API_VERSION=2024-12-01-preview\n"
            "```\n"
            f"Current values loaded:\n"
            f"- ENDPOINT: `{AZURE_OPENAI_ENDPOINT or '(empty)'}`\n"
            f"- API_KEY: `{'(set)' if AZURE_OPENAI_API_KEY else '(empty)'}`\n"
            f"- DEPLOYMENT: `{AZURE_OPENAI_DEPLOYMENT}`\n"
        )

    system = SYSTEM_PROMPT + "\n\n" + pcap_context
    api_msgs = [{"role": "system", "content": system}]

    for item in history[-20:]:
        if isinstance(item, dict):
            if item.get("role") in ("user", "assistant"):
                api_msgs.append({"role": item["role"], "content": item["content"]})
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            if item[0]: api_msgs.append({"role": "user",      "content": str(item[0])})
            if item[1]: api_msgs.append({"role": "assistant",  "content": str(item[1])})

    api_msgs.append({"role": "user", "content": message})

    try:
        client = _get_client()
        resp = client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT,
            messages=api_msgs,
            max_tokens=1500,
            temperature=0.2,
        )
        return resp.choices[0].message.content or "No response."
    except Exception as e:
        err = str(e)
        if "401" in err or "unauthorized" in err.lower() or "invalid" in err.lower():
            return f"❌ **Authentication failed.** Check your `AZURE_OPENAI_API_KEY` in `.env`.\n\nDetail: `{err}`"
        elif "404" in err or "not found" in err.lower():
            return f"❌ **Deployment not found.** Check `AZURE_OPENAI_DEPLOYMENT` in `.env` (currently: `{AZURE_OPENAI_DEPLOYMENT}`).\n\nDetail: `{err}`"
        elif "connection" in err.lower() or "timeout" in err.lower():
            return f"❌ **Connection failed.** Check `AZURE_OPENAI_ENDPOINT` in `.env` (currently: `{AZURE_OPENAI_ENDPOINT}`).\n\nDetail: `{err}`"
        else:
            return f"❌ **API error:** `{err}`"
