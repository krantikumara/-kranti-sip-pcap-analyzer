"""
app.py - Kranti's PCAP Analyzer
Main UI entry point.

SETUP (run once):
    pip install pyshark openai
    pip install "gradio==4.19.2" "gradio-client==0.10.1"
    pip install "jinja2==3.1.2" "huggingface_hub==0.23.4"
    python app.py
"""

# ── Runtime monkey-patch: fixes gradio routes.py passing dict as template name ─
import jinja2.utils as _ju

# Fix 1: LRUCache unhashable key guard
_orig_getitem = _ju.LRUCache.__getitem__
_orig_get     = _ju.LRUCache.get
_orig_setitem = _ju.LRUCache.__setitem__

def _safe_getitem(self, key):
    try: hash(key)
    except TypeError: raise KeyError(key)
    return _orig_getitem(self, key)

def _safe_get(self, key, default=None):
    try: hash(key)
    except TypeError: return default
    return _orig_get(self, key, default)

def _safe_setitem(self, key, value):
    try: hash(key)
    except TypeError: return
    return _orig_setitem(self, key, value)

_ju.LRUCache.__getitem__ = _safe_getitem
_ju.LRUCache.get         = _safe_get
_ju.LRUCache.__setitem__ = _safe_setitem

# Fix 2: Patch starlette Jinja2Templates.get_template to handle dict-as-name bug
# gradio/routes.py calls templates.TemplateResponse(name, context)
# but in some versions the arguments get swapped (context dict passed as name)
import starlette.templating as _st
_orig_get_template = _st.Jinja2Templates.get_template

def _safe_get_template(self, name):
    if isinstance(name, dict):
        # name and context were swapped — extract real template name from context
        # or use a sensible fallback
        name = name.get("request", {}) and "index.html" or "index.html"
    return _orig_get_template(self, name)

_st.Jinja2Templates.get_template = _safe_get_template

# Fix 3: Patch gradio routes directly
try:
    import gradio.routes as _gr
    import inspect as _ins, pathlib as _pl

    _f   = _pl.Path(_ins.getfile(_gr))
    _src = _f.read_text(encoding="utf-8")

    # gradio 4.19.2 routes.py line 322:
    # return templates.TemplateResponse("index.html", {"request": request, ...})
    # Check if it's calling TemplateResponse with positional args swapped
    _old = 'return templates.TemplateResponse(\n            "index.html"'
    if _old not in _src:
        # Try to find the actual call and print it for diagnosis
        _i = _src.find("templates.TemplateResponse(")
        if _i != -1:
            _snippet = _src[_i:_i+200]
            # Fix: ensure name is first arg as string
            import re as _re
            # Pattern: TemplateResponse(context_dict, "index.html") → swap args
            _new_src = _re.sub(
                r'templates\.TemplateResponse\(\s*(\{[^}]+\})\s*,\s*"([^"]+)"\s*\)',
                r'templates.TemplateResponse("\2", \1)',
                _src
            )
            if _new_src != _src:
                for _p in (_f.parent/"__pycache__").glob("routes*.pyc"):
                    _p.unlink(missing_ok=True)
                _f.write_text(_new_src, encoding="utf-8")
                print("[Startup] gradio/routes.py TemplateResponse args fixed")
except Exception as _e:
    print(f"[Startup] gradio routes patch skipped: {_e}")

print("[Startup] All patches applied")
# ── End patch ──────────────────────────────────────────────────────────────────

import asyncio
import os
import traceback

import gradio as gr

from config import APP_TITLE, SERVER_HOST, SERVER_PORT
from pcap_parser import PCAPParser, PYSHARK_AVAILABLE
from agent import build_pcap_context, analyze_all_dialogs, chat as agent_chat
from callflow import generate_call_flow_html


# ─────────────────────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────────────────────

_pcap_result  = None   # ParseResult after analysis
_pcap_context = ""     # Text context fed to chat


def _run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _fmt_size(n):
    if n < 1024:    return f"{n} B"
    if n < 1024**2: return f"{n/1024:.1f} KB"
    return                  f"{n/1024**2:.2f} MB"


def _sev(s):
    return {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢","Info":"🔵"}.get(s,"⚪")


# ─────────────────────────────────────────────────────────────────────────────
# Analysis pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis(pcap_file, batch_size, limit):
    global _pcap_result, _pcap_context

    if pcap_file is None:
        return ("⚠️ Please upload a PCAP/PCAPNG file first.",
                "", "", "", "", "")

    if not PYSHARK_AVAILABLE:
        return ("❌ pyshark not installed. Run: pip install pyshark\n"
                "Also install Wireshark/tshark from wireshark.org",
                "", "", "", "", "")

    # Gradio 4.x gives filepath as string, 3.x gives file object
    path = pcap_file if isinstance(pcap_file, str) else pcap_file.name

    # 1. Parse PCAP
    try:
        parser = PCAPParser(path)
        result = parser.parse()
        _pcap_result = result
    except Exception as e:
        return (f"❌ Parse error: {e}\n{traceback.format_exc()}",
                "", "", "", "", "")

    # 2. Build tabs
    overview = _build_overview(result)
    msgflow  = _build_message_flow(result)
    callflow = generate_call_flow_html(result)

    # 3. AI analysis
    lim = int(limit) if limit and limit > 0 else None
    dialogs_to_analyze = result.dialogs[:lim] if lim else result.dialogs
    try:
        ai_results = analyze_all_dialogs(
            type("R", (), {"dialogs": dialogs_to_analyze,
                           "filename": result.filename})(),
            batch_size=int(batch_size),
        )
        dialog_md = _build_dialog_analysis(ai_results)
    except Exception as e:
        dialog_md = f"⚠️ AI analysis error: {e}\n\nCheck config.py credentials."

    # 4. Store context for chat
    _pcap_context = build_pcap_context(result)

    stats = _build_stats(result)
    status = (f"✅ Done — {result.sip_packets} SIP packets, "
              f"{len(result.dialogs)} dialogs, "
              f"{result.parse_time}s parse time. "
              f"💬 Chat is ready!")

    return status, overview, msgflow, callflow, dialog_md, stats


def _build_overview(r):
    health = "🔴 Issues Found" if any(d.state=="FAILED" for d in r.dialogs) else "🟢 All OK"
    hold_count   = sum(1 for d in r.dialogs if d.hold_events)
    resume_count = sum(1 for d in r.dialogs if d.resume_events)
    return f"""## 📊 Capture Overview

| Field | Value |
|---|---|
| **File** | `{r.filename}` |
| **Size** | {_fmt_size(r.file_size)} |
| **Duration** | {r.duration_sec or 'N/A'} sec |
| **Total Packets** | {r.total_packets:,} |
| **SIP Packets** | {r.sip_packets:,} |
| **RTP Packets** | {r.rtp_packets:,} |
| **Dialogs** | {len(r.dialogs)} total |
| **Failed Dialogs** | {sum(1 for d in r.dialogs if d.state=='FAILED')} |
| **TLS** | {'✅ Yes' if r.has_tls else '❌ No'} |
| **SRTP** | {'✅ Yes' if r.has_srtp else '❌ No'} |
| **Call Hold Events** | {hold_count} dialogs |
| **Call Resume Events** | {resume_count} dialogs |
| **Health** | {health} |

**SIP Methods:** {' · '.join(f'`{m}`' for m in r.methods_seen) or 'None'}

**Error Codes:** {' · '.join(f'`{c}`' for c in r.error_codes) or 'None ✅'}

**Endpoints:** {' · '.join(f'`{e}`' for e in r.endpoints) or 'None'}
"""


def _build_message_flow(r):
    msgs = r.all_messages
    if not msgs:
        return "<p>No SIP messages found.</p>"

    DIRECTION_STYLE = {
        "sendonly": ("🟠", "#e65100"),
        "recvonly": ("🔵", "#1565c0"),
        "inactive": ("🟣", "#6a1b9a"),
        "sendrecv": ("🟢", "#2e7d32"),
    }

    rows = ""
    for m in msgs[:300]:
        # SDP badge
        sdp_badge = ""
        if m.sdp and m.sdp.direction:
            icon, col = DIRECTION_STYLE.get(m.sdp.direction, ("⚪", "#555"))
            sdp_badge = f'<span style="color:{col};font-weight:bold;white-space:nowrap">{icon} a={m.sdp.direction}</span>'
        elif m.has_sdp:
            sdp_badge = '<span style="color:#555">📄 SDP</span>'

        # Message label styling
        if m.is_error:
            msg_style = "color:#c62828;font-weight:bold"
        elif m.sdp and m.sdp.is_hold:
            msg_style = "color:#e65100;font-weight:bold"
        elif m.sdp and m.sdp.is_resume:
            msg_style = "color:#2e7d32;font-weight:bold"
        elif not m.is_request:
            msg_style = "color:#1565c0"
        else:
            msg_style = "font-weight:bold"

        retx = ' <span style="color:#888;font-size:10px">[RETX]</span>' if m.retransmission else ""
        label = f'<span style="{msg_style}">{m.label}</span>{retx}'

        from_str  = m.from_user or m.src_ip
        to_str    = m.to_user   or m.dst_ip
        cid_short = (m.call_id[:20] + "…") if m.call_id and len(m.call_id) > 20 else (m.call_id or "—")
        bg = "#fff8f8" if m.is_error else "#fffff8" if (m.sdp and m.sdp.is_hold) else "#f8fff8" if (m.sdp and m.sdp.is_resume) else "white"

        rows += f"""<tr style="background:{bg};border-bottom:1px solid #e8e8e8">
          <td style="padding:4px 8px;font-family:monospace;font-size:11px;color:#666;white-space:nowrap">{m.packet_number}</td>
          <td style="padding:4px 8px;font-family:monospace;font-size:11px;white-space:nowrap">{m.timestamp}</td>
          <td style="padding:4px 8px;font-family:monospace;font-size:11px;white-space:nowrap">{from_str}</td>
          <td style="padding:4px 8px;font-family:monospace;font-size:11px;white-space:nowrap">{to_str}</td>
          <td style="padding:4px 8px;font-size:12px;white-space:nowrap">{label}</td>
          <td style="padding:4px 8px;font-family:monospace;font-size:10px;color:#555;white-space:nowrap">{cid_short}</td>
          <td style="padding:4px 8px;font-family:monospace;font-size:11px;white-space:nowrap">{m.cseq or ""}</td>
          <td style="padding:4px 8px;font-size:11px;white-space:nowrap">{sdp_badge}</td>
        </tr>"""

    total = len(msgs)
    note = f'<p style="color:#888;font-size:12px;margin:8px 0">Showing {min(300,total)} of {total} messages</p>' if total > 300 else ""

    return f"""<div style="font-family:Segoe UI,Arial,sans-serif">
      <div style="margin-bottom:8px">
        <span style="font-size:15px;font-weight:700;color:#0f2c59">📡 SIP Message Flow</span>
        <span style="font-size:12px;color:#888;margin-left:12px">← scroll horizontally →</span>
        <span style="font-size:12px;margin-left:16px">🟠 sendonly &nbsp; 🟢 sendrecv &nbsp; 🔵 recvonly &nbsp; 🟣 inactive</span>
      </div>
      {note}
      <div style="overflow-x:auto;border:1px solid #e0e0e0;border-radius:8px">
        <table style="border-collapse:collapse;width:100%;min-width:900px">
          <thead>
            <tr style="background:#0f2c59;position:sticky;top:0">
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">Pkt#</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">Time</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">From (SIP URI)</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">To (SIP URI)</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">Message</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">Call-ID</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">CSeq</th>
              <th style="padding:8px 10px;text-align:left;white-space:nowrap;color:#ffffff !important;font-size:13px">SDP</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""


def _build_dialog_analysis(ai_results):
    if not ai_results:
        return "## 🗂️ Dialog Analysis\n\nNo results."
    lines = [f"## 🗂️ Dialog Analysis — {len(ai_results)} dialogs\n",
             "| # | Type | Severity | Category | Summary | Confidence |",
             "|---|---|---|---|---|---|"]
    for i, r in enumerate(ai_results, 1):
        lines.append(
            f"| {i} | {r.get('dialog_type','?')} "
            f"| {_sev(r.get('severity','Low'))} {r.get('severity','Low')} "
            f"| {r.get('category','?')} "
            f"| {r.get('summary','')[:80]} "
            f"| {r.get('confidence','Low')} |"
        )
    lines += ["\n---\n### Detail\n"]
    for r in ai_results:
        cid   = r.get("call_id","?")
        short = (cid[:50]+"...") if len(cid)>50 else cid
        lines += [
            f"\n#### {_sev(r.get('severity','Low'))} {r.get('category','?')} — {r.get('dialog_type','?')}",
            f"**Call-ID:** `{short}`",
            f"> {r.get('summary','')}",
            f"\n**Root Cause:** {r.get('root_cause','')}",
            f"\n**Recommended Action:** {r.get('action','')}",
        ]
        if r.get("rfc_reference"):
            lines.append(f"\n**RFC Reference:** {r['rfc_reference']}")
        lines.append(f"\n**Confidence:** {r.get('confidence','Low')}\n---")
    return "\n".join(lines)


def _build_stats(r):
    total_d   = len(r.dialogs)
    failed_d  = sum(1 for d in r.dialogs if d.state=="FAILED")
    hold_d    = sum(1 for d in r.dialogs if d.hold_events)
    resume_d  = sum(1 for d in r.dialogs if d.resume_events)
    sdp_msgs  = sum(1 for m in r.all_messages if m.has_sdp)
    retx_msgs = sum(1 for m in r.all_messages if m.retransmission)

    return f"""## 📈 Statistics

### Dialog Summary
| Metric | Count |
|---|---|
| Total Dialogs | {total_d} |
| Failed | {failed_d} |
| With Hold | {hold_d} |
| With Resume | {resume_d} |

### Message Summary
| Metric | Count |
|---|---|
| Total SIP Msgs | {r.sip_packets} |
| With SDP | {sdp_msgs} |
| Retransmissions | {retx_msgs} |
| RTP Packets | {r.rtp_packets} |

### Methods Seen
{' · '.join(f'`{m}`' for m in r.methods_seen) or 'None'}

### Error Responses
{' · '.join(f'`{c}`' for c in r.error_codes) or 'None ✅'}

### Endpoints
{chr(10).join(f'- `{e}`' for e in r.endpoints) or 'None'}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Chat handlers
# ─────────────────────────────────────────────────────────────────────────────

def do_chat(message, history):
    global _pcap_context
    if not message.strip():
        return "", history

    if not _pcap_result:
        reply = ("⚠️ No PCAP file analyzed yet. "
                 "Please upload a PCAP file and click **Analyze** first.")
    else:
        reply = agent_chat(message, history, _pcap_context)

    history = history + [(message, reply)]
    return "", history


def clear_chat():
    return []


QUICK_QUESTIONS = [
    "Which calls were put on hold?",
    "What codecs were negotiated?",
    "Were there any authentication failures?",
    "Explain the call setup sequence",
    "Which packets had a=sendonly?",
    "Were there retransmissions?",
    "What is the call flow summary?",
    "Any one-way audio risks?",
]


# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────

def build_ui():
    with gr.Blocks(title=APP_TITLE) as demo:

        # Header
        gr.HTML(f"""
        <div style="background:linear-gradient(135deg,#0f2c59,#0078d4);
                    border-radius:12px;padding:22px 32px;margin-bottom:16px;
                    display:flex;align-items:center;gap:16px">
          <div style="width:6px;height:54px;background:#ffb900;border-radius:3px;flex-shrink:0"></div>
          <div>
            <h1 style="color:#fff;margin:0;font-size:26px;font-weight:700">{APP_TITLE}</h1>
            <p style="color:rgba(255,255,255,.8);margin:5px 0 0;font-size:13px">
              SIP Protocol Analysis · Hold/Resume Detection · Call Flow · AI Chat
            </p>
          </div>
        </div>""")

        with gr.Row():
            # Sidebar
            with gr.Column(scale=1, min_width=270):
                gr.Markdown("### ⚙️ Settings")
                pcap_input = gr.File(
                    label="Upload PCAP / PCAPNG",
                    type="filepath",
                )
                batch_size = gr.Slider(1, 20, value=5, step=1,
                                       label="AI batch size",
                                       info="dialogs per API call")
                limit_dlg  = gr.Number(value=0, label="Max dialogs (0 = all)",
                                       precision=0)
                analyze_btn = gr.Button("🔍 Analyze PCAP", variant="primary", size="lg")

                gr.Markdown("""---
**Analyzes:**
- 📞 SIP call setup & teardown
- 📵 Call Hold `a=sendonly/inactive`
- ▶️ Resume `a=sendrecv`
- 🎵 Codec negotiation
- 🔔 Early Media (183+SDP)
- 🔒 SRTP / DTLS-SRTP
- 🧊 ICE negotiation
- ⚠️ Errors & failures
- 🔄 Retransmissions
- 💬 AI Chat about PCAP
""")

            # Main area
            with gr.Column(scale=4):
                status_out = gr.Markdown(
                    f"Upload a PCAP/PCAPNG file and click **Analyze PCAP**.")

                with gr.Tabs():
                    with gr.Tab("📊 Overview"):
                        overview_out = gr.Markdown()

                    with gr.Tab("📡 Message Flow"):
                        gr.Markdown("All SIP messages. 🟠=sendonly 🟢=sendrecv 🔵=recvonly 🟣=inactive  ↔ *Scroll horizontally to see all columns*")
                        msgflow_out = gr.HTML()

                    with gr.Tab("🎯 Call Flow & SDP"):
                        gr.Markdown(
                            "SVG ladder diagram with SDP annotations. "
                            "Shows exact packet numbers for each hold/resume event."
                        )
                        callflow_out = gr.HTML()

                    with gr.Tab("🗂️ Dialog Analysis (AI)"):
                        gr.Markdown("GPT-4o analysis of every dialog — root cause & recommendations.")
                        dialog_out = gr.Markdown()

                    with gr.Tab("📈 Statistics"):
                        stats_out = gr.Markdown()

                    with gr.Tab("💬 Chat with PCAP"):
                        gr.HTML("""
                        <div style="background:#e3f2fd;border-radius:8px;padding:12px 16px;
                                    margin-bottom:12px;border-left:4px solid #0078d4">
                          <strong style="color:#0d47a1">💬 Ask anything about your PCAP</strong><br>
                          <span style="font-size:13px;color:#1565c0">
                            Run analysis first, then ask about specific packets,
                            call flows, hold events, codecs, errors — anything!
                          </span>
                        </div>""")

                        chatbot = gr.Chatbot(label="PCAP Chat", height=400, show_label=False)

                        with gr.Row():
                            chat_in   = gr.Textbox(
                                placeholder="Ask about this PCAP...",
                                show_label=False, scale=5, lines=1,
                            )
                            send_btn  = gr.Button("Send", variant="primary", scale=1)
                            clear_btn = gr.Button("🗑️ Clear", scale=1)

                        gr.Markdown("**Quick questions:**")
                        with gr.Row():
                            for q in QUICK_QUESTIONS[:4]:
                                gr.Button(q, size="sm").click(
                                    fn=lambda msg=q: msg, outputs=chat_in)
                        with gr.Row():
                            for q in QUICK_QUESTIONS[4:]:
                                gr.Button(q, size="sm").click(
                                    fn=lambda msg=q: msg, outputs=chat_in)

        # Wire up analysis
        analyze_btn.click(
            fn=run_analysis,
            inputs=[pcap_input, batch_size, limit_dlg],
            outputs=[status_out, overview_out, msgflow_out,
                     callflow_out, dialog_out, stats_out],
        )

        # Wire up chat
        send_btn.click(fn=do_chat, inputs=[chat_in, chatbot], outputs=[chat_in, chatbot])
        chat_in.submit(fn=do_chat, inputs=[chat_in, chatbot], outputs=[chat_in, chatbot])
        clear_btn.click(fn=clear_chat, outputs=chatbot)

    return demo


if __name__ == "__main__":
    print("=" * 60)
    print(f"  {APP_TITLE}")
    print("=" * 60)
    print(f"  gradio version: {gr.__version__}")
    if not PYSHARK_AVAILABLE:
        print("  ⚠️  pyshark not installed — run: pip install pyshark")
    print("=" * 60)

    build_ui().queue().launch(
        server_name = SERVER_HOST,
        server_port = SERVER_PORT,
        share       = True,
        inbrowser   = True,
        show_error  = True,
    )
