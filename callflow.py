"""
callflow.py - SIP Call Flow Diagram Generator
Produces an SVG ladder diagram of SIP messages.
"""

from typing import List, Dict
from pcap_parser import SIPMessage, SDPData


def _esc(t: str) -> str:
    return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")


def generate_svg(messages: List[SIPMessage], title: str = "SIP Call Flow",
                 max_msgs: int = 80) -> str:
    if not messages:
        return "<svg><text x='10' y='20' font-family='Arial' font-size='14'>No SIP messages</text></svg>"

    msgs = messages[:max_msgs]

    # Collect unique endpoints in order
    seen: Dict[str, int] = {}
    for m in msgs:
        if m.src_ip and m.src_ip not in seen: seen[m.src_ip] = len(seen)
        if m.dst_ip and m.dst_ip not in seen: seen[m.dst_ip] = len(seen)
    endpoints = list(seen.keys())
    if len(endpoints) < 2:
        endpoints = (endpoints + ["unknown"])[:2]

    # Layout constants
    ML   = 70    # left margin
    MT   = 80    # top margin
    EPS  = 300   # endpoint spacing
    RH   = 38    # row height
    EBW  = 140   # endpoint box width
    EBH  = 28

    n_ep      = len(endpoints)
    svg_w     = ML*2 + (n_ep-1)*EPS + EBW
    svg_h     = MT + (len(msgs)+3)*RH + 60

    ep_x = {ep: ML + EBW//2 + i*EPS for i, ep in enumerate(endpoints)}

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_w}" height="{svg_h}" '
        f'style="font-family:Segoe UI,Arial,sans-serif;background:#fff">',

        # Arrow markers
        '''<defs>
  <marker id="a0" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#0078d4"/></marker>
  <marker id="a1" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#d32f2f"/></marker>
  <marker id="a2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#e65100"/></marker>
  <marker id="a3" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#388e3c"/></marker>
</defs>''',

        # Title
        f'<text x="{svg_w//2}" y="22" text-anchor="middle" font-size="15" font-weight="bold" fill="#0f2c59">{_esc(title)}</text>',
    ]

    if len(messages) > max_msgs:
        out.append(f'<text x="{svg_w//2}" y="40" text-anchor="middle" font-size="10" fill="#888">(first {max_msgs} of {len(messages)} shown)</text>')

    # Endpoint boxes and lifelines
    ll_bottom = MT + (len(msgs)+2)*RH
    for ep, x in ep_x.items():
        bx = x - EBW//2
        out.append(f'<rect x="{bx}" y="{MT-EBH-4}" width="{EBW}" height="{EBH}" rx="5" fill="#0f2c59"/>')
        out.append(f'<text x="{x}" y="{MT-EBH+16}" text-anchor="middle" font-size="11" font-weight="bold" fill="#fff">{_esc(ep)}</text>')
        out.append(f'<line x1="{x}" y1="{MT-4}" x2="{x}" y2="{ll_bottom}" stroke="#c5d5e8" stroke-width="1.5" stroke-dasharray="5,4"/>')

    # Messages
    for idx, m in enumerate(msgs):
        y  = MT + idx*RH + RH//2
        sx = ep_x.get(m.src_ip, ep_x[endpoints[0]])
        dx = ep_x.get(m.dst_ip, ep_x[endpoints[-1]])
        if sx == dx:
            dx = ep_x[endpoints[1]] if m.src_ip == endpoints[0] else ep_x[endpoints[0]]

        going_right = dx > sx

        # Color selection
        if m.is_error:
            clr, mkr = "#d32f2f", "a1"
        elif m.sdp and m.sdp.is_hold:
            clr, mkr = "#e65100", "a2"
        elif m.sdp and m.sdp.is_resume:
            clr, mkr = "#388e3c", "a3"
        else:
            clr, mkr = "#0078d4", "a0"

        gap = 10
        x1  = sx + (gap if going_right else -gap)
        x2  = dx - (gap if going_right else -gap)
        dash = 'stroke-dasharray="5,3"' if m.retransmission else ""
        out.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{clr}" stroke-width="1.8" {dash} marker-end="url(#{mkr})"/>')

        # Label
        label = m.label
        if m.sdp and m.sdp.direction:
            label += f" [a={m.sdp.direction}]"
        elif m.has_sdp:
            label += " [SDP]"

        mid_x = (sx + dx) // 2
        lw    = max(len(label)*7 + 16, 70)

        bg = "#fff3e0" if m.sdp and m.sdp.is_hold else \
             "#e8f5e9" if m.sdp and m.sdp.is_resume else \
             "#fce4ec" if m.is_error else "#f0f6ff"

        out.append(f'<rect x="{mid_x-lw//2}" y="{y-17}" width="{lw}" height="15" rx="7" fill="{bg}" stroke="{clr}" stroke-width="0.8"/>')
        out.append(f'<text x="{mid_x}" y="{y-6}" text-anchor="middle" font-size="10" font-weight="bold" fill="{clr}">{_esc(label)}</text>')

        # Timestamp
        out.append(f'<text x="2" y="{y+4}" font-size="8" fill="#aaa" font-family="Consolas,monospace">{_esc(m.timestamp)}</text>')

        # CSeq
        if m.cseq:
            out.append(f'<text x="{mid_x+lw//2+4}" y="{y-5}" font-size="8" fill="#999" font-family="Consolas,monospace">{_esc(m.cseq)}</text>')

    # Legend
    leg_y = ll_bottom + 16
    legend = [("#0078d4","SIP Message"),("#d32f2f","Error 4xx/5xx"),
              ("#e65100","Hold (a=sendonly)"),("#388e3c","Resume (a=sendrecv)")]
    lx = ML
    for lc, lt in legend:
        out.append(f'<rect x="{lx}" y="{leg_y}" width="12" height="10" rx="2" fill="{lc}"/>')
        out.append(f'<text x="{lx+15}" y="{leg_y+9}" font-size="10" fill="#555">{_esc(lt)}</text>')
        lx += 170

    out.append("</svg>")
    return "\n".join(out)


def generate_call_flow_html(result) -> str:
    """Build the full Call Flow tab HTML content."""
    all_msgs    = result.all_messages
    all_dialogs = result.dialogs

    svg = generate_svg(all_msgs, title=f"SIP Call Flow — {result.filename}", max_msgs=80)

    # SDP events table
    sdp_events = []
    for m in all_msgs:
        if m.has_sdp and m.sdp:
            event_type = ""
            if m.sdp.is_hold:
                event_type = f"HOLD ({m.sdp.hold_type})"
            elif m.sdp.is_resume:
                event_type = "RESUME"
            elif m.sdp.direction:
                event_type = f"SDP ({m.sdp.direction})"
            else:
                event_type = "SDP"
            sdp_events.append((m, event_type))

    ev_rows = ""
    for m, etype in sdp_events:
        s = m.sdp
        color = "#e65100" if "HOLD" in etype else "#388e3c" if "RESUME" in etype else "#0078d4"
        codecs = ", ".join(s.codecs[:3]) if s.codecs else "—"
        direction = f'<code style="color:{color};font-weight:bold">a={s.direction}</code>' if s.direction else "—"
        extras = " ".join([
            "🔒 SRTP" if s.has_srtp else "",
            "🔒 DTLS" if s.has_dtls else "",
            "🧊 ICE"  if s.has_ice  else "",
            "📹 Video" if s.has_video else "",
            "📠 T.38" if s.has_fax   else "",
        ]).strip() or "—"
        hold_ip = f"c={s.connection_ip}" if s.connection_ip else ""

        bg = "#fff3e0" if "HOLD" in etype else "#e8f5e9" if "RESUME" in etype else "#f8f9fa"
        ev_rows += f"""
        <tr style="background:{bg}">
          <td style="padding:6px 8px;font-family:monospace;font-size:11px">{m.timestamp}</td>
          <td style="padding:6px 8px;font-size:11px">
            Pkt #{m.packet_number}<br><strong>{m.label}</strong>
            <br><span style="color:#888;font-size:10px">{m.cseq or ''}</span>
          </td>
          <td style="padding:6px 8px;font-size:12px;color:{color}"><strong>{etype}</strong></td>
          <td style="padding:6px 8px">{direction}</td>
          <td style="padding:6px 8px;font-size:11px">{codecs}</td>
          <td style="padding:6px 8px;font-size:11px">{hold_ip}</td>
          <td style="padding:6px 8px;font-size:11px">{extras}</td>
        </tr>"""

    # Per-dialog SDP breakdown
    dialog_html = ""
    for d in all_dialogs:
        sdp_msgs = d.sdp_messages
        if not sdp_msgs:
            continue
        sc = {"COMPLETED":"#388e3c","FAILED":"#d32f2f","ONGOING":"#f57c00","ABANDONED":"#607d8b"}.get(d.state,"#555")
        cid = (d.call_id[:55]+"...") if len(d.call_id)>55 else d.call_id
        rows = ""
        for m in sdp_msgs:
            ml  = m.method if m.is_request else f"{m.status_code} {m.status_phrase or ''}".strip()
            dv  = "—"
            cv  = "—"
            hv  = "—"
            if m.sdp:
                if m.sdp.direction:
                    dc = {"sendonly":"#e65100","recvonly":"#1565c0","inactive":"#7b1fa2","sendrecv":"#388e3c"}.get(m.sdp.direction,"#333")
                    dv = f'<code style="color:{dc};font-weight:bold">a={m.sdp.direction}</code>'
                if m.sdp.codecs:
                    cv = ", ".join(m.sdp.codecs[:3])
                if m.sdp.is_hold:
                    hv = f"HOLD ({m.sdp.hold_type})"
                elif m.sdp.is_resume:
                    hv = "RESUME"
            rows += f"""<tr style="border-bottom:1px solid #f0f0f0">
              <td style="padding:4px 8px;font-family:monospace;font-size:11px;color:#888">{m.timestamp}</td>
              <td style="padding:4px 8px;font-size:11px">#{m.packet_number}</td>
              <td style="padding:4px 8px"><strong>{ml}</strong></td>
              <td style="padding:4px 8px">{dv}</td>
              <td style="padding:4px 8px;font-size:11px">{cv}</td>
              <td style="padding:4px 8px;font-size:11px">{hv}</td>
              <td style="padding:4px 8px;font-family:monospace;font-size:10px;color:#999">{m.cseq or ''}</td>
            </tr>"""

        dialog_html += f"""
        <div style="border:1px solid #e0e0e0;border-radius:8px;margin:8px 0;overflow:hidden">
          <div style="background:#f8fafd;padding:8px 14px;border-bottom:1px solid #e0e0e0;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
            <strong style="color:#0f2c59;font-size:12px">{d.dialog_type}</strong>
            <span style="font-family:monospace;font-size:11px;color:#555;flex:1">{cid}</span>
            <span style="color:{sc};font-weight:600;font-size:11px">{d.state}</span>
            <span style="color:#888;font-size:11px">{len(d.messages)} msgs · {len(sdp_msgs)} SDP</span>
          </div>
          <div style="overflow-x:auto">
          <table style="width:100%;border-collapse:collapse;font-size:12px">
            <thead><tr style="background:#f0f4f8">
              <th style="padding:4px 8px;text-align:left;font-size:11px">Time</th>
              <th style="padding:4px 8px;text-align:left;font-size:11px">Pkt#</th>
              <th style="padding:4px 8px;text-align:left;font-size:11px">Method</th>
              <th style="padding:4px 8px;text-align:left;font-size:11px">Direction</th>
              <th style="padding:4px 8px;text-align:left;font-size:11px">Codecs</th>
              <th style="padding:4px 8px;text-align:left;font-size:11px">Hold/Resume</th>
              <th style="padding:4px 8px;text-align:left;font-size:11px">CSeq</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table></div>
        </div>"""

    return f"""
    <div style="font-family:Segoe UI,Arial,sans-serif;padding:8px">
      <div style="overflow-x:auto;border:1px solid #e0e0e0;border-radius:8px;background:#fafbfc;padding:12px;margin-bottom:16px">
        {svg}
      </div>

      <h3 style="margin:16px 0 8px;color:#0f2c59">
        SDP Events &amp; Hold/Resume Analysis
        <span style="font-size:12px;color:#888;font-weight:normal">({len(sdp_events)} SDP messages)</span>
      </h3>
      <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:13px;border:1px solid #e0e0e0">
        <thead><tr style="background:#0f2c59;color:white">
          <th style="padding:8px;text-align:left">Time</th>
          <th style="padding:8px;text-align:left">SIP Message</th>
          <th style="padding:8px;text-align:left">Event</th>
          <th style="padding:8px;text-align:left">Direction</th>
          <th style="padding:8px;text-align:left">Codecs</th>
          <th style="padding:8px;text-align:left">Connection</th>
          <th style="padding:8px;text-align:left">Security</th>
        </tr></thead>
        <tbody>{ev_rows or '<tr><td colspan="7" style="padding:16px;color:#888;text-align:center">No SDP messages found.</td></tr>'}</tbody>
      </table></div>

      <h3 style="margin:20px 0 8px;color:#0f2c59">
        Dialog SDP Breakdown ({len(all_dialogs)} dialogs)
      </h3>
      {dialog_html or '<p style="color:#888">No dialogs with SDP found.</p>'}
    </div>"""
