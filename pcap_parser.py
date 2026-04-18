"""
pcap_parser.py - SIP PCAP Parser
Extracts SIP messages, dialogs, SDP data using robust multi-strategy field lookup.
"""

import os
import re
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SDPData:
    direction: Optional[str] = None
    codecs: List[str] = field(default_factory=list)
    connection_ip: Optional[str] = None
    media_port: Optional[str] = None
    has_video: bool = False
    has_fax: bool = False
    has_srtp: bool = False
    has_dtls: bool = False
    has_ice: bool = False
    raw_attrs: List[str] = field(default_factory=list)

    @property
    def is_hold(self):
        return self.direction in ("sendonly", "inactive") or self.connection_ip in ("0.0.0.0", "::")

    @property
    def is_resume(self):
        return self.direction == "sendrecv"

    @property
    def hold_type(self):
        if self.connection_ip in ("0.0.0.0", "::"):
            return "RFC2543 (c=0.0.0.0)"
        if self.direction in ("sendonly", "inactive"):
            return f"RFC3264 (a={self.direction})"
        return None

    def summary(self):
        parts = []
        if self.direction:   parts.append(f"a={self.direction}")
        if self.codecs:      parts.append(f"codecs: {', '.join(self.codecs[:3])}")
        if self.connection_ip: parts.append(f"c={self.connection_ip}")
        return " | ".join(parts) if parts else "no SDP attributes"


@dataclass
class SIPMessage:
    packet_number: int
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    transport: str
    method: Optional[str]
    status_code: Optional[int]
    status_phrase: Optional[str]
    call_id: Optional[str]
    from_header: Optional[str]
    to_header: Optional[str]
    cseq: Optional[str]
    via: Optional[str]
    contact: Optional[str]
    content_type: Optional[str]
    is_request: bool
    has_sdp: bool
    retransmission: bool
    sdp: Optional[SDPData] = None

    @property
    def label(self):
        if self.is_request:
            return self.method or "UNKNOWN"
        return f"{self.status_code} {self.status_phrase or ''}".strip()

    @property
    def is_error(self):
        return not self.is_request and self.status_code and self.status_code >= 400

    @property
    def from_user(self):
        """Return full SIP URI from From header e.g. sip:1005@192.168.1.1"""
        if not self.from_header:
            return self.src_ip
        # Extract full SIP URI inside angle brackets first
        m = re.search(r'<(sips?:[^>]+)>', self.from_header)
        if m: return m.group(1)
        # Bare SIP URI without brackets
        m = re.search(r'(sips?:[^;\s,>]+)', self.from_header)
        if m: return m.group(1)
        # Display name fallback
        m = re.search(r'"([^"]+)"', self.from_header)
        if m: return m.group(1)
        return self.from_header.split(";")[0].strip()[:60]

    @property
    def to_user(self):
        """Return full SIP URI from To header e.g. sip:1006@192.168.1.1"""
        if not self.to_header:
            return self.dst_ip
        # Extract full SIP URI inside angle brackets first
        m = re.search(r'<(sips?:[^>]+)>', self.to_header)
        if m: return m.group(1)
        # Bare SIP URI without brackets
        m = re.search(r'(sips?:[^;\s,>]+)', self.to_header)
        if m: return m.group(1)
        # Display name fallback
        m = re.search(r'"([^"]+)"', self.to_header)
        if m: return m.group(1)
        return self.to_header.split(";")[0].strip()[:60]


@dataclass
class SIPDialog:
    call_id: str
    dialog_type: str
    state: str
    start_time: str
    end_time: Optional[str]
    messages: List[SIPMessage] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    final_response: Optional[int] = None

    @property
    def sdp_messages(self):
        return [m for m in self.messages if m.has_sdp]

    @property
    def hold_events(self):
        return [m for m in self.messages if m.sdp and m.sdp.is_hold]

    @property
    def resume_events(self):
        return [m for m in self.messages if m.sdp and m.sdp.is_resume]

    @property
    def from_user(self):
        for m in self.messages:
            if m.from_user:
                return m.from_user
        return ""

    @property
    def to_user(self):
        for m in self.messages:
            if m.to_user:
                return m.to_user
        return ""


@dataclass
class ParseResult:
    filename: str
    file_size: int
    duration_sec: Optional[float]
    total_packets: int
    sip_packets: int
    rtp_packets: int
    dialogs: List[SIPDialog]
    all_messages: List[SIPMessage]
    endpoints: List[str]
    methods_seen: List[str]
    error_codes: List[int]
    has_tls: bool
    has_srtp: bool
    parse_time: float


# ─────────────────────────────────────────────────────────────────────────────
# Robust field lookup — tshark field names vary by version
# ─────────────────────────────────────────────────────────────────────────────

def _get_field(af: dict, *keys) -> str:
    """
    Try multiple field name variants across tshark versions.
    Searches both flat fields and nested _tree dicts.
    """
    for key in keys:
        # Direct lookup
        val = af.get(key)
        if val and str(val).strip():
            return str(val).strip()

    # Search all nested trees
    for tree_key, tree_val in af.items():
        if not isinstance(tree_val, dict):
            continue
        for key in keys:
            val = tree_val.get(key)
            if val and str(val).strip():
                return str(val).strip()

    return ""


def _get_call_id(af: dict, sip_layer) -> str:
    """Extract Call-ID using multiple strategies."""
    # Strategy 1: standard field names in all_fields
    val = _get_field(af,
        "sip.Call-ID",
        "sip.call-id",
        "sip.call_id",
        "sip.Call-Id",
        "sip.call_id_generated",
    )
    if val: return val

    # Strategy 2: look in header tree
    hdr = af.get("sip.msg_hdr_tree", {})
    if isinstance(hdr, dict):
        for k, v in hdr.items():
            if "call" in k.lower() and "id" in k.lower() and v:
                return str(v).strip()

    # Strategy 3: direct attribute on sip layer
    for attr in ("callid", "call_id", "Call_ID", "Call_Id"):
        try:
            val = getattr(sip_layer, attr, None)
            if val: return str(val).strip()
        except: pass

    # Strategy 4: scan all_fields for anything with "call" in key
    for k, v in af.items():
        if "call" in k.lower() and "id" in k.lower() and v and isinstance(v, str):
            return v.strip()

    return ""


def _get_from_to(af: dict, sip_layer) -> tuple:
    """Extract From and To headers. Returns (from_str, to_str)."""
    # Strategy 1: standard names
    from_hdr = _get_field(af,
        "sip.From",
        "sip.from",
        "sip.from_user",
        "sip.from.addr",
    )
    to_hdr = _get_field(af,
        "sip.To",
        "sip.to",
        "sip.to_user",
        "sip.to.addr",
    )

    # Strategy 2: from_tree / to_tree
    from_tree = af.get("sip.From_tree", af.get("sip.from_tree", {}))
    if isinstance(from_tree, dict) and not from_hdr:
        from_hdr = (from_tree.get("sip.from.addr") or
                    from_tree.get("sip.addr") or
                    from_tree.get("sip.From") or "")

    to_tree = af.get("sip.To_tree", af.get("sip.to_tree", {}))
    if isinstance(to_tree, dict) and not to_hdr:
        to_hdr = (to_tree.get("sip.to.addr") or
                  to_tree.get("sip.addr") or
                  to_tree.get("sip.To") or "")

    # Strategy 3: msg_hdr_tree
    hdr = af.get("sip.msg_hdr_tree", {})
    if isinstance(hdr, dict):
        if not from_hdr:
            from_hdr = str(hdr.get("sip.From") or hdr.get("sip.from") or "")
        if not to_hdr:
            to_hdr   = str(hdr.get("sip.To")   or hdr.get("sip.to")   or "")

    # Strategy 4: direct sip layer attributes
    if not from_hdr:
        try: from_hdr = str(getattr(sip_layer, "from_header", "") or "")
        except: pass
    if not to_hdr:
        try: to_hdr   = str(getattr(sip_layer, "to_header", "")   or "")
        except: pass

    # Strategy 5: scan for From/To in all header-like fields
    for k, v in af.items():
        if not isinstance(v, str): continue
        kl = k.lower()
        if "from" in kl and not from_hdr and ("sip:" in v or "@" in v or "<" in v):
            from_hdr = v
        if k.lower().endswith(".to") and not to_hdr and ("sip:" in v or "@" in v or "<" in v):
            to_hdr = v

    return from_hdr.strip(), to_hdr.strip()


def _get_cseq(af: dict) -> str:
    return _get_field(af, "sip.CSeq", "sip.cseq", "sip.CSeq_value", "sip.cseq.seq_no")


def _get_via(af: dict) -> str:
    return _get_field(af, "sip.Via", "sip.via", "sip.Via_value")


def _get_contact(af: dict) -> str:
    return _get_field(af, "sip.Contact", "sip.contact", "sip.Contact_value")


def _get_content_type(af: dict) -> str:
    return _get_field(af,
        "sip.Content-Type", "sip.content_type",
        "sip.Content-type", "sip.content-type",
    )


# ─────────────────────────────────────────────────────────────────────────────
# SDP extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_sdp(body_tree: dict) -> Optional[SDPData]:
    if not isinstance(body_tree, dict):
        return None
    sdp_dict = body_tree.get("sdp")
    if not isinstance(sdp_dict, dict):
        return None

    data = SDPData()

    # Direction attributes
    attrs = sdp_dict.get("sdp.media_attr", [])
    if isinstance(attrs, str): attrs = [attrs]
    data.raw_attrs = [a for a in attrs if isinstance(a, str)]

    for attr in data.raw_attrs:
        al = attr.strip().lower()
        if al in ("sendrecv", "sendonly", "recvonly", "inactive"):
            data.direction = al
        elif al.startswith("crypto:"):   data.has_srtp = True
        elif al.startswith("fingerprint:"): data.has_dtls = True
        elif al.startswith("candidate:") or al.startswith("ice-ufrag"): data.has_ice = True

    # Codecs
    media_tree = sdp_dict.get("sdp.media_tree", {})
    if isinstance(media_tree, dict):
        fmts = media_tree.get("sdp.media.format", [])
        if isinstance(fmts, str): fmts = [fmts]
        for f in fmts:
            if isinstance(f, str) and "telephone" not in f.lower():
                clean = f.replace("ITU-T ", "").strip()
                if clean and clean not in data.codecs:
                    data.codecs.append(clean)
        mtype = media_tree.get("sdp.media.media", "")
        if mtype == "video": data.has_video = True
        elif mtype == "image": data.has_fax = True
        data.media_port = str(media_tree.get("sdp.media.port", "") or "")

    # Connection IP
    conn = sdp_dict.get("sdp.connection_info_tree", {})
    if isinstance(conn, dict):
        ip = conn.get("sdp.connection_info.address", "")
        if ip:
            data.connection_ip = str(ip)
            if ip in ("0.0.0.0", "::"):
                data.direction = data.direction or "sendonly"

    return data


# ─────────────────────────────────────────────────────────────────────────────
# Main parser
# ─────────────────────────────────────────────────────────────────────────────

class PCAPParser:
    def __init__(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"File not found: {pcap_path}")
        if not PYSHARK_AVAILABLE:
            raise ImportError("pyshark not installed. Run: pip install pyshark")
        self.pcap_path = pcap_path
        self.filename  = Path(pcap_path).name

    def parse(self) -> ParseResult:
        import time
        t0 = time.time()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            raw = ex.submit(self._parse_thread).result()
        msgs, total, sip_count, rtp_count, has_tls, has_srtp, ts_start, ts_end = raw
        dialogs   = self._build_dialogs(msgs)
        endpoints = sorted({m.src_ip for m in msgs if m.src_ip} |
                           {m.dst_ip for m in msgs if m.dst_ip})
        methods   = sorted({m.method for m in msgs if m.method})
        errors    = sorted({m.status_code for m in msgs
                            if m.status_code and m.status_code >= 400})
        duration  = (ts_end - ts_start) if ts_start and ts_end else None
        return ParseResult(
            filename=self.filename, file_size=os.path.getsize(self.pcap_path),
            duration_sec=round(duration, 2) if duration else None,
            total_packets=total, sip_packets=sip_count, rtp_packets=rtp_count,
            dialogs=dialogs, all_messages=msgs, endpoints=endpoints,
            methods_seen=methods, error_codes=errors,
            has_tls=has_tls, has_srtp=has_srtp,
            parse_time=round(time.time() - t0, 2),
        )

    def _parse_thread(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        msgs = []
        total = sip_count = rtp_count = 0
        has_tls = has_srtp = False
        ts_start = ts_end = None
        try:
            cap = pyshark.FileCapture(
                self.pcap_path,
                display_filter="sip or rtp",
                keep_packets=True,
                use_json=True,
                include_raw=False,
            )
            for pkt in cap:
                total += 1
                try:    ts = float(pkt.sniff_timestamp)
                except: ts = 0.0
                if ts_start is None: ts_start = ts
                ts_end = ts
                if hasattr(pkt, "sip"):
                    sip_count += 1
                    msg = self._extract_message(pkt)
                    if msg: msgs.append(msg)
                if hasattr(pkt, "rtp"):  rtp_count += 1
                if hasattr(pkt, "tls"):  has_tls = True
                if hasattr(pkt, "srtp"): has_srtp = True
            cap.close()
        except Exception as e:
            raise RuntimeError(f"Parse failed: {e}") from e
        finally:
            try: loop.close()
            except: pass
        return msgs, total, sip_count, rtp_count, has_tls, has_srtp, ts_start, ts_end

    def _extract_message(self, pkt) -> Optional[SIPMessage]:
        try:
            sip = pkt.sip
            af  = sip._all_fields

            # Transport / IPs
            transport = "TLS" if hasattr(pkt,"tls") else "TCP" if hasattr(pkt,"tcp") else "UDP"
            src_ip = dst_ip = src_port = dst_port = ""
            if hasattr(pkt,"ip"):
                src_ip, dst_ip = str(pkt.ip.src), str(pkt.ip.dst)
            elif hasattr(pkt,"ipv6"):
                src_ip, dst_ip = str(pkt.ipv6.src), str(pkt.ipv6.dst)
            if hasattr(pkt,"tcp"):
                src_port, dst_port = str(pkt.tcp.srcport), str(pkt.tcp.dstport)
            elif hasattr(pkt,"udp"):
                src_port, dst_port = str(pkt.udp.srcport), str(pkt.udp.dstport)

            # Method or status
            is_request = True
            method = status_code = status_phrase = None
            req_tree = af.get("sip.Request-Line_tree", {})
            if isinstance(req_tree, dict) and req_tree.get("sip.Method"):
                method = str(req_tree["sip.Method"]).upper()
                is_request = True
            else:
                sta_tree = af.get("sip.Status-Line_tree", {})
                if isinstance(sta_tree, dict):
                    code = sta_tree.get("sip.Status-Code", "")
                    if str(code).isdigit():
                        status_code = int(code)
                        is_request  = False
                        sta_line    = str(af.get("sip.Status-Line", ""))
                        m = re.match(r'SIP/2\.0\s+\d+\s+(.*)', sta_line)
                        status_phrase = m.group(1).strip() if m else ""

            # ── Headers with robust multi-strategy extraction ──────────────
            call_id            = _get_call_id(af, sip)
            from_hdr, to_hdr   = _get_from_to(af, sip)
            cseq               = _get_cseq(af)
            via                = _get_via(af)
            contact            = _get_contact(af)
            ctype              = _get_content_type(af)

            # Retransmission
            retx = False
            for tk in ("sip.Request-Line_tree", "sip.Status-Line_tree"):
                t = af.get(tk, {})
                if isinstance(t, dict) and str(t.get("sip.resend", "0")) == "1":
                    retx = True; break

            # SDP
            body_tree = af.get("sip.msg_body_tree", {})
            has_sdp   = isinstance(body_tree, dict) and "sdp" in body_tree
            sdp_data  = _extract_sdp(body_tree) if has_sdp else None
            if not has_sdp and "sdp" in ctype.lower():
                has_sdp = True

            # Timestamp
            try:
                ts_str = datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime("%H:%M:%S.%f")[:-3]
            except:
                ts_str = "00:00:00.000"

            return SIPMessage(
                packet_number=int(pkt.number), timestamp=ts_str,
                src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                transport=transport, method=method,
                status_code=status_code, status_phrase=status_phrase,
                call_id=call_id or None, from_header=from_hdr or None,
                to_header=to_hdr or None, cseq=cseq or None,
                via=via or None, contact=contact or None, content_type=ctype or None,
                is_request=is_request, has_sdp=has_sdp, retransmission=retx,
                sdp=sdp_data,
            )
        except:
            return None

    def _build_dialogs(self, msgs: List[SIPMessage]) -> List[SIPDialog]:
        dlgs: Dict[str, SIPDialog] = {}
        for msg in msgs:
            if not msg.call_id:
                continue
            cid = msg.call_id
            if cid not in dlgs:
                dtype = ("CALL" if msg.method == "INVITE" else
                         "REGISTRATION" if msg.method == "REGISTER" else
                         "SUBSCRIPTION" if msg.method == "SUBSCRIBE" else "OTHER")
                dlgs[cid] = SIPDialog(
                    call_id=cid, dialog_type=dtype, state="ONGOING",
                    start_time=msg.timestamp, end_time=None,
                )
            d = dlgs[cid]
            d.messages.append(msg)
            if not msg.is_request and msg.status_code:
                d.final_response = msg.status_code
            if msg.is_request and msg.method in ("BYE", "CANCEL"):
                d.state    = "COMPLETED" if msg.method == "BYE" else "ABANDONED"
                d.end_time = msg.timestamp

        for d in dlgs.values():
            if d.state == "ONGOING" and d.final_response and d.final_response >= 400:
                d.state = "FAILED"

        return list(dlgs.values())
