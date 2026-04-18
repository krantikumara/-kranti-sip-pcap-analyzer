# Kranti's PCAP Analyzer

AI-powered SIP protocol analyzer for Wireshark PCAP/PCAPNG files.

## Features

- **SIP Message Analysis** — Full message flow with all fields
- **SDP Analysis** — Direction attributes (a=sendonly/sendrecv/recvonly/inactive)
- **Call Hold/Resume Detection** — RFC 3264 and RFC 2543 hold detection
- **Call Flow Diagram** — SVG ladder diagram with annotations
- **AI Dialog Analysis** — GPT-4o root cause analysis per dialog
- **Chat with PCAP** — Ask any question about the capture

## Quick Start

```bash
# 1. Install dependencies
pip install pyshark openai
pip install "gradio==4.19.2" "gradio-client==0.10.1"
pip install "jinja2==3.1.2" "huggingface_hub==0.23.4"

# Also install Wireshark/tshark from https://www.wireshark.org/download.html

# 2. Configure Azure OpenAI in config.py (or set env vars)
export AZURE_OPENAI_ENDPOINT="https://YOUR-RESOURCE.openai.azure.com"
export AZURE_OPENAI_API_KEY="your-key"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"

# 3. Run
python app.py
```

## SDP Hold/Resume Detection

| Attribute | Meaning | Detection |
|---|---|---|
| `a=sendonly` | Calling party on hold | ✅ RFC 3264 Hold |
| `a=recvonly` | Called party acknowledged hold | ✅ RFC 3264 Hold |
| `a=inactive` | Both parties on hold | ✅ RFC 3264 Hold |
| `a=sendrecv` | Active call / resume | ✅ RFC 3264 Resume |
| `c=0.0.0.0` | Legacy hold | ✅ RFC 2543 Hold |

## Files

| File | Purpose |
|---|---|
| `app.py` | Main Gradio UI |
| `pcap_parser.py` | SIP/SDP packet extraction |
| `agent.py` | Azure OpenAI analysis & chat |
| `callflow.py` | SVG call flow diagram |
| `config.py` | Configuration |

## License

MIT License — Open Source
