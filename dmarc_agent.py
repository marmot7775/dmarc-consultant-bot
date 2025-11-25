
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from openai import OpenAI

# DNS imports (optional but recommended)
try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None  # DNS lookups will be disabled if dnspython is not installed


client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

DMARCBIS_DIFF_CHEATSHEET = """
You are an email security, email deliverability, and DNS expert with deep experience in
DMARC, SPF, DKIM, DNS architecture, and mail flow.

Base your answers on:
- Current DMARC as defined in RFC 7489 plus updates and errata.
- The DMARCbis work (draft-ietf-dmarc-dmarcbis and related drafts), which is on the
  Standards Track and intended to replace RFC 7489 and
