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
  Standards Track and intended to replace RFC 7489 and RFC 9091.

Key points about DMARC vs DMARCbis:

1. Status and structure
   - RFC 7489 is an Informational RFC that defines DMARC as originally deployed.
   - DMARCbis is a Standards Track revision. The work is split into multiple documents
     for the core protocol and reporting, and adds clearer examples and operational guidance.

2. Organizational domain discovery
   - RFC 7489 relies on the Public Suffix List to find the organizational domain.
   - DMARCbis replaces the Public Suffix List dependency with a DNS tree walk. Receivers walk
     up the DNS hierarchy to look for DMARC records, with limits on how far they can walk.

3. Tags and compatibility
   - The DMARC version tag stays v=DMARC1 for compatibility.
   - Existing records remain valid under DMARCbis.
   - Tags such as pct, ri, and rf are being moved toward Historic status. Modern guidance
     is to avoid pct based rollouts and rely on clear policies plus the testing flag t.

4. Reporting
   - Aggregate and failure reporting concepts remain but are clarified and split into dedicated
     documents. Behavior is specified more precisely rather than fundamentally changed.

5. Practical guidance
   - Current DMARC deployments based on RFC 7489 continue to work.
   - New deployments should avoid pct centric strategies and be ready for DNS tree walk based
     organizational domain discovery as receivers adopt DMARCbis.
   - When users ask about current DMARC vs DMARCbis, clearly label which behavior comes
     from RFC 7489 style deployments and which is DMARCbis guidance.

Answer in practical, implementation focused language that a security engineer,
email administrator, or MSP can act on.
"""


# ------------------------------------------------------------
# DNS helpers
# ------------------------------------------------------------

def _lookup_txt_records(name: str) -> List[str]:
    """
    Return all TXT records for a name as plain strings.
    Handle common DNS errors gracefully.
    """
    if dns is None:
        return []

    try:
        answers = dns.resolver.resolve(name, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []

    records: List[str] = []
    for rdata in answers:
        # dnspython TXT data can be list of bytes or strings
        try:
            parts = [
                p.decode("utf-8") if isinstance(p, bytes) else str(p)
                for p in rdata.strings
            ]
            records.append("".join(parts))
        except AttributeError:
            text = str(rdata)
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
            records.append(text)

    return records


def get_dmarc_records(domain: str) -> List[str]:
    """
    Return all DMARC records at _dmarc.domain.
    There should be at most one valid record. More than one is a misconfiguration.
    """
    name = f"_dmarc.{domain}"
    records: List[str] = []
    for rec in _lookup_txt_records(name):
        if rec.lower().startswith("v=dmarc1"):
            records.append(rec)
    return records


def get_dmarc_record(domain: str) -> Optional[str]:
    """
    Return the first DMARC record for convenience.
    """
    records = get_dmarc_records(domain)
    return records[0] if records else None


def get_spf_record(domain: str) -> Optional[str]:
    """
    Look for an SPF record at the domain.
    Return the first v=spf1 record found, or None.
    """
    for rec in _lookup_txt_records(domain):
        if rec.lower().startswith("v=spf1"):
            return rec
    return None


# ------------------------------------------------------------
# DMARC parsing and DMARCbis evaluation
# ------------------------------------------------------------

def parse_dmarc_record(record: str) -> Dict[str, str]:
    """
    Parse a DMARC record string into a dict of tag -> value.
    Simple parser suitable for normal records.
    """
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
        else:
            tags[part.strip().lower()] = ""
    return tags


def evaluate_dmarc_against_dmarcbis(
    record: str,
    domain: str,
    record_count: int = 1,
) -> Dict[str, Any]:
    """
    Take a DMARC record string and produce a DMARC vs DMARCbis style assessment.
    Includes basic syntax and configuration checks.
    """
    tags = parse_dmarc_record(record)
    issues: List[str] = []
    notes: List[str] = []

    # Multiple record check
    if record_count > 1:
        issues.append(
            f"There are {record_count} DMARC records at _dmarc.{domain}. "
            "Only one DMARC record should be published. Multiple records can cause receivers "
            "to ignore DMARC or behave inconsistently."
        )

    v = tags.get("v", "").strip().lower()
    p = tags.get("p", "").strip().lower()
    sp = tags.get("sp", "").strip().lower()
    pct_raw = tags.get("pct")
    ri = tags.get("ri")
    rf = tags.get("rf")
    rua_raw = tags.get("rua")
    ruf_raw = tags.get("ruf")
    t_flag = tags.get("t")

    # Version
    if v != "dmarc1":
        issues.append(
            "Version tag v is not v=DMARC1. DMARC and DMARCbis both expect v=DMARC1."
        )

    # Policy
    if p in ("none", "quarantine", "reject"):
        policy = p
    else:
        policy = "unknown"
        issues.append(
            "Policy tag p is missing or not one of none, quarantine, or reject. "
            "Receivers may ignore the record if p is invalid."
        )

    if policy == "none":
        notes.append(
            "Policy p=none is suitable for initial monitoring, but DMARCbis style guidance treats it as a temporary state. "
            "Plan a clear path toward p=quarantine and eventually p=reject once alignment is clean."
        )
    elif policy == "quarantine":
        notes.append(
            "Policy p=quarantine is a partial enforcement step. DMARCbis guidance expects you to monitor impact and either "
            "move to p=reject or have clear reasons to stay at quarantine."
        )
    elif policy == "reject":
        notes.append(
            "Policy p=reject is a strong enforcement posture. Continue monitoring aggregate reports and keep a process for "
            "onboarding new third party senders."
        )

    if sp:
        notes.append(
            f"Subdomain policy sp={sp} is present. Under DMARCbis this remains valid but should reflect your intent for "
            "subdomains, especially where they host independent services."
        )

    # pct validation
    pct_value: Optional[int] = None
    if pct_raw is not None:
        try:
            pct_value = int(pct_raw)
            if pct_value < 0 or pct_value > 100:
                issues.append(
                    f"pct={pct_raw} is outside the valid range 0 to 100. Receivers may treat this as invalid."
                )
            else:
                issues.append(
                    "Tag pct is present. DMARCbis moves pct toward Historic status. Relying on pct-based partial enforcement "
                    "is discouraged in favor of clear policies plus the testing flag t."
                )
        except ValueError:
            issues.append(
                f"pct={pct_raw} is not a valid integer. Receivers may consider the record invalid or ignore pct."
            )

    # ri, rf considered Historic in DMARCbis registries
    if ri is not None:
        notes.append(
            "Tag ri is present. Under DMARCbis it is treated as Historic. Many receivers ignore ri and choose their own report cadence."
        )
    if rf is not None:
        notes.append(
            "Tag rf is present. DMARCbis treats rf as Historic. Failure report formats are less central in modern deployments."
        )

    # Reporting: rua/ruf validation
    def _parse_uris(raw: str) -> List[str]:
        return [u.strip() for u in raw.split(",") if u.strip()]

    if not rua_raw:
        issues.append(
            "No rua tag found. Without rua you will not receive aggregate reports, which makes DMARC monitoring and "
            "DMARCbis style rollouts much harder."
        )
        rua_list: List[str] = []
    else:
        rua_list = _parse_uris(rua_raw)
        if not rua_list:
            issues.append(
                "rua is present but empty after parsing. At least one mailto URI is required for aggregate reporting."
            )
        else:
            non_mailto = [u for u in rua_list if not u.lower().startswith("mailto:")]
            if non_mailto:
                issues.append(
                    "rua contains values that are not mailto URIs. DMARC requires mailto URIs for aggregate reports."
                )
            else:
                notes.append(
                    "Aggregate reporting rua is present and uses mailto URIs. Under DMARCbis this remains the primary source "
                    "of operational visibility."
                )

    if ruf_raw:
        ruf_list = _parse_uris(ruf_raw)
        non_mailto_ruf = [u for u in ruf_list if not u.lower().startswith("mailto:")]
        if non_mailto_ruf:
            issues.append(
                "ruf contains values that are not mailto URIs. DMARC requires mailto URIs for failure reports."
            )
        else:
            notes.append(
                "Failure reporting ruf is present. DMARCbis tightens privacy and operational guidance for failure reports. "
                "Only use ruf if you have a real process for handling and protecting these samples."
            )

    # Testing flag
    if t_flag:
        notes.append(
            "Testing flag t is present. DMARCbis encourages using testing in combination with full policies rather than "
            "pct-based rollouts."
        )

    if not issues and not notes:
        overall = (
            f"The DMARC record for {domain} looks broadly compatible with DMARCbis guidance. "
            "You should still review it in detail against your actual sending infrastructure."
        )
    else:
        overall = (
            f"The DMARC record for {domain} is structurally valid but there are items to review in light of DMARC and DMARCbis guidance."
        )

    return {
        "record": record,
        "tags": tags,
        "policy": policy,
        "issues": issues,
        "dmarchbis_notes": notes,  # key name kept for compatibility with your app.py
        "overall_assessment": overall,
        "record_count": record_count,
    }


# ------------------------------------------------------------
# SPF evaluation with exact DNS lookup counting
# ------------------------------------------------------------

def _spf_core(term: str) -> str:
    """
    Strip SPF qualifier (+, -, ~, ?) and return the core mechanism or modifier.
    """
    if not term:
        return term
    if term[0] in "+-~?":
        return term[1:]
    return term


def _spf_dns_lookups_for_record(domain: str, record: str, visited: Set[str]) -> Tuple[int, List[str]]:
    """
    Exact logical DNS lookup count for a specific SPF record string.

    Counts mechanisms and modifiers that require DNS queries:
      - include
      - redirect
      - a / a:
      - mx / mx:
      - ptr / ptr:
      - exists:
      - exp=
    """
    notes: List[str] = []
    terms = record.split()
    lookups = 0

    if not terms or terms[0].lower() != "v=spf1":
        notes.append(f"SPF record for {domain} does not start with v=spf1.")
        return lookups, notes

    # Skip "v=spf1"
    for raw in terms[1:]:
        core = _spf_core(raw)

        # Modifiers
        if core.startswith("redirect="):
            lookups += 1
            target = core.split("=", 1)[1]
            child_count, child_notes = _spf_dns_lookups_for_domain(target, visited)
            lookups += child_count
            notes.extend(child_notes)
            # redirect ends evaluation of the current record
            break

        if core.startswith("exp="):
            # exp means another TXT lookup
            lookups += 1
            continue

        # Mechanisms that cause DNS lookups
        if core.startswith("include:"):
            lookups += 1
            child_domain = core.split(":", 1)[1]
            child_count, child_notes = _spf_dns_lookups_for_domain(child_domain, visited)
            lookups += child_count
            notes.extend(child_notes)
            continue

        if core == "a" or core.startswith("a:") or core.startswith("a/"):
            lookups += 1
            continue

        if core == "mx" or core.startswith("mx:") or core.startswith("mx/"):
            lookups += 1
            continue

        if core == "ptr" or core.startswith("ptr:"):
            lookups += 1
            notes.append("SPF uses ptr, which is discouraged and can be slow or unreliable.")
            continue

        if core.startswith("exists:"):
            lookups += 1
            continue

        # ip4, ip6, all, and other pure pattern mechanisms do not add DNS lookups

    return lookups, notes


def _spf_dns_lookups_for_domain(domain: str, visited: Set[str]) -> Tuple[int, List[str]]:
    """
    Recursively compute the SPF DNS lookup count for a domain,
    following include and redirect chains.
    """
    notes: List[str] = []

    if domain in visited:
        notes.append(f"SPF include or redirect recursion detected for {domain}.")
        return 0, notes

    if len(visited) > 20:
        notes.append("SPF recursion depth limit reached. Stopping further include or redirect processing.")
        return 0, notes

    visited.add(domain)

    record = get_spf_record(domain)
    if not record:
        notes.append(f"No SPF record found for {domain} when following include or redirect.")
        return 0, notes

    return _spf_dns_lookups_for_record(domain, record, visited)


def evaluate_spf(domain: str, record: str) -> Dict[str, Any]:
    """
    Evaluate an SPF record and compute the exact logical DNS lookup count.

    Flags if the SPF configuration exceeds the SPF 10 lookup limit, which can
    cause receivers to treat SPF as a permanent error for this domain.
    """
    issues: List[str] = []
    notes: List[str] = []

    if not record:
        return {
            "record": None,
            "dns_lookups": 0,
            "estimated_dns_lookups": 0,
            "issues": ["No SPF record found."],
            "notes": [],
        }

    visited: Set[str] = set()
    total_lookups, lookup_notes = _spf_dns_lookups_for_domain(domain, visited)
    notes.extend(lookup_notes)

    if total_lookups > 10:
        issues.append(
            f"SPF DNS lookups for {domain} are {total_lookups}, which exceeds the SPF 10 lookup limit. "
            "Receivers can treat this as a permanent error and ignore the SPF result."
        )
    else:
        notes.append(
            f"SPF DNS lookups for {domain} are {total_lookups}, which is within the SPF 10 lookup limit."
        )

    if total_lookups == 0:
        notes.append(
            "SPF has zero DNS lookups. This usually means the record is simple and may only contain ip4, ip6, and all."
        )

    return {
        "record": record,
        "dns_lookups": total_lookups,
        "estimated_dns_lookups": total_lookups,  # kept for compatibility with earlier UI code
        "issues": issues,
        "notes": notes,
    }


# ------------------------------------------------------------
# Domain analysis used by the Streamlit app
# ------------------------------------------------------------

def analyze_domain(domain: str, rua: Optional[str] = None, ruf: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a domain:
    - Fetch existing DMARC record(s) at _dmarc.domain.
    - Fetch existing SPF record at the root.
    - Run a DMARC vs DMARCbis style assessment on the live DMARC record.
    - Evaluate SPF DNS lookup count.
    - Suggest a starting DMARC record if none exists.
    """
    domain = domain.strip()
    dmarc_records = get_dmarc_records(domain)
    existing_dmarc = dmarc_records[0] if dmarc_records else None
    existing_spf = get_spf_record(domain)
    record_count = len(dmarc_records)

    rua_part = f";rua=mailto:{rua}" if rua else f";rua=mailto:dmarc-reports@{domain}"
    ruf_part = f";ruf=mailto:{ruf}" if ruf else ""
    recommended_record = f"v=DMARC1; p=none{rua_part}{ruf_part}; fo=1"

    if existing_dmarc:
        summary = (
            f"For {domain} there is already a DMARC record published at _dmarc.{domain}. "
            f"The app has evaluated it against DMARC and DMARCbis style guidance and highlighted any items to review."
        )
        dmarc_analysis = evaluate_dmarc_against_dmarcbis(existing_dmarc, domain, record_count=record_count)
    else:
        summary = (
            f"{domain} does not appear to have a DMARC record at _dmarc.{domain}. "
            f"The suggested record below is a starting point that collects reports at p=none "
            f"while you discover all legitimate senders and fix alignment."
        )
        dmarc_analysis = None

    if existing_spf:
        spf_analysis = evaluate_spf(domain, existing_spf)
    else:
        spf_analysis = None

    details: List[str] = []

    if existing_dmarc:
        details.append("A DMARC record is already present. Review the DMARCbis assessment below for policy and tag guidance.")
    else:
        details.append("No DMARC record was found. Start with a p=none record and review reports before enforcement.")

    if existing_spf:
        details.append("An SPF record is present. Verify that all legitimate senders are included and aligned.")
    else:
        details.append("No SPF record was detected on the root domain. Make sure you have SPF in place.")

    details.extend(
        [
            "Review aggregate RUA reports to identify all legitimate and unknown senders.",
            "Align SPF and DKIM for each first party and third party mail stream.",
            "Once alignment is complete, plan a staged move toward p=quarantine and then p=reject.",
        ]
    )

    dns_info: Dict[str, Optional[str]] = {
        "existing_dmarc": existing_dmarc,
        "existing_spf": existing_spf,
    }

    if dns is None:
        dns_info["note"] = "dnspython is not available, DNS lookups are disabled."

    return {
        "summary": summary,
        "recommended_record": recommended_record,
        "details": details,
        "dns": dns_info,
        "dmarc_analysis": dmarc_analysis,
        "spf_analysis": spf_analysis,
    }


# ------------------------------------------------------------
# Freeform Q&A using OpenAI with fallback
# ------------------------------------------------------------

def _fallback_rule_based_answer(question: str) -> str:
    """
    Simple backup logic if OpenAI is not available.
    """
    q = question.lower()

    if "p=none" in q and "p=reject" in q:
        return (
            "A safe path from p=none to p=reject usually looks like this:\n\n"
            "1. Start with p=none and collect reports for a while.\n"
            "2. Identify all legitimate senders and make sure SPF and DKIM are aligned.\n"
            "3. Move to p=quarantine with a low percentage, for example pct=10, while monitoring.\n"
            "4. Gradually increase pct and then move to p=reject once you are confident all "
            "legitimate traffic is authenticated and aligned.\n"
        )

    if "rua" in q or "ruf" in q:
        return (
            "RUA is for aggregate reports that give you a broad picture of who is sending on behalf "
            "of your domain. RUF is for forensic or failure reports that contain samples of messages "
            "that fail alignment. Most organizations use RUA and sometimes use RUF because of "
            "privacy and volume concerns."
        )

    if "dmarcbis" in q or "2.0" in q:
        return (
            "DMARCbis is the Standards Track revision of DMARC. It keeps v=DMARC1 and existing "
            "records valid, but it clarifies organizational domain discovery, moves some tags like "
            "pct toward Historic status, and replaces the Public Suffix List with a DNS tree walk. "
            "In practice your current DMARC record will keep working, but new guidance will focus "
            "less on pct and more on clear policies and testing flags."
        )

    return (
        "Here is a general approach for DMARC questions:\n\n"
        "1. Clarify the goal. Is it visibility only, or enforcement.\n"
        "2. Make sure SPF and DKIM are correctly configured for all legitimate senders.\n"
        "3. Use DMARC reports to identify unknown or unauthenticated sources.\n"
        "4. Remediate or block unknown sources, then move policies toward stronger enforcement."
    )


def answer_freeform_question(question: str) -> str:
    """
    Use OpenAI to answer DMARC, SPF, DKIM, email security and DNS related questions.
    Falls back to simple rule based logic if there is any problem.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _fallback_rule_based_answer(question)

    try:
        response = client.chat.completions.create(
            model="gpt-5.1-mini",
            messages=[
                {
                    "role": "system",
                    "content": DMARCBIS_DIFF_CHEATSHEET,
                },
                {
                    "role": "user",
                    "content": question,
                },
            ],
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return _fallback_rule_based_answer(question)
