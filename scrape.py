#!/usr/bin/env python3
"""Aviation Security Alerts - open-source scraper with verification (stdlib only).
Collect -> reject stale/retrospective items -> group into events (follow-ups never create new alerts)
-> cross-check pending events against other outlets -> publish only VERIFIED events.
Usage: python scrape.py [--selftest]"""
import json, re, sys, time, html, urllib.request, urllib.parse
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import xml.etree.ElementTree as ET

DATA = "data.json"
UA = "Mozilla/5.0 (compatible; AviationAlertsBot/2.0)"
MAX_AGE_H = 48; AUTO_RESOLVE_H = 72; KEEP_RESOLVED_D = 30; PENDING_DROP_D = 7
MAX_ITEMS = 40; MAX_CORRO = 12; FOLLOWUP_SIM = 0.40; CONTINUE_H = 36

NEWS_QUERIES = [
 "airspace closure Gulf", "airport attack Saudi Arabia", "Houthi airport missile drone", "NOTAM Saudi Arabia airspace",
 "flights cancelled Saudi Arabia", "flights suspended Dubai airlines", "GPS jamming Gulf aviation", "EASA CZIB conflict zone",
 "FAA airspace Middle East warning", "Iran airspace flights", "Iraq airspace flights", "Lebanon Beirut airport flights",
 "Israel airspace Ben Gurion flights", "Kuwait airport flights", "Qatar airspace flights Doha", "Bahrain airport flights",
 "Oman airspace flights Muscat", "Yemen airport Aden Sanaa flights", "Red Sea aviation airspace", "Jordan airspace Amman flights",
 "Syria airspace Damascus flights", "Egypt airport flights suspended", "airline suspends flights Middle East",
 "Riyadh airport", "Dammam airport", "Jeddah airport", "Abu Dhabi Sharjah flights disruption", "drone intercepted airport Gulf",
 "site:arabnews.com airport flights", "site:gulfnews.com flights airspace", "site:khaleejtimes.com flights airport",
 "site:thenationalnews.com flights airspace", "site:timesofisrael.com airspace flights", "site:middleeasteye.net airport flights",
 "site:aljazeera.com airport airspace", "site:reuters.com airspace airport Gulf", "site:avherald.com Middle East",
 "site:simpleflying.com Middle East airspace", "site:aviationweek.com Middle East airspace", "site:flightglobal.com Middle East airspace",
]
FEEDS = [
 ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml", "media"),
 ("BBC Middle East", "http://feeds.bbci.co.uk/news/world/middle_east/rss.xml", "media"),
 ("The National", "https://www.thenationalnews.com/arc/outboundfeeds/rss/?outputType=xml", "media"),
 ("Simple Flying", "https://simpleflying.com/feed/", "media"),
]
HTML_PAGES = [("EASA CZIBs", "https://www.easa.europa.eu/en/domains/air-operations/czibs", "official", ["czib"]),
              ("Safe Airspace", "https://safeairspace.net/summary/", "risk", ["notam", "level", "airspace"])]
OFFICIAL = ["easa", "faa", "gaca", "gcaa", "icao", "state department", "spa.gov", "wam", "transport canada", "civil aviation"]
RISK = ["safe airspace", "safeairspace", "osprey", "opsgroup"]

COUNTRIES = {
 "Saudi Arabia": ["saudi", "riyadh", "jeddah", "dammam", "medina", "madinah", "mecca", "makkah", "abha", "jizan", "jazan", "najran", "taif", "yanbu", "khamis mushait", "qassim", "gaca"],
 "UAE": ["uae", "dubai", "abu dhabi", "sharjah", "etihad", "flydubai", "gcaa", "fujairah", "ras al khaimah"],
 "Qatar": ["qatar", "doha"], "Bahrain": ["bahrain", "manama"], "Kuwait": ["kuwait"], "Oman": ["oman", "muscat", "salalah"],
 "Iran": ["iran", "tehran"], "Iraq": ["iraq", "baghdad", "erbil", "basra"], "Israel": ["israel", "tel aviv", "ben gurion"],
 "Lebanon": ["lebanon", "beirut"], "Syria": ["syria", "damascus", "aleppo"], "Jordan": ["jordan", "amman"],
 "Egypt": ["egypt", "cairo"], "Yemen": ["yemen", "aden", "sanaa", "houthi", "mukalla"]}
REGION_EXTRA = ["red sea", "persian gulf", "strait of hormuz", "gulf of oman", "middle east", "gulf airspace", "gcc"]
AIRPORTS = {"king khalid": "RUH", "riyadh": "RUH", "dammam": "DMM", "king fahd": "DMM", "jeddah": "JED", "medina": "MED", "madinah": "MED",
 "abha": "AHB", "jizan": "GIZ", "jazan": "GIZ", "najran": "EAM", "taif": "TIF", "yanbu": "YNB", "qassim": "ELQ", "dubai": "DXB",
 "sharjah": "SHJ", "abu dhabi": "AUH", "doha": "DOH", "bahrain": "BAH", "kuwait": "KWI", "muscat": "MCT", "tehran": "IKA",
 "baghdad": "BGW", "erbil": "EBL", "beirut": "BEY", "damascus": "DAM", "amman": "AMM", "cairo": "CAI", "aden": "ADE", "tel aviv": "TLV", "ben gurion": "TLV"}
FIRS = {"Saudi Arabia": "OEJD", "UAE": "OMAE", "Qatar": "OTDF", "Bahrain": "OBBB", "Kuwait": "OKAC", "Iran": "OIIX", "Iraq": "ORBB",
 "Lebanon": "OLBB", "Syria": "OSTT", "Jordan": "OJAC", "Egypt": "HECC", "Yemen": "OYSC", "Oman": "OOMM", "Israel": "LLLL"}

RX = lambda p: re.compile(p, re.I)
AVIATION = RX(r"\b(airspace|airport|airports|flight|flights|airline|airlines|aircraft|notam|czib|runway|air traffic|gps|gnss|jamming|spoofing|aviation|passenger jet|plane|planes|fir|diverted|air route|carrier)\b")
DISRUPT = RX(r"(attack|strike|struck|missile|drone|clos|suspend|cancel|divert|halt|restrict|ban\b|prohibit|warn|advisory|jamming|spoof|intercept|shot down|threat|evacuat|delay|reopen|resum|ground|notam|czib|avoid|risk|no-fly|do not fly)")
APT_WORD = RX(r"\b(airport|airports|runway|terminal|air base)\b")
ATTACK_HIT = RX(r"(struck|hit\b|hits\b|attacked|attack on|strike on|strikes on|bombed|shelled|damaged|killed|injured|targeted)")
THREAT = RX(r"(missile|drone|intercept|ballistic|rocket)")
SHOT = RX(r"shot down|downed")
AIRSPACE_CLOSE = RX(r"(airspace.{0,40}(clos|shut)|(clos|shut).{0,40}airspace|prohibit|no-fly|do not fly|notam|czib|conflict zone)")
APT_CLOSE = RX(r"(clos|suspend|halt|evacuat|shut|ground stop)")
FLIGHT_SUSP = RX(r"(suspend|suspension|halt|stops? flights|pauses? flights)")
MEDIUM = RX(r"(cancel|delay|divert|advisory|warn|jamming|spoof|restrict|caution|reroute)")
# --- staleness / repeat detection ---
RETRO_CUES = RX(r"\b(recap|timeline|explainer|what we know|anniversary|looking back|a year (ago|since)|last (week|month|year)|weeks? (after|since|ago)|months? (after|since|ago)|earlier this (month|year)|previously reported|history of|in retrospect|flashback|reminder)\b")
FRESH_CUES = RX(r"\b(today|tonight|this (morning|afternoon|evening)|just now|breaking|minutes ago|hours ago|overnight|on (monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b")
MON = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
DATE_RX = re.compile(r"\b(?:(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?)\b", re.I)
STOP = set("the and for with from after amid into near over says said report reports reported new its this that are was were has have will not than more also how what who why when where about their they them his her you your".split())

def now(): return datetime.now(timezone.utc)
def iso(d): return d.strftime("%Y-%m-%dT%H:%M:%SZ")
def pdt(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))
def clean(s): return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s or ""))).strip()
def toks(s): return {w for w in re.findall(r"[a-z]{3,}", (s or "").lower()) if w not in STOP}
def jacc(a, b): return len(a & b) / len(a | b) if a and b else 0.0

def is_retro(title, text, pub):
    """True if the item is about an old event / background (so it must not raise a new alert)."""
    if FRESH_CUES.search(title): fresh = True
    else: fresh = False
    for y in re.findall(r"\b(20\d\d)\b", title):
        if int(y) < pub.year and not fresh: return "past year in headline"
    if RETRO_CUES.search(title) or RETRO_CUES.search((text or "")[:200]):
        if not fresh: return "retrospective wording"
    past = []
    for m in DATE_RX.finditer(title):
        d, mo = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))
        try:
            dt = datetime(pub.year, MON.index(mo.lower()[:3]) + 1, int(d), tzinfo=timezone.utc)
            if dt > pub + timedelta(days=1): dt = dt.replace(year=pub.year - 1)
            if dt <= pub: past.append(dt)
        except ValueError: pass
    if past and max(past) < pub - timedelta(days=3) and not fresh: return "headline dated " + max(past).strftime("%d %b")
    return ""

def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r: return r.read().decode("utf-8", "replace")
def local(tag): return tag.split("}")[-1]

def parse_feed(xml_text):
    out = []; root = ET.fromstring(xml_text.strip().encode("utf-8"))
    for el in root.iter():
        if local(el.tag) not in ("item", "entry"): continue
        d = {"title": "", "link": "", "date": None, "text": "", "source": ""}
        for c in el:
            t = local(c.tag)
            if t == "title": d["title"] = clean(c.text)
            elif t == "link": d["link"] = (c.get("href") or c.text or "").strip()
            elif t in ("pubDate", "updated", "published", "date"):
                try: d["date"] = parsedate_to_datetime(c.text).astimezone(timezone.utc)
                except Exception:
                    try: d["date"] = pdt((c.text or "").strip())
                    except Exception: pass
            elif t in ("description", "summary", "content"): d["text"] = clean(c.text)
            elif t == "source": d["source"] = clean(c.text)
        if d["title"] and d["link"]: out.append(d)
    return out

def classify(text):
    low = text.lower()
    if not AVIATION.search(low) or not DISRUPT.search(low): return None
    countries = [c for c, kws in COUNTRIES.items() if any(re.search(r"\b" + re.escape(k) + r"\b", low) for k in kws)]
    if not countries and not any(k in low for k in REGION_EXTRA): return None
    apt, hit, thr = APT_WORD.search(low), ATTACK_HIT.search(low), THREAT.search(low)
    airports = sorted({v for k, v in AIRPORTS.items() if re.search(r"\b" + re.escape(k) + r"\b", low)}) if apt else []
    reasons = []
    if (apt and hit) or (SHOT.search(low) and re.search(r"aircraft|plane|jet|flight|airliner", low)): sev = "CRITICAL"; reasons.append("attack on airport/aircraft")
    elif AIRSPACE_CLOSE.search(low) or (apt and APT_CLOSE.search(low)) or (apt and thr) or FLIGHT_SUSP.search(low): sev = "HIGH"; reasons.append("closure/suspension/threat")
    elif MEDIUM.search(low): sev = "MEDIUM"; reasons.append("cancellations/advisory/GNSS")
    else: sev = "LOW"; reasons.append("aviation context")
    if re.search(r"jamming|spoof|gnss|\bgps\b", low) or AIRSPACE_CLOSE.search(low) or "airspace" in low or re.search(r"\bfir\b", low): cat = "AIRSPACE"
    elif apt: cat = "AIRPORT"
    elif thr or re.search(r"attack|strike", low): cat = "MILITARY"
    else: cat = "CIVIL"
    return {"countries": countries, "airports": airports, "severity": sev, "category": cat, "reasons": reasons}

def tier_for(name, default):
    n = name.lower()
    if any(k in n for k in RISK): return "risk"
    if any(k in n for k in OFFICIAL): return "official"
    return default
def pub_key(name):
    n = re.sub(r"\s+via\s+.*$", "", (name or "").lower()); n = re.sub(r"google news.*", "", n)
    return re.sub(r"[^a-z0-9]", "", re.sub(r"\.(com|net|org|co|pk|in|tv)\b", "", n))
def slug(s): return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def make_item(e, name, tier, c):
    src = e.get("source") or name
    title = re.sub(r"\s+-\s+" + re.escape(src) + r"$", "", e["title"]) if e.get("source") else e["title"]
    return {"c": c, "title": title, "item": {"source_name": src, "tier": tier_for(src, tier), "published_at": iso(e["date"]),
            "text": (e["title"] + ". " + e["text"])[:600], "url": e["link"], "reasons": c["reasons"]}}

def collect(test_entries=None):
    items, srcs, disc = [], [], {"retro": 0, "old": 0, "undated": 0}
    cutoff = now() - timedelta(hours=MAX_AGE_H)
    def add(name, tier, entries, html_page=False):
        n = 0
        for e in entries:
            if not e["date"]: disc["undated"] += 1; continue
            if e["date"] < cutoff: disc["old"] += 1; continue
            c = classify(e["title"] + " " + e["text"])
            if not c: continue
            if is_retro(e["title"], e["text"], e["date"]): disc["retro"] += 1; continue
            items.append(make_item(e, name, tier, c)); n += 1
        return n
    if test_entries is not None: add("Test", "media", test_entries); return items, srcs, disc
    jobs = [("Google News", "https://news.google.com/rss/search?q=" + urllib.parse.quote(q + " when:2d") + "&hl=en&gl=AE&ceid=AE:en", "media") for q in NEWS_QUERIES] + FEEDS
    ok_news = 0
    for name, url, tier in jobs:
        try:
            n = add(name, tier, parse_feed(fetch(url)))
            if name == "Google News": ok_news += 1
            else: srcs.append({"name": name, "ok": True, "note": f"{n} relevant item(s)"})
        except Exception as ex:
            if name != "Google News": srcs.append({"name": name, "ok": False, "note": str(ex)[:80]})
        time.sleep(0.25)
    srcs.insert(0, {"name": "Google News (Reuters, AP, AFP, Arab News, Gulf News, Khaleej Times, Times of Israel, Middle East Eye, Aviation Herald, etc.)", "ok": ok_news > 0, "note": f"{ok_news}/{len(NEWS_QUERIES)} queries answered"})
    yr = str(now().year)
    for name, url, tier, kws in HTML_PAGES:
        try:
            page = fetch(url); n = 0; seen = set()
            for href, label in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', page, re.S | re.I):
                label = clean(label)
                if len(label) < 12 or label in seen or not any(k in (label + href).lower() for k in kws): continue
                if yr not in (label + href):  # undated page links: only current-year documents count
                    disc["undated"] += 1; continue
                seen.add(label)
                n += add(name, tier, [{"title": label + " (" + name + ")", "link": urllib.parse.urljoin(url, href), "date": now(), "text": "Listed on " + name, "source": name}], True)
            srcs.append({"name": name, "ok": True, "note": f"{n} current document(s)"})
        except Exception as ex: srcs.append({"name": name, "ok": False, "note": str(ex)[:80]})
    return items, srcs, disc

def independent(ev):
    return {pub_key(i["source_name"]) for i in ev["items"] if not i.get("followup") and pub_key(i["source_name"])}
def verify(ev):
    if not ev.get("auto"):
        ev["verification"] = "VERIFIED"; ev.setdefault("verification_note", "Curated and analyst-verified"); return
    names = independent(ev); tiers = {i["tier"] for i in ev["items"] if not i.get("followup")}
    ev["independent_sources"] = len(names)
    if "official" in tiers or "risk" in tiers: ev["verification"] = "VERIFIED"; ev["verification_note"] = "Confirmed by an official or conflict-zone risk source"
    elif len(names) >= 2: ev["verification"] = "VERIFIED"; ev["verification_note"] = f"Corroborated by {len(names)} independent outlets"
    else: ev["verification"] = "PENDING"; ev["verification_note"] = "Single source so far; held back until corroborated"
    if ev["severity"] == "LOW" and ev["verification"] == "VERIFIED": ev["verification"] = "PENDING"; ev["verification_note"] = "Low-impact context; not alerted"
    ev["confidence"] = "CONFIRMED" if "official" in tiers else "RELIABLE" if ("risk" in tiers or len(names) >= 3) else "REPORTED"

def find_event(events, c, ptime, ttoks):
    best, bs = None, 0
    for ev in events.values():
        if ev.get("verification") == "REJECTED": continue
        sc = set(ev.get("countries", [])); cc = set(c["countries"])
        if (sc or cc) and not (sc & cc): continue
        if ev.get("airports") and c["airports"] and not (set(ev["airports"]) & set(c["airports"])): continue
        sim = jacc(ttoks, toks(ev["title"]) | toks(" ".join(i["text"][:80] for i in ev["items"][:3])))
        gap = abs((ptime - pdt(ev["last_seen"])).total_seconds()) / 3600
        same = ev["category"] == c["category"]
        if gap <= CONTINUE_H and (same or sim >= 0.30): score = 1 + sim
        elif sim >= FOLLOWUP_SIM and (ptime - pdt(ev["first_seen"])) > timedelta(hours=CONTINUE_H) and gap > CONTINUE_H: score = 0.5 + sim  # old story told again
        else: continue
        if score > bs: best, bs = ev, score
    return best

def merge(data, items, srcs, disc):
    t = now(); events = {e["id"]: e for e in data.get("events", [])}
    new_events = new_items = followups = 0; touched = set()
    for it in sorted(items, key=lambda x: x["item"]["published_at"]):
        c, item = it["c"], it["item"]; ptime = pdt(item["published_at"]); tt = toks(it["title"])
        ev = find_event(events, c, ptime, tt)
        if ev:
            known = {i.get("url") for i in ev["items"]} | {(i["source_name"], i["text"][:60]) for i in ev["items"]}
            if item["url"] in known or (item["source_name"], item["text"][:60]) in known: continue
            if (ptime - pdt(ev["last_seen"])).total_seconds() / 3600 > CONTINUE_H or abs((ptime - pdt(ev["first_seen"])).total_seconds()) / 3600 > 24 * 7:
                item = {**item, "followup": True}; followups += 1   # old incident re-reported: attach, never re-alert
        else:
            eid = slug(f"auto-{(c['countries'] or ['region'])[0]}-{(c['airports'] or [c['category']])[0]}-{item['published_at'][:13]}")[:90]
            ev = events[eid] = {"id": eid, "title": it["title"], "category": c["category"], "severity": c["severity"], "confidence": "REPORTED",
                "countries": c["countries"], "airports": c["airports"], "firs": [FIRS[x] for x in c["countries"] if x in FIRS],
                "first_seen": item["published_at"], "last_seen": item["published_at"], "status": "ACTIVE", "auto": True, "verification": "PENDING",
                "summary": "", "ops_note": "Automatically collected from open sources. Check official NOTAMs, AIP SUPs and CZIBs before any operational decision.", "items": []}
            new_events += 1
        ev["items"].append(item); new_items += 1; touched.add(ev["id"])
        ev["items"] = sorted(ev["items"], key=lambda i: i["published_at"], reverse=True)[:MAX_ITEMS]
        if not item.get("followup"):
            if RANK[c["severity"]] > RANK[ev["severity"]]: ev["severity"] = c["severity"]; ev["title"] = it["title"]
            ev["last_seen"] = max(ev["last_seen"], item["published_at"])
            if ev.get("auto") and ev["status"] == "RESOLVED": ev["status"] = "ACTIVE"
        ev["countries"] = sorted(set(ev["countries"]) | set(c["countries"])); ev["airports"] = sorted(set(ev["airports"]) | set(c["airports"]))
    return events, touched, new_events, new_items, followups

def corroborate(events):
    """Cross-check unverified auto events against other outlets before they are shown."""
    pend = sorted([e for e in events.values() if e.get("auto") and e.get("verification") == "PENDING" and e["status"] == "ACTIVE"],
                  key=lambda e: (-RANK[e["severity"]], e["last_seen"]), reverse=False)[:MAX_CORRO]
    checked = promoted = 0; cutoff = now() - timedelta(hours=72)
    for ev in pend:
        kw = " ".join(sorted(toks(ev["title"]), key=len, reverse=True)[:6])
        try: entries = parse_feed(fetch("https://news.google.com/rss/search?q=" + urllib.parse.quote(kw + " when:3d") + "&hl=en&gl=AE&ceid=AE:en"))
        except Exception: continue
        checked += 1; names = independent(ev); known = {i["url"] for i in ev["items"]}
        for e in entries:
            if not e["date"] or e["date"] < cutoff or e["link"] in known: continue
            src = e.get("source") or ""; pk = pub_key(src)
            if not pk or pk in names: continue
            c = classify(e["title"] + " " + e["text"])
            if not c or is_retro(e["title"], e["text"], e["date"]): continue
            if jacc(toks(e["title"]), toks(ev["title"])) < 0.30: continue
            ev["items"].append(make_item(e, "Google News", "media", c)["item"]); names.add(pk)
        time.sleep(0.25)
        before = ev["verification"]; verify(ev)
        if before == "PENDING" and ev["verification"] == "VERIFIED": promoted += 1
    return checked, promoted

def consolidate(events):
    """Merge duplicate auto events that describe the same story (older versions split them by date)."""
    kept = []
    for ev in sorted([e for e in events.values() if e.get("auto")], key=lambda e: e["first_seen"]):
        tgt = None
        for k in kept:
            sc, cc = set(k["countries"]), set(ev["countries"])
            if (sc or cc) and not (sc & cc): continue
            if k["airports"] and ev["airports"] and not (set(k["airports"]) & set(ev["airports"])): continue
            sim = jacc(toks(k["title"]), toks(ev["title"])); gap = abs((pdt(ev["first_seen"]) - pdt(k["last_seen"])).total_seconds()) / 3600
            if sim >= 0.5 or (sim >= 0.3 and gap <= CONTINUE_H): tgt = k; break
        if not tgt: kept.append(ev); continue
        urls = {i["url"] for i in tgt["items"]}
        tgt["items"] = sorted(tgt["items"] + [i for i in ev["items"] if i["url"] not in urls], key=lambda i: i["published_at"], reverse=True)[:MAX_ITEMS]
        tgt["first_seen"] = min(tgt["first_seen"], ev["first_seen"]); tgt["last_seen"] = max(tgt["last_seen"], ev["last_seen"])
        if RANK[ev["severity"]] > RANK[tgt["severity"]]: tgt["severity"] = ev["severity"]; tgt["title"] = ev["title"]
        tgt["countries"] = sorted(set(tgt["countries"]) | set(ev["countries"])); tgt["airports"] = sorted(set(tgt["airports"]) | set(ev["airports"]))
        events.pop(ev["id"], None)

def finalize(data, items, srcs, disc, do_corro=True):
    t = now(); events, touched, ne, ni, fu = merge(data, items, srcs, disc)
    consolidate(events); touched = {e for e in touched if e in events}
    for eid in touched:
        ev = events[eid]; fresh = [i for i in ev["items"] if not i.get("followup")] or ev["items"]; latest = fresh[0]
        ev["current"] = f"{latest['published_at'][5:16].replace('T',' ')}Z latest report: {latest['text'].split('. ')[0][:220]} ({latest['source_name']}). Auto-collected."
        ev["summary"] = f"{len(ev['items'])} source item(s) from {len({i['source_name'] for i in ev['items']})} source(s) grouped automatically."
        ev["verified_at"] = iso(t)
    for ev in events.values(): verify(ev)
    checked, promoted = corroborate(events) if do_corro else (0, 0)
    resolved = 0
    for ev in events.values():
        if ev.get("auto") and ev["status"] == "ACTIVE" and t - pdt(ev["last_seen"]) > timedelta(hours=AUTO_RESOLVE_H):
            ev["status"] = "RESOLVED"; ev["current"] = f"No new reports since {ev['last_seen'][:16].replace('T',' ')}Z; closed automatically."; resolved += 1
    cut = t - timedelta(days=KEEP_RESOLVED_D); pcut = t - timedelta(days=PENDING_DROP_D)
    events = {k: v for k, v in events.items() if not (v["status"] == "RESOLVED" and pdt(v["last_seen"]) < cut) and not (v.get("verification") == "PENDING" and pdt(v["last_seen"]) < pcut)}
    vis = sum(1 for e in events.values() if e.get("verification") != "PENDING"); pend = len(events) - vis
    ok = sum(1 for s in srcs if s["ok"])
    status = {"last_run": iso(t), "next_run": iso(t + timedelta(minutes=10)), "items_found": ni, "new_events": ne,
      "note": f"{ni} new item(s), {ne} new event(s); {fu} re-reports of older incidents attached without a new alert; {pend} event(s) held pending verification, {promoted} promoted after cross-check of {checked}; rejected as stale/retrospective: {disc['retro']}, outside window: {disc['old']}, undated: {disc['undated']}; {resolved} auto-resolved; {ok}/{len(srcs)} sources reachable.",
      "sources": srcs}
    return {"exported_at": iso(t), "status": status, "events": sorted(events.values(), key=lambda e: e["last_seen"], reverse=True)}

def migrate(data):
    """Clean events written by older versions: drop stale/undated items, then re-verify."""
    yr = str(now().year); keep = []
    for ev in data.get("events", []):
        if ev.get("auto"):
            ev["items"] = [i for i in ev.get("items", []) if not is_retro(i["text"].split(". ")[0], i["text"], pdt(i["published_at"]))
                           and not (i["source_name"] in ("Safe Airspace", "EASA CZIBs") and yr not in (i["text"] + i.get("url", "")))]
            if not ev["items"]: continue
            ev["last_seen"] = max(i["published_at"] for i in ev["items"]); ev["first_seen"] = min(i["published_at"] for i in ev["items"])
        keep.append(ev)
    data["events"] = keep; return data

def selftest():
    n = now(); f = lambda d: d.strftime("%a, %d %b %Y %H:%M:%S +0000")
    def rss(rows): return "<rss><channel>" + "".join(f"<item><title>{t}</title><link>{l}</link><pubDate>{f(d)}</pubDate><source>{s}</source><description>{x}</description></item>" for t, l, d, s, x in rows) + "</channel></rss>"
    old = n - timedelta(days=9)
    rows = [("Houthi missiles strike Aden airport, flights halted - Reuters", "https://x/1", n, "Reuters", "Two missiles hit the airport runway in Yemen."),
            ("Aden airport hit by missiles, flights halted - Gulf News", "https://x/2", n - timedelta(hours=1), "Gulf News", "Missiles struck the runway at Aden airport"),
            ("Best airlines awards 2026", "https://x/3", n, "X", ""),
            ("Recap: what we know about the Riyadh airport attack", "https://x/4", n, "Y", "airport attack Saudi flights"),
            ("Riyadh airport closure: airspace risk - 2022", "https://x/5", n, "Z", "airport closure Saudi"),
            ("Saudi airport strike on 12 Oct revisited, flights suspended", "https://x/6", n, "W", "airport Saudi"),
            ("Saudi Arabia airspace NOTAM restricts flights near Riyadh airport", "https://x/7", n, "Lonely Outlet", "")]
    items, _, disc = collect(parse_feed(rss(rows)))
    assert disc["retro"] == 3, disc
    assert len(items) == 3, [i["title"] for i in items]
    out = finalize({"events": []}, items, [{"name": "t", "ok": True, "note": ""}], disc, do_corro=False)
    by = {e["airports"][0] if e["airports"] else "x": e for e in out["events"]}
    assert by["ADE"]["verification"] == "VERIFIED" and by["ADE"]["independent_sources"] == 2, by["ADE"]
    assert [e for e in out["events"] if e["verification"] == "PENDING"], "single-source event must be pending"
    # old incident re-reported later must not create a new event
    old_ev = by["ADE"]; old_ev["first_seen"] = iso(n - timedelta(days=4)); old_ev["last_seen"] = iso(n - timedelta(days=3))
    again = [("Houthi missiles strike Aden airport, flights halted - AP", "https://x/9", n, "AP", "Missiles hit the runway at Aden airport Yemen")]
    it2, _, d2 = collect(parse_feed(rss(again)))
    out2 = finalize({"events": [old_ev]}, it2, [], d2, do_corro=False)
    assert len(out2["events"]) == 1 and out2["events"][0]["last_seen"] == old_ev["last_seen"], "re-report created a new alert"
    assert any(i.get("followup") for i in out2["events"][0]["items"])
    print("selftest OK:", [(e["verification"], e["severity"], e["title"][:40]) for e in out["events"]])

if __name__ == "__main__":
    if "--selftest" in sys.argv: selftest(); sys.exit(0)
    try: data = json.load(open(DATA))
    except Exception: data = {"events": []}
    data = migrate(data)
    items, srcs, disc = collect()
    out = finalize(data, items, srcs, disc)
    json.dump(out, open(DATA, "w"), indent=1, ensure_ascii=False)
    print(out["status"]["note"])
