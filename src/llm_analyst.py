import json, os, re
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)                      
except ImportError:
    pass

KNOWLEDGE = json.load(open(os.path.join(os.path.dirname(__file__), "..", "knowledge", "mitre_map.json")))
REQUIRED = ["summary", "severity", "likely_attack", "mitre_technique",
            "confidence", "recommended_actions", "additional_evidence_needed"]

SYSTEM_PROMPT = """You are a SOC (security operations) analyst assistant.
You receive ONE alert as JSON evidence, plus reference notes about the detector that fired.
Rules:
- Use ONLY the evidence and notes given. Do not invent IPs, usernames, counts or events.
- If the evidence is not enough to be sure, say so in "confidence" and "additional_evidence_needed".
- Reply with a single JSON object and nothing else, with exactly these keys:
  summary (2 sentences max), severity (low|medium|high|critical),
  likely_attack, mitre_technique, confidence (low|medium|high),
  recommended_actions (list of short strings), additional_evidence_needed (list of short strings)."""

def build_prompt(alert):
    notes = KNOWLEDGE.get(alert["detector"], {})
    return ("ALERT EVIDENCE:\n" + json.dumps(alert, indent=2) +
            "\n\nREFERENCE NOTES FOR THIS DETECTOR:\n" + json.dumps(notes, indent=2))

def parse_response(text):
    """Extract and validate the JSON object; never crash the pipeline on bad output."""
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, flags=re.S)
        if not m:
            return {"error": "LLM did not return JSON", "raw": text}
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return {"error": "LLM returned invalid JSON", "raw": text}
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        return {"error": f"missing keys: {missing}", "raw": text}
    data["severity"] = str(data["severity"]).lower()
    if data["severity"] not in ("low", "medium", "high", "critical"):
        data["severity"] = "medium"
    return data

def mock_analyst(alert):
    """Offline stand-in with NO LLM: fills the same JSON format from the knowledge file."""
    k = KNOWLEDGE.get(alert["detector"], {})
    n = alert.get("failed_logins", 0)
    sev = "critical" if alert["detector"] == "success_after_failures" else (
          "high" if n >= 30 else "medium")
    return {"summary": f"[MOCK] {k.get('meaning', 'Unusual activity')} "
                       f"Source {alert['source_ip']}, {n} failed logins.",
            "severity": sev, "likely_attack": alert["detector"].replace("_", " "),
            "mitre_technique": k.get("technique", "Unknown"), "confidence": "medium",
            "recommended_actions": k.get("actions", []),
            "additional_evidence_needed": ["Raw log lines for this IP", "IP reputation lookup"]}

def call_llm(alert, provider):
    prompt = build_prompt(alert)
    model = "gemini-3.1-flash-lite"
    print("Using model:", repr(model))
    if provider == "anthropic":
        from anthropic import Anthropic
        r = Anthropic().messages.create(model=model, max_tokens=800, system=SYSTEM_PROMPT,
                                        messages=[{"role": "user", "content": prompt}])
        return r.content[0].text
    if provider == "openai":
        from openai import OpenAI
        r = OpenAI().chat.completions.create(model=model, messages=[
            {"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}])
        return r.choices[0].message.content
    if provider == "gemini":
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        r = client.models.generate_content(
            model=model, contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json"))   
        return r.text
    raise ValueError(f"unknown provider {provider}")

def analyze_alert(alert, provider=None):
    provider = provider or os.getenv("LLM_PROVIDER", "mock")
    if provider == "mock":
        return mock_analyst(alert)
    return parse_response(call_llm(alert, provider))