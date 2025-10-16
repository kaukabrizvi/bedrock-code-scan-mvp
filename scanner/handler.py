import os, json, base64, re
from typing import List, Dict
import boto3

REGION = os.getenv("REGION", "us-east-1")
MODEL_ID = os.getenv("MODEL_ID")
bedrock = boto3.client("bedrock-runtime", region_name=REGION)

DEFAULT_EXCLUDES = [r"^bin/"]

def is_excluded(path: str, excludes: List[str]) -> bool:
    return any(re.search(pat, path) for pat in excludes)

def load_repo_policy(event_payload: Dict) -> Dict:
    policy = event_payload.get("repo_policy")
    if policy:
        return policy
    return {
        "scope": {"exclude": ["^bin/"]},
        "rules": {
            "input_validation_parsing": {"enabled": True},
            "concurrency": {"enabled": True},
            "general_security": {"enabled": True}
        },
        "output": {"confidence_threshold": 0.35}
    }

def build_prompt(policy: Dict, file_item: Dict) -> Dict:
    policy_excerpt = json.dumps(policy)[:2000]
    code_snippet = file_item["content"][:12000]
    user = f"""
PROJECT CONTEXT:
- Repo: {file_item.get('repo')}
- Commit: {file_item.get('sha')}
- Language: {file_item.get('lang')}
- File: {file_item.get('path')}
- Policy: {policy_excerpt}

TASK:
Analyze the provided code for:
1) Input validation & parsing bugs.
2) Concurrency bugs (races, deadlocks, lock ordering, unsafe sharing, async hazards).
3) Other security issues (parameter misuse, unsafe flows).

Infer author intent; if intent mismatches implementation, report it.

CODE:
{code_snippet}

OUTPUT SCHEMA:
{{
  "findings": [
    {{
      "rule_id": "string",
      "title": "string",
      "severity": "low|medium|high|critical",
      "confidence": 0.0,
      "file": "string",
      "line_start": 0,
      "line_end": 0,
      "category": "input_validation|parsing|concurrency|security_general",
      "explanation": "string",
      "fix_suggestion": "string"
    }}
  ]
}}
    """.strip()

    return {
        "anthropic_version": "bedrock-2023-05-31",
        "system": "You are a security/static-analysis expert. Output ONLY valid JSON for 'findings'.",
        "messages": [{"role": "user", "content": user}],
        "max_tokens": 1200,
        "temperature": 0.2,
    }

def invoke_bedrock(body: Dict) -> Dict:
    r = bedrock.invoke_model(
        modelId=MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(body),
    )
    payload = json.loads(r["body"].read())
    text = ""
    if "content" in payload and payload["content"]:
        text = payload["content"][0].get("text", "")
    try:
        data = json.loads(text)
    except Exception:
        data = {"findings": []}
    return data

def lambda_handler(event, context):
    try:
        body = event.get("body")
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode("utf-8")
        payload = json.loads(body)
    except Exception as e:
        return {"statusCode": 400, "body": json.dumps({"error": f"bad request: {e}"})}

    policy = load_repo_policy(payload)
    excludes = DEFAULT_EXCLUDES + policy.get("scope", {}).get("exclude", [])

    findings_total = []
    for f in payload.get("files", []):
        path = f["path"]
        if is_excluded(path, excludes):
            continue
        code = base64.b64decode(f["content_base64"]).decode("utf-8", errors="ignore")
        file_item = {
            "repo": payload.get("repo"),
            "sha": payload.get("sha"),
            "path": path,
            "lang": f.get("lang", "unknown"),
            "content": code,
        }
        req = build_prompt(policy, file_item)
        resp = invoke_bedrock(req)
        for item in resp.get("findings", []):
            item.setdefault("file", path)
        findings_total.extend(resp.get("findings", []))

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "summary": {"count": len(findings_total)},
            "findings": findings_total[:50]
        }),
    }
// trigger
