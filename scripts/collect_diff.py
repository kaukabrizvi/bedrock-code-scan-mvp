import os, subprocess, base64, json, re
from pathlib import Path

SCANIGNORE_PATTERNS = [r"^bin/"]

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True).strip()

def should_exclude(path):
    for pat in SCANIGNORE_PATTERNS:
        if re.search(pat, path):
            return True
    return False

def main():
    # default to comparing current branch to origin/main
    base = os.getenv("GITHUB_BASE_REF") or "origin/main"
    head = os.getenv("GITHUB_SHA") or "HEAD"
    try:
        files = run(f'git diff --name-only {base}...{head}').splitlines()
    except subprocess.CalledProcessError:
        files = run('git ls-files').splitlines()

    out = []
    for f in files:
        if not f or should_exclude(f) or not os.path.isfile(f):
            continue
        with open(f, "rb") as fh:
            content_b64 = base64.b64encode(fh.read()).decode("utf-8")
        lang = Path(f).suffix.lstrip(".") or "txt"
        out.append({"path": f, "lang": lang, "content_base64": content_b64})

    payload = {
        "repo": os.getenv("GITHUB_REPOSITORY", "unknown/repo"),
        "sha": head,
        "files": out
    }

    if os.path.exists("policy.scan.yaml"):
        try:
            import yaml
            with open("policy.scan.yaml", "r") as yf:
                payload["repo_policy"] = yaml.safe_load(yf)
        except Exception:
            pass

    print(json.dumps(payload))

if __name__ == "__main__":
    main()
