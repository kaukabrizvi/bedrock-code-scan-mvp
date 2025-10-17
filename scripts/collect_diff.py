import os, subprocess, base64, json, re, sys
from pathlib import Path

SCANIGNORE_PATTERNS = [r"^bin/"]

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True).strip()

def safe_run(cmd):
    try:
        return run(cmd)
    except subprocess.CalledProcessError:
        return ""

def should_exclude(path):
    for pat in SCANIGNORE_PATTERNS:
        if re.search(pat, path):
            return True
    return False

def resolve_base_head():
    """
    Resolve a reliable base..head for PRs and local runs.
    Priority:
      1) PR base ref from env (GITHUB_BASE_REF) and GITHUB_SHA
      2) origin/main and HEAD
      3) merge-base(main, HEAD) and HEAD
      4) Fallback to HEAD~1 and HEAD
    """
    env_base = os.getenv("GITHUB_BASE_REF", "").strip()
    head = os.getenv("GITHUB_SHA", "").strip() or safe_run("git rev-parse HEAD")
    # Ensure we have the head commit locally
    if head:
        safe_run(f"git fetch --no-tags --depth=1000 origin {head}:{head} || true")

    if env_base:
        # fetch base ref defensively
        safe_run(f"git fetch --no-tags origin {env_base}:{env_base} || true")
        base = env_base
        # Convert branch name to full commit sha
        base_sha = safe_run(f"git rev-parse {base}")
        if base_sha:
            return base_sha, head

    # try origin/main
    if safe_run("git rev-parse origin/main"):
        base_sha = safe_run("git rev-parse origin/main")
        return base_sha, head

    # try local main
    if safe_run("git rev-parse main"):
        base_sha = safe_run("git rev-parse main")
        # compute merge-base for stability
        mb = safe_run(f"git merge-base {base_sha} {head}") or base_sha
        return mb, head

    # fallback: previous commit
    prev = safe_run("git rev-parse HEAD~1")
    if prev:
        return prev, head

    # nothing else worked
    return "", head

def get_changed_files(base, head):
    if base and head:
        out = safe_run(f"git diff --name-only {base}...{head}")
        if out:
            return [f for f in out.splitlines() if f]
    # Fallback to tracked files (initial commit, etc.)
    out = safe_run("git ls-files")
    return [f for f in out.splitlines() if f]

def main():
    base, head = resolve_base_head()
    files = get_changed_files(base, head)

    out = []
    for f in files:
        if not f or should_exclude(f) or not os.path.isfile(f):
            continue
        try:
            with open(f, "rb") as fh:
                content_b64 = base64.b64encode(fh.read()).decode("utf-8")
            lang = Path(f).suffix.lstrip(".") or "txt"
            out.append({"path": f, "lang": lang, "content_base64": content_b64})
        except Exception:
            # ignore unreadable files
            pass

    payload = {
        "repo": os.getenv("GITHUB_REPOSITORY", "unknown/repo"),
        "sha": head or "HEAD",
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
