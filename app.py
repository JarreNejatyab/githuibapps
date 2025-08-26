import os
import time
import hmac
import hashlib
import logging
import json
from pathlib import Path
from typing import Optional

from flask import Flask, request, abort, jsonify
from dotenv import load_dotenv
import jwt  # PyJWT
import requests
from pr_reviewer import review_pull_request  # AI PR review

# Load environment variables (default search: current working directory and parents)
load_dotenv()

APP_ID = os.getenv("APP_ID")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
ENTERPRISE_HOSTNAME = os.getenv("ENTERPRISE_HOSTNAME")  # e.g. ghe.example.com
PORT = int(os.getenv("PORT", "3000"))
MESSAGE_PATH = os.getenv("MESSAGE_PATH", "message.md")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

if not APP_ID or not PRIVATE_KEY_PATH or not WEBHOOK_SECRET:
    raise RuntimeError("Missing one of required env vars: APP_ID, PRIVATE_KEY_PATH, WEBHOOK_SECRET")

try:
    private_key = Path(PRIVATE_KEY_PATH).read_text(encoding="utf-8")
except FileNotFoundError as e:
    raise RuntimeError(f"Private key file not found at '{PRIVATE_KEY_PATH}'") from e
except Exception as e:
    raise RuntimeError(f"Failed reading private key: {e}") from e

message_for_new_prs = Path(MESSAGE_PATH).read_text(encoding="utf-8") if Path(MESSAGE_PATH).is_file() else "Thanks for your pull request!"  # fallback

# Base API URL (public GitHub or GHES)
if ENTERPRISE_HOSTNAME:
    API_BASE = f"https://{ENTERPRISE_HOSTNAME}/api/v3"
else:
    API_BASE = "https://api.github.com"

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("github-app")

app = Flask(__name__)


def create_jwt(app_id: str, key: str) -> str:
    """Create a JWT for the GitHub App authentication (valid 10 minutes)."""
    now = int(time.time())
    payload = {
        "iat": now - 60,        # issued at time (backdate 60s to allow clock drift)
        "exp": now + 9 * 60,    # max 10 minutes; use 9 to be safe
        "iss": app_id
    }
    encoded = jwt.encode(payload, key, algorithm="RS256")
    return encoded


def get_app_name() -> Optional[str]:
    try:
        token = create_jwt(APP_ID, private_key)
        r = requests.get(f"{API_BASE}/app", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }, timeout=10)
        if r.ok:
            return r.json().get("name")
        logger.warning("Failed to get app metadata: %s %s", r.status_code, r.text)
    except Exception as e:
        logger.warning("Error getting app name: %s", e)
    return None


def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    """Verify GitHub webhook signature (X-Hub-Signature-256)."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    provided = signature_header.split("=", 1)[1]
    # constant-time compare
    return hmac.compare_digest(expected, provided)


def create_installation_token(installation_id: int) -> str:
    jwt_token = create_jwt(APP_ID, private_key)
    url = f"{API_BASE}/app/installations/{installation_id}/access_tokens"
    r = requests.post(url, headers={
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json"
    }, timeout=15)
    if not r.ok:
        raise RuntimeError(f"Failed to create installation token: {r.status_code} {r.text}")
    return r.json()["token"]


def post_pr_comment(owner: str, repo: str, pr_number: int, body: str, installation_id: int):
    token = create_installation_token(installation_id)
    url = f"{API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"
    r = requests.post(url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }, json={"body": body}, timeout=15)
    if not r.ok:
        raise RuntimeError(f"Failed to create comment: {r.status_code} {r.text}")
    return r.json()


@app.route("/api/webhook", methods=["POST"])
def handle_webhook():
    raw = request.get_data()  # raw payload (bytes)
    signature_header = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(raw, signature_header):
        logger.warning("Signature verification failed")
        abort(401, description="Invalid signature")

    try:
        event = request.headers.get("X-GitHub-Event")
        payload = request.get_json(force=True, silent=False)
    except Exception:
        abort(400, description="Invalid JSON")

    logger.debug("Event received: %s action=%s", event, payload.get("action"))

    if event == "pull_request" and payload.get("action") == "opened":
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        installation = payload.get("installation", {})
        pr_number = pr.get("number")
        owner_login = repo.get("owner", {}).get("login")
        repo_name = repo.get("name")
        installation_id = installation.get("id")
        logger.info("Received pull_request.opened for #%s (%s/%s) installation %s", pr_number, owner_login, repo_name, installation_id)

        try:
            comment = post_pr_comment(owner_login, repo_name, pr_number, message_for_new_prs, installation_id)
            logger.info("Comment created: %s", comment.get("html_url"))
            # Attempt AI review (optional if Azure OpenAI configured)
            try:
                # Fetch files changed
                token_for_files = create_installation_token(installation_id)
                headers = {"Authorization": f"token {token_for_files}", "Accept": "application/vnd.github+json"}
                files_resp = requests.get(f"{API_BASE}/repos/{owner_login}/{repo_name}/pulls/{pr_number}/files", headers=headers, timeout=20)
                diff_text_parts = []
                file_names = []
                if files_resp.ok:
                    files_json = files_resp.json()
                    for f in files_json:
                        file_names.append(f.get("filename"))
                        patch = f.get("patch")
                        if patch:
                            diff_text_parts.append(f"File: {f.get('filename')}\n{patch}\n")
                diff_concat = "\n".join(diff_text_parts)
                pr_title = pr.get("title") or "(no title)"
                base_branch = pr.get("base", {}).get("ref", "?")
                head_branch = pr.get("head", {}).get("ref", "?")
                author = pr.get("user", {}).get("login", "?")
                review_markdown = review_pull_request(
                    repo_full_name=f"{owner_login}/{repo_name}",
                    pr_title=pr_title,
                    author=author,
                    base_branch=base_branch,
                    head_branch=head_branch,
                    changed_files=file_names,
                    diff=diff_concat,
                )
                if review_markdown:
                    ai_comment_body = f"### Automated PR Review\n\n{review_markdown}\n\n---\n_This review was generated by an AI assistant._"
                    post_pr_comment(owner_login, repo_name, pr_number, ai_comment_body, installation_id)
                    logger.info("AI review comment posted")
                else:
                    logger.info(
                        "AI review skipped (no review generated) | env_present=%s diff_chars=%d files=%d",
                        all([
                            os.getenv("AZURE_OPENAI_API_KEY"),
                            os.getenv("AZURE_OPENAI_ENDPOINT"),
                            os.getenv("AZURE_OPENAI_DEPLOYMENT")
                        ]),
                        len(diff_concat),
                        len(file_names)
                    )
            except Exception as e:
                logger.warning("AI review failed: %s", e)
        except Exception as e:
            logger.error("Error creating comment: %s", e)
            return jsonify({"status": "error", "error": str(e)}), 500
    else:
        logger.debug("Ignoring event / action combination")

    return jsonify({"status": "ok"})


@app.route("/health", methods=["GET"])
def health():  # simple health/diagnostic endpoint
    return jsonify({
        "status": "ok",
        "app_id": APP_ID,
        "api_base": API_BASE,
        "message_loaded": Path(MESSAGE_PATH).is_file(),
    })


if __name__ == "__main__":
    app_name = get_app_name()
    if app_name:
        logger.info("Authenticated as '%s'", app_name)
    # Log Azure OpenAI env var presence for diagnostics
    azure_status = {k: bool(os.getenv(k)) for k in [
        'AZURE_OPENAI_API_KEY', 'AZURE_OPENAI_ENDPOINT', 'AZURE_OPENAI_DEPLOYMENT'
    ]}
    logger.info("Azure OpenAI env status: %s", azure_status)
    if not all(azure_status.values()):
        logger.info("Azure OpenAI review disabled until all three vars are set.")
    logger.info("Listening on http://localhost:%s/api/webhook", PORT)
    logger.info("Health endpoint at http://localhost:%s/health", PORT)
    app.run(host="0.0.0.0", port=PORT)
