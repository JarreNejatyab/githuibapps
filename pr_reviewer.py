import os
import logging
from typing import Optional, List
from openai import AzureOpenAI

logger = logging.getLogger("pr-reviewer")

# NOTE: We purposely DO NOT cache env vars at import time so that tests or the
# running process can inject them after the module loads. Always read them on demand.
DEFAULT_API_VERSION = "2024-05-01-preview"

SYSTEM_PROMPT = (
    "You are a concise, constructive GitHub Pull Request reviewer."
    " Return structured markdown with sections: \n"
    "- Summary\n- Strengths\n- Suggested Improvements (actionable, bullet list with inline code suggestions)\n"
    "- Risk / Edge Cases\n"
    "Keep it under 350 words. If diff is trivial, say so. Highlight any security or performance concerns clearly."
)


def _client() -> Optional[AzureOpenAI]:
    api_key = os.getenv("AZURE_OPENAI_API_KEY")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", DEFAULT_API_VERSION)

    if not (api_key and endpoint and deployment):
        missing = [name for name, val in [
            ("AZURE_OPENAI_API_KEY", api_key),
            ("AZURE_OPENAI_ENDPOINT", endpoint),
            ("AZURE_OPENAI_DEPLOYMENT", deployment)] if not val]
        logger.info("AI review disabled: missing env vars %s", ", ".join(missing))
        return None
    try:
        return AzureOpenAI(api_key=api_key, api_version=api_version, azure_endpoint=endpoint.rstrip("/"))
    except Exception as e:
        logger.warning("Failed to init AzureOpenAI client: %s", e)
        return None


def review_pull_request(
    repo_full_name: str,
    pr_title: str,
    author: str,
    base_branch: str,
    head_branch: str,
    changed_files: List[str],
    diff: str,
    diff_char_limit: int = 20000,
) -> Optional[str]:
    client = _client()
    if not client:
        logger.debug("No client available; skipping AI review")
        return None

    truncated = diff[:diff_char_limit]
    if len(diff) > diff_char_limit:
        truncated += "\n... (diff truncated)"

    user_content = f"""Repository: {repo_full_name}
PR Title: {pr_title}
Author: {author}
Base -> Head: {base_branch} -> {head_branch}
Changed Files:\n{os.linesep.join(changed_files) or '(none)'}

Unified Diff (possibly truncated):
```
{truncated}
```
"""

    try:
        # Re-read deployment + version for logging in case they changed
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", DEFAULT_API_VERSION)
        logger.debug("Invoking Azure OpenAI: deployment=%s ver=%s diff_chars=%d files=%d", deployment, api_version, len(diff), len(changed_files))
        response = client.chat.completions.create(
            model=deployment,
            temperature=0.2,
            top_p=0.9,
            max_tokens=900,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        )
        if not response or not getattr(response, 'choices', None):
            logger.info("AI review: empty response object")
            return None
        choice = response.choices[0]
        if not choice or not getattr(choice, 'message', None):
            logger.info("AI review: no message in first choice")
            return None
        content = choice.message.content
        if not content or not content.strip():
            logger.info("AI review: blank content returned")
            return None
        logger.debug("AI review: content length=%d", len(content))
        return content
    except Exception as e:
        logger.warning("AI review request failed: %s", e)
        return None
