# Sample GitHub App

This sample app showcases how webhooks can be used with a GitHub App's installation token to create a bot that responds to issues. Code uses [octokit.js](https://github.com/octokit/octokit.js).

## Requirements

### Common

- A GitHub App subscribed to **Pull Request** events and with the following permissions:
  - Pull requests: Read & write
  - Metadata: Read-only
- (For local development) A tunnel to expose your local server to the internet (e.g. [smee](https://smee.io/), [ngrok](https://ngrok.com/) or [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/tunnel-guide/local/))
- Your GitHub App Webhook must be configured to receive events at a URL that is accessible from the internet.

### Node.js version

- Node.js 20 or higher

### Python version (alternative implementation)

- Python 3.11 or higher
- `pip` / virtual environment tooling

## Setup

### 1. Clone the repository

```
git clone <this-repo-url>
cd github-app-js-sample
```

### 2. Environment variables

Create a `.env` file similar to `.env.example` and set actual values:

```
APP_ID=123456
PRIVATE_KEY_PATH=./<your-private-key>.pem
WEBHOOK_SECRET=your_webhook_secret
# Optional for GHES
# ENTERPRISE_HOSTNAME=ghe.example.com
```

### Node.js path

1. Install dependencies:
  ```
  npm install
  ```
2. Start the server:
  ```
  npm run server
  ```

### Python path (alternative)

1. Create and activate a virtual environment (recommended):
  ```
  python -m venv .venv
  source .venv/bin/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
  ```
2. Install Python dependencies:
  ```
  pip install -r requirements.txt
  ```
3. Start the Python server:
  ```
  python app.py
  ```

Both implementations listen on `http://localhost:3000/api/webhook` by default.

### 3. Expose locally (optional)

Ensure your server is reachable from the internet.
  - If you're using `smee`, run:
   ```
   smee -u <smee_url> -t http://localhost:3000/api/webhook
   ```

### 4. Install the App

Ensure your GitHub App includes at least one repository on its installations.

## Usage

With your server running, you can now create a pull request on any repository that
your app can access. GitHub will emit a `pull_request.opened` event and will deliver
the corresponding Webhook [payload](https://docs.github.com/webhooks-and-events/webhooks/webhook-events-and-payloads#pull_request) to your server.

The server in this example listens for `pull_request.opened` events and acts on
them by creating a comment on the pull request, with the message in `message.md`,
using the [octokit.js rest methods](https://github.com/octokit/octokit.js#octokitrest-endpoint-methods).

In the Python implementation the same behavior is achieved with direct REST calls via the `requests` library, constructing a JWT for the App and exchanging it for an installation access token before posting the comment.

## Security considerations

To keep things simple, this example reads the `GITHUB_APP_PRIVATE_KEY` from the
environment. A more secure and recommended approach is to use a secrets management system
like [Vault](https://www.vaultproject.io/use-cases/key-management), or one offered
by major cloud providers:
[Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-node?tabs=windows),
[AWS Secrets Manager](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-secrets-manager/),
[Google Secret Manager](https://cloud.google.com/nodejs/docs/reference/secret-manager/latest),
etc.
