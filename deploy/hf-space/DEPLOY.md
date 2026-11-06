# Deploying the live demo to Hugging Face Spaces

The demo is a Docker Space. The Space holds just two files — `Dockerfile` and
`README.md` (both in this folder) — and the Dockerfile pulls the code from GitHub
at build time, so the Space stays tiny and always tracks `main`.

Public URL once deployed: `https://huggingface.co/spaces/<user>/mcp-security-gateway`
(direct app: `https://<user>-mcp-security-gateway.hf.space`).

## Option A — automatic (GitHub Actions, recommended)

The workflow `.github/workflows/deploy-hf.yml` creates and updates the Space for you.

1. Create a Hugging Face **write** token: <https://huggingface.co/settings/tokens>.
2. In the GitHub repo: **Settings → Secrets and variables → Actions**
   - add a secret **`HF_TOKEN`** = that token
   - (optional) add a variable **`HF_SPACE`** = `<your-hf-user>/mcp-security-gateway`
     (defaults to `omar1504/mcp-security-gateway`).
3. **Actions → Deploy to Hugging Face Space → Run workflow.**

It creates the Space if needed and uploads the two files; HF builds and serves it.
Every later change to `deploy/hf-space/**` re-deploys automatically.

## Option B — manual (3 clicks)

1. <https://huggingface.co/new-space> → name `mcp-security-gateway`, **SDK: Docker**
   (blank template), visibility Public, Create.
2. Upload this folder's `Dockerfile` and `README.md` to the Space (drag-and-drop
   in the Space's **Files** tab, or `git push` to the Space repo).
3. The Space builds automatically and goes live.

## Notes

- The demo runs in **scripted mode** (deterministic, no LLM, no secrets needed).
- To enable **live-LLM mode** on the Space, add Space **Settings → Variables and
  secrets**: `MSG_LLM_BASE_URL`, `MSG_LLM_MODEL`, `MSG_LLM_API_KEY`.
- Free CPU hardware is enough; the app uses little memory and no GPU.
