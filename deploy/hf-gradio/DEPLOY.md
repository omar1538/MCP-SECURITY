# Deploying the live demo to Hugging Face Spaces (free, Gradio)

Hugging Face now gates the **Docker** Space SDK behind a paid plan, so the demo
ships as a **Gradio** Space, which is free. The Space holds three files from this
folder — `app.py`, `requirements.txt`, `README.md`. `requirements.txt` installs
the project from GitHub, so the Space stays small and tracks `main`.

Public URL once deployed:
`https://huggingface.co/spaces/<user>/mcp-security-gateway`
(direct app: `https://<user>-mcp-security-gateway.hf.space`).

## Option A — manual, no token needed (fastest)

You only need to be logged into huggingface.co in your browser.

1. <https://huggingface.co/new-space> → name `mcp-security-gateway`,
   **SDK: Gradio**, template **Blank**, **Hardware: CPU basic (free)**, Public, Create.
2. In the Space's **Files** tab, upload this folder's `app.py`, `requirements.txt`
   and `README.md` (drag-and-drop, or `git push` to the Space repo).
3. It builds automatically (installs deps, generates the data on boot) and goes live.

## Option B — automatic (GitHub Actions)

The workflow `.github/workflows/deploy-hf.yml` creates and updates the Space.

1. Create a Hugging Face **write** token: <https://huggingface.co/settings/tokens>.
2. GitHub repo → **Settings → Secrets and variables → Actions**:
   - secret **`HF_TOKEN`** = that token
   - (optional) variable **`HF_SPACE`** = `<your-hf-user>/mcp-security-gateway`.
3. **Actions → Deploy to Hugging Face Space → Run workflow.**

## Notes

- Runs in **scripted mode** (deterministic, no LLM, no secrets).
- First build takes a few minutes (it installs torch-free deps and generates the
  synthetic data). CPU basic (free) is enough.
- The Docker variant is still in `deploy/hf-space/` for anyone on a paid plan.
