# repro-git-hook

A passive, out-of-band audit logger for AI-assisted scientific computing and regulated environments. 

This tool enforces reproducibility and security rules and automatically generates a human-readable, git-tracked audit trail of your AI prompts, decisions, and environment state at every commit.

---

## The Problem: "In-Band" Logging is Buggy

AI coding assistants are increasingly used in regulated workflows, but standard implementations of audit trails rely on **"In-band logging"** (e.g., using MCP tools where the LLM is instructed to call a `log_decision` function). 

This is fundamentally flawed: When an LLM is deep in the weeds debugging a complex issue, its attention is entirely consumed by the code. It inevitably "forgets" to call the logging tool, leading to fragmented or missing audit trails. Furthermore, relying on brittle IDE hooks to trigger these tools often breaks.

## The Solution: "Out-of-Band" Git Hooks

`repro-git-hook` shifts the auditing process entirely out-of-band. It hooks directly into the Git lifecycle via `pre-commit`.

1. **You write code with your AI Assistant** as usual. The IDE quietly logs the conversation transcript in the background.
2. **You run `git commit`**.
3. **The Pre-Commit Hook** intercepts the commit and runs `auditor.py`.
4. **Agent-First Linting**: The script scans the codebase for reproducibility and security violations. Instead of brutally blocking your commit, it logs these as `[WARNING]` alerts in an audit file, leaving a roadmap of technical debt for an AI agent to clean up later.
5. **Audit Generation**: The script extracts your latest AI interaction logs, snapshots your environment, and writes a gorgeous Markdown file to `.repro/logs/YYYY-MM-DD.md`.
6. **Auto-Add**: The `.repro/` directory is automatically added to the current commit.

Your code and the underlying "reasoning" (the AI prompt/response log) are permanently locked together in the same commit hash.

---

## Features

### Reproducibility Checks
* **`random-seed`**: Scans Python/R files and flags RNG usage if seeds (e.g., `set.seed()`, `np.random.seed`) are missing.
* **`env-pinned`**: Warns if `requirements.txt` or `environment.yml` contains unpinned dependencies.
* **`no-hardcoded-paths`**: Checks string literals for absolute system paths (`C:\`, `/usr/`, `/home/`).
* **`no-inplace-data-mutation`**: Flags writes to `data/raw` directories to prevent accidental raw data mutation.

### Security Checks
Scans all files for accidental inclusions of secrets before they are immortalized in git history:
* SSH / RSA Private Keys
* GitHub Tokens
* AWS Credentials
* Generic API keys

---

## Installation & Usage

1. Copy `auditor.py` into your project (e.g., into a `scripts/` or `tools/` directory).
2. Create or append to your `.git/hooks/pre-commit` file:

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run the auditor script
python "scripts/auditor.py" pre-commit
```

3. Make the hook executable (Unix/macOS):
```bash
chmod +x .git/hooks/pre-commit
```

Now, every time you run `git commit`, an audit log will be automatically generated in `.repro/logs/` and included in your commit!

---

## Log Format

Each commit generates a `.repro/logs/YYYY-MM-DDTHHMMSS.md` file:

```markdown
# Session Log: 2026-05-16T103554

**Git hash:** a3f9c12d8e41

## Reproducibility & Security Checks
> [!WARNING]
> **Agent Action Required:** The following issues were detected. They did not block the commit, but should be addressed for reproducibility.
> * 🚨 **no-secrets**: Potential SSH/RSA Private Key detected! (`config/deploy.yml:14`)
> * ⚠️ **no-inplace-data-mutation**: Potential mutation of raw data directory found. (`scripts/process.R:42`)

## Recent AI Interaction Context
```text
Prompt: Can you help me write a function to download the dataset?
Assistant: Sure, here is the function...
```

## Environment Snapshot
- OS: posix
- Python: 3.11.4
```
