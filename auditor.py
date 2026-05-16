import argparse
import ast
import json
import os
import re
import subprocess
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

# --- Logger functionality ---

def get_env_state():
    """Captures the current environment state for reproducibility."""
    env_state = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "os": os.name,
        "python_version": sys.version,
    }
    
    try:
        git_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        env_state["git_commit"] = git_hash.decode("utf-8").strip()
    except Exception:
        env_state["git_commit"] = "Not a git repository"
        
    try:
        pip_freeze = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], stderr=subprocess.DEVNULL)
        env_state["pip_freeze"] = pip_freeze.decode("utf-8").splitlines()
    except Exception:
        env_state["pip_freeze"] = []
        
    return env_state

# --- Linter functionality ---

def check_secrets(filepath):
    """Checks for accidental inclusion of secrets like SSH keys or API tokens."""
    issues = []
    secret_patterns = {
        "SSH/RSA Private Key": r"-----BEGIN .* PRIVATE KEY-----",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic Secret": r"api_key\s*=\s*['\"][a-zA-Z0-9_-]{16,}['\"]"
    }
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines, 1):
            for secret_name, pattern in secret_patterns.items():
                if re.search(pattern, line):
                    issues.append({"rule": "no-secrets", "severity": "error", "file": str(filepath), "line": i, "msg": f"Potential {secret_name} detected!"})
    except Exception:
        pass
    return issues

def check_env_pinned(directory):
    issues = []
    req_file = Path(directory) / "requirements.txt"
    if req_file.exists():
        with open(req_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    if "==" not in line and ">=" not in line and "~=" not in line:
                        issues.append({"rule": "env-pinned", "severity": "warn", "file": "requirements.txt", "line": line_num, "msg": f"Unpinned dependency: {line}"})
    return issues

def check_python_file(filepath):
    issues = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
            
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=SyntaxWarning)
            tree = ast.parse(source)
        
        has_random_import = False
        has_random_seed = False
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) or isinstance(node.ImportFrom):
                # Simplified check for demo
                pass
                        
            # Check hardcoded paths in strings
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                if re.match(r"^(/usr|/home|/var|/etc|C:\\|D:\\)", val, re.IGNORECASE):
                    issues.append({"rule": "no-hardcoded-paths", "severity": "error", "file": str(filepath), "line": getattr(node, 'lineno', 0), "msg": f"Hardcoded absolute path found: {val[:30]}..."})
                if re.search(r"data/raw.*", val, re.IGNORECASE):
                    issues.append({"rule": "no-inplace-data-mutation", "severity": "warn", "file": str(filepath), "line": getattr(node, 'lineno', 0), "msg": f"Reference to raw data directory found: {val[:30]}..."})
    except Exception:
        pass
    return issues

def check_r_file(filepath):
    issues = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        has_set_seed = False
        has_rnorm = False
        
        for i, line in enumerate(lines, 1):
            line_strip = line.strip()
            if line_strip.startswith("#"): continue
            if "set.seed(" in line: has_set_seed = True
            if re.search(r"\b(rnorm|runif|sample|rbinom|rpois|rexp|rgamma)\b", line): has_rnorm = True
            
            if re.search(r"['\"](/usr|/home|/var|/etc|[a-zA-Z]:[\\/])", line):
                issues.append({"rule": "no-hardcoded-paths", "severity": "error", "file": str(filepath), "line": i, "msg": "Hardcoded absolute path found."})
                
            if re.search(r"['\"]data/raw.*?['\"]", line, re.IGNORECASE) and ("write" in line or "save" in line or "<-" in line):
                issues.append({"rule": "no-inplace-data-mutation", "severity": "warn", "file": str(filepath), "line": i, "msg": "Potential mutation of raw data directory found."})
                
        if has_rnorm and not has_set_seed:
            issues.append({"rule": "random-seed", "severity": "error", "file": str(filepath), "line": 0, "msg": "RNG function used but set.seed() not found in file."})
    except Exception:
        pass
    return issues

def lint_directory(directory):
    all_issues = []
    all_issues.extend(check_env_pinned(directory))
    
    for root, _, files in os.walk(directory):
        if ".git" in root or "__pycache__" in root or ".venv" in root or "renv" in root or ".repro" in root:
            continue
        for file in files:
            filepath = Path(root) / file
            
            # Universal secret check on all files
            all_issues.extend(check_secrets(filepath))
            
            if file.endswith(".py"):
                all_issues.extend(check_python_file(filepath))
            elif file.endswith((".R", ".Rmd", ".qmd")):
                all_issues.extend(check_r_file(filepath))
                
    return all_issues

# --- Antigravity Integration ---

def get_latest_antigravity_log():
    """Finds the most recent Antigravity conversation log."""
    app_data = Path(os.environ.get("USERPROFILE", "C:\\Users\\bindoffa")) / ".gemini" / "antigravity" / "brain"
    if not app_data.exists():
        return "No recent AI interactions found."
        
    # Find most recently modified conversation directory
    dirs = [d for d in app_data.iterdir() if d.is_dir() and (d / ".system_generated" / "logs" / "overview.txt").exists()]
    if not dirs:
        return "No recent AI logs found."
        
    latest_dir = max(dirs, key=lambda d: d.stat().st_mtime)
    log_file = latest_dir / ".system_generated" / "logs" / "overview.txt"
    
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            # Return last 30 lines as a proxy for the latest exchange
            return "".join(lines[-30:])
    except Exception:
        return "Failed to parse recent AI log."

def run_pre_commit(target_dir=None):
    """Executes the pre-commit workflow: linting, gathering logs, and writing to .repro/"""
    print("Running AI Reproducibility Auditor (Agent-First Mode)...")
    
    is_git = True
    if target_dir:
        repo_root = str(Path(target_dir).resolve())
        try:
            subprocess.check_output(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_root, stderr=subprocess.DEVNULL)
        except Exception:
            is_git = False
            print(f"Info: Provided directory is not a git repository. Git integration disabled.")
    else:
        try:
            repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL).decode("utf-8").strip()
        except Exception:
            print("Error: Not running inside a git repository. Please run inside a repo or explicitly provide a directory: python auditor.py pre-commit <path>")
            sys.exit(1)
        
    print(f"Scanning directory: {repo_root}")
    issues = lint_directory(repo_root)
    env_state = get_env_state()
    ai_log_snippet = get_latest_antigravity_log()
    
    # Generate the Markdown Report
    repro_dir = Path(repo_root) / ".repro" / "logs"
    repro_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp_str = datetime.now().strftime("%Y-%m-%dT%H%M%S")
    report_path = repro_dir / f"{timestamp_str}.md"
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Session Log: {timestamp_str}\n\n")
        f.write(f"**Git hash:** {env_state['git_commit']}\n\n")
        
        f.write("## Reproducibility & Security Checks\n")
        if not issues:
            f.write("✅ All checks passed.\n\n")
        else:
            f.write("> [!WARNING]\n")
            f.write("> **Agent Action Required:** The following issues were detected. They did not block the commit, but should be addressed for reproducibility.\n\n")
            for issue in issues:
                icon = "🚨" if issue['severity'] == 'error' else "⚠️"
                f.write(f"* {icon} **{issue['rule']}**: {issue['msg']} (`{issue['file']}:{issue['line']}`)\n")
        f.write("\n")
        
        f.write("## Recent AI Interaction Context\n")
        f.write("```text\n")
        f.write(ai_log_snippet)
        f.write("\n```\n\n")
        
        f.write("## Environment Snapshot\n")
        f.write(f"- OS: {env_state['os']}\n")
        f.write(f"- Python: {env_state['python_version']}\n")
        
    print(f"Audit log generated at {report_path}")
    
    # Auto-add the .repro directory to the current commit if in a git repo
    if is_git:
        try:
            subprocess.check_output(["git", "add", ".repro/"], cwd=repo_root, stderr=subprocess.DEVNULL)
            print("Successfully added .repro/ to the commit.")
        except Exception as e:
            print(f"Warning: Could not automatically git add .repro/: {e}")

def main():
    parser = argparse.ArgumentParser(description="AI Workflow Auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    lint_parser = subparsers.add_parser("lint")
    lint_parser.add_argument("directory", nargs="?", default=".")
    
    precommit_parser = subparsers.add_parser("pre-commit")
    precommit_parser.add_argument("directory", nargs="?", default=None)
    
    args = parser.parse_args()
    
    if args.command == "lint":
        issues = lint_directory(args.directory)
        for issue in issues:
            print(f"[{issue['severity'].upper()}] {issue['rule']}: {issue['msg']} ({issue['file']}:{issue['line']})")
    elif args.command == "pre-commit":
        run_pre_commit(args.directory)

if __name__ == "__main__":
    main()
