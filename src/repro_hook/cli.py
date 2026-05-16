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

def get_env_state(repo_root="."):
    """Captures the current environment state for reproducibility."""
    env_state = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "os": os.name,
        "python_version": sys.version,
    }
    
    try:
        git_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, stderr=subprocess.DEVNULL)
        env_state["git_commit"] = git_hash.decode("utf-8").strip()
    except Exception:
        env_state["git_commit"] = "Not a git repository"
        
    try:
        pip_freeze = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], stderr=subprocess.DEVNULL)
        env_state["pip_freeze"] = pip_freeze.decode("utf-8").splitlines()
    except Exception:
        env_state["pip_freeze"] = []
        
    # Detect R Environment
    root_path = Path(repo_root)
    # Check for R files in root or immediately obvious signs of an R project
    if list(root_path.glob("*.Rproj")) or list(root_path.glob("*.R")) or list(root_path.glob("*.Rmd")):
        try:
            r_version = subprocess.check_output(["Rscript", "--version"], stderr=subprocess.STDOUT).decode("utf-8").strip()
            env_state["R_version"] = r_version
        except Exception:
            env_state["R_version"] = "Rscript not found in PATH"
            
        try:
            r_session = subprocess.check_output(["Rscript", "-e", "sessionInfo()"], cwd=repo_root, stderr=subprocess.DEVNULL).decode("utf-8").strip()
            env_state["R_session_info"] = r_session
        except Exception:
            env_state["R_session_info"] = "Could not capture sessionInfo()"
            
        if (root_path / "renv.lock").exists():
            env_state["R_env_manager"] = "renv.lock present"
        else:
            env_state["R_env_manager"] = "No renv.lock found"
            
    # Detect Rust Environment
    if (root_path / "Cargo.toml").exists() or list(root_path.glob("**/*.rs")):
        try:
            env_state["Rust_version"] = subprocess.check_output(["rustc", "--version"], stderr=subprocess.STDOUT).decode("utf-8").strip()
            env_state["Cargo_version"] = subprocess.check_output(["cargo", "--version"], stderr=subprocess.STDOUT).decode("utf-8").strip()
        except Exception:
            env_state["Rust_version"] = "rustc/cargo not found in PATH"
            
    # Detect C/C++ Environment
    if (root_path / "CMakeLists.txt").exists() or list(root_path.glob("**/*.cpp")) or list(root_path.glob("**/*.c")):
        try:
            env_state["CMake_version"] = subprocess.check_output(["cmake", "--version"], stderr=subprocess.STDOUT).decode("utf-8").splitlines()[0]
        except Exception:
            pass
        try:
            # Try gcc
            env_state["C++_compiler"] = subprocess.check_output(["g++", "--version"], stderr=subprocess.STDOUT).decode("utf-8").splitlines()[0]
        except Exception:
            try:
                # Fallback to clang
                env_state["C++_compiler"] = subprocess.check_output(["clang++", "--version"], stderr=subprocess.STDOUT).decode("utf-8").splitlines()[0]
            except Exception:
                pass
            
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
                    if "==" not in line:
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
            if isinstance(node, ast.Import):
                for name in node.names:
                    if name.name in ["random", "numpy", "torch"]: has_random_import = True
            elif isinstance(node, ast.ImportFrom):
                if node.module in ["numpy", "torch", "random"]: has_random_import = True
                    
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ["seed", "manual_seed"]: has_random_seed = True
                        
            # Check hardcoded paths in strings
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                if re.match(r"^(/usr|/home|/var|/etc|[a-zA-Z]:\\|[a-zA-Z]:/)", val, re.IGNORECASE):
                    issues.append({"rule": "no-hardcoded-paths", "severity": "error", "file": str(filepath), "line": getattr(node, 'lineno', 0), "msg": f"Hardcoded absolute path found: {val[:30]}..."})
                if re.search(r"data/raw.*", val, re.IGNORECASE):
                    issues.append({"rule": "no-inplace-data-mutation", "severity": "warn", "file": str(filepath), "line": getattr(node, 'lineno', 0), "msg": f"Reference to raw data directory found: {val[:30]}..."})
                    
        if has_random_import and not has_random_seed:
            issues.append({"rule": "random-seed", "severity": "error", "file": str(filepath), "line": 0, "msg": "RNG module imported but no seed set in scope."})
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

# --- AI Agent Integration ---

def get_latest_ai_log(repo_root):
    """Attempts to find the most recent AI conversation log from known open-format agents."""
    
    # 1. Check Antigravity
    ag_app_data = Path.home() / ".gemini" / "antigravity" / "brain"
    if ag_app_data.exists():
        dirs = [d for d in ag_app_data.iterdir() if d.is_dir() and (d / ".system_generated" / "logs" / "overview.txt").exists()]
        if dirs:
            latest_dir = max(dirs, key=lambda d: d.stat().st_mtime)
            log_file = latest_dir / ".system_generated" / "logs" / "overview.txt"
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    return "".join(f.readlines()[-30:]), True
            except Exception:
                pass
                
    # 2. Add future parsers here (e.g., Cline JSON logs)
    
    # 3. Fallback Agent Prompt
    fallback_msg = (
        "> [!NOTE]\n"
        "> **Transcript Unavailable:** No local open-format AI transcripts (e.g., Antigravity, Cline) were found for this commit.\n"
        "> If the user is using Cursor, Copilot, or RStudio, their AI logs are likely stored in proprietary or encrypted databases.\n"
        "> \n"
        "> 🤖 **To the AI Agent reading this log in the future:**\n"
        "> Please ask the user to briefly summarize the reasoning behind this commit so you can append it here. "
        "Alternatively, if you know how to extract the chat history from the user's current IDE, you are encouraged to write a Python parser "
        "and add it to the `get_latest_ai_log()` function in `auditor.py`!"
    )
    return fallback_msg, False

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
    env_state = get_env_state(repo_root)
    ai_log_snippet, is_raw_text = get_latest_ai_log(repo_root)
    
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
        if is_raw_text:
            f.write("```text\n")
            f.write(ai_log_snippet)
            f.write("\n```\n\n")
        else:
            f.write(ai_log_snippet + "\n\n")
        
        f.write("## Environment Snapshot\n")
        f.write(f"- OS: {env_state['os']}\n")
        
        has_specific_env = False
        if "R_version" in env_state:
            has_specific_env = True
            f.write(f"- R Version: {env_state['R_version']}\n")
            f.write(f"- R Environment: {env_state.get('R_env_manager', 'Unknown')}\n")
            f.write("\n<details><summary>R sessionInfo()</summary>\n\n```text\n")
            f.write(env_state.get('R_session_info', ''))
            f.write("\n```\n</details>\n")
            
        if "Rust_version" in env_state:
            has_specific_env = True
            f.write(f"- Rust Version: {env_state['Rust_version']}\n")
            if "Cargo_version" in env_state:
                f.write(f"- Cargo Version: {env_state['Cargo_version']}\n")
                
        if "C++_compiler" in env_state or "CMake_version" in env_state:
            has_specific_env = True
            if "C++_compiler" in env_state:
                f.write(f"- C++ Compiler: {env_state['C++_compiler']}\n")
            if "CMake_version" in env_state:
                f.write(f"- CMake Version: {env_state['CMake_version']}\n")
                
        if not has_specific_env:
            # Fallback to python if no other primary languages are detected
            f.write(f"- Python: {env_state.get('python_version', 'Unknown')}\n")
        
    print(f"Audit log generated at {report_path}")
    
    # Auto-add the .repro directory to the current commit if in a git repo
    if is_git:
        try:
            subprocess.check_output(["git", "add", ".repro/"], cwd=repo_root, stderr=subprocess.DEVNULL)
            print("Successfully added .repro/ to the commit.")
        except Exception as e:
            print(f"Warning: Could not automatically git add .repro/: {e}")

def install_hook():
    """Installs the pre-commit hook into the current git repository."""
    try:
        repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL).decode("utf-8").strip()
    except Exception:
        print("Error: Not inside a git repository. Please run this command from the root of your project.")
        sys.exit(1)
        
    hook_dir = Path(repo_root) / ".git" / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    
    hook_file = hook_dir / "pre-commit"
    hook_content = (
        "#!/bin/bash\n"
        "# .git/hooks/pre-commit\n\n"
        "# Run the auditor securely and ephemerally from GitHub\n"
        "uvx --from git+https://github.com/ABindoff/repro-git-hook repro-hook pre-commit\n"
    )
    
    with open(hook_file, "w", encoding="utf-8") as f:
        f.write(hook_content)
        
    # Make executable on Unix
    if os.name == "posix":
        os.chmod(hook_file, 0o755)
        
    print(f"✅ Successfully installed repro-git-hook into {hook_file}")

def main():
    parser = argparse.ArgumentParser(description="AI Workflow Auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    lint_parser = subparsers.add_parser("lint")
    lint_parser.add_argument("directory", nargs="?", default=".")
    
    precommit_parser = subparsers.add_parser("pre-commit")
    precommit_parser.add_argument("directory", nargs="?", default=None)
    
    install_parser = subparsers.add_parser("install", help="Installs the pre-commit hook into the current Git repository")
    
    args = parser.parse_args()
    
    if args.command == "lint":
        issues = lint_directory(args.directory)
        for issue in issues:
            print(f"[{issue['severity'].upper()}] {issue['rule']}: {issue['msg']} ({issue['file']}:{issue['line']})")
    elif args.command == "pre-commit":
        run_pre_commit(args.directory)
    elif args.command == "install":
        install_hook()

if __name__ == "__main__":
    main()
