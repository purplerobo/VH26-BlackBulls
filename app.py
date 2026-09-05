import streamlit as st
import os
import sys
import base64
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))

from analyzer.checker import analyze_file

st.set_page_config(page_title="LeakGuard Dashboard", page_icon=":shield:", layout="wide")

st.title("LeakGuard - Resource Leak Detection Dashboard")
st.markdown("---")

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
scan_mode = st.sidebar.radio(
    "Scan mode",
    ["Directory", "Single File", "GitHub Repo"],
    horizontal=True
)

scan_target = None
scan_file = None
github_url = None

if scan_mode == "Directory":
    scan_target = st.sidebar.text_input("Target directory to scan", value="test_repo")
elif scan_mode == "Single File":
    scan_file = st.sidebar.text_input("Python file path", value="test_repo/obvious/fail_never_closed.py")
else:
    github_url = st.sidebar.text_input(
        "GitHub repo URL or owner/repo",
        value="purplerobo/VH26-BlackBulls",
        placeholder="owner/repo or full URL"
    )
    branch = st.sidebar.text_input("Branch (optional)", value="main")

run_scan = st.sidebar.button("Run AST Analysis", type="primary", use_container_width=True)

# ── LOAD ML MODELS LAZY ──────────────────────────────────────────────────────
@st.cache_resource
def load_ml():
    try:
        from ml_pipeline.predictor import get_leak_confidence, categorize_risk
        return get_leak_confidence, categorize_risk
    except Exception:
        return None, None

get_leak_confidence, categorize_risk = load_ml()

# ── GITHUB API HELPERS ───────────────────────────────────────────────────────
def parse_github_url(url_or_owner_repo):
    url_or_owner_repo = url_or_owner_repo.strip().rstrip("/")
    url_or_owner_repo = url_or_owner_repo.replace("https://github.com/", "")
    url_or_owner_repo = url_or_owner_repo.replace("http://github.com/", "")
    url_or_owner_repo = url_or_owner_repo.replace("github.com/", "")
    parts = url_or_owner_repo.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None, None

def fetch_github_tree(owner, repo, branch="main"):
    import urllib.request
    import json
    py_files = []

    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "LeakGuard-Dashboard")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            py_files = [item["path"] for item in data.get("tree", []) if item["path"].endswith(".py")]
            if py_files:
                return py_files
    except Exception:
        pass

    dirs_to_check = [""]
    while dirs_to_check:
        current = dirs_to_check.pop()
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{current}?ref={branch}"
        try:
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/vnd.github.v3+json")
            req.add_header("User-Agent", "LeakGuard-Dashboard")
            with urllib.request.urlopen(req) as resp:
                items = json.loads(resp.read().decode())
                for item in items:
                    if item["type"] == "file" and item["path"].endswith(".py"):
                        py_files.append(item["path"])
                    elif item["type"] == "dir":
                        dirs_to_check.append(item["path"])
        except Exception:
            continue

    return py_files

def fetch_github_file(owner, repo, filepath, branch="main"):
    import urllib.request
    import json
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}?ref={branch}"
    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "LeakGuard-Dashboard")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8")
            return data.get("content", "")
    except Exception:
        return None

# ── RUN SCAN AND STORE IN SESSION ────────────────────────────────────────────
if run_scan:
    all_findings = []
    safe_files = []

    if scan_mode == "Directory":
        if not scan_target or not os.path.exists(scan_target):
            st.error(f"Directory `{scan_target}` not found.")
            st.stop()
        for root, _, files in os.walk(scan_target):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    leaks = analyze_file(fpath)
                    if leaks:
                        all_findings.extend(leaks)
                    else:
                        safe_files.append(fpath)

    elif scan_mode == "Single File":
        if not scan_file or not os.path.exists(scan_file):
            st.error(f"File `{scan_file}` not found.")
            st.stop()
        leaks = analyze_file(scan_file)
        if leaks:
            all_findings.extend(leaks)
        else:
            safe_files.append(scan_file)

    else:
        owner, repo = parse_github_url(github_url)
        if not owner or not repo:
            st.error("Invalid GitHub URL. Use format: `owner/repo`")
            st.stop()

        with st.spinner(f"Fetching Python files from {owner}/{repo}..."):
            py_files = fetch_github_tree(owner, repo, branch)

        if not py_files:
            st.error(f"No Python files found in `{owner}/{repo}` (branch: `{branch}`).")
            st.stop()

        st.write(f"Found **{len(py_files)}** Python files. Scanning...")

        tmp_dir = tempfile.mkdtemp()
        try:
            for fpath in py_files:
                content = fetch_github_file(owner, repo, fpath, branch)
                if content is None:
                    continue

                local_path = os.path.join(tmp_dir, fpath)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                with open(local_path, "w", encoding="utf-8") as f:
                    f.write(content)

                leaks = analyze_file(local_path)
                display_path = f"{owner}/{repo}/{fpath}"
                if leaks:
                    for leak in leaks:
                        leak["file_name"] = display_path
                    all_findings.extend(leaks)
                else:
                    safe_files.append(display_path)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    st.session_state["findings"] = all_findings
    st.session_state["safe_files"] = safe_files
    st.session_state["definite"] = [f for f in all_findings if f["status"] == "LEAK"]
    st.session_state["uncertain"] = [f for f in all_findings if f["status"] == "UNCERTAIN"]

# ── RENDER FROM SESSION STATE ────────────────────────────────────────────────
definite = st.session_state.get("definite", [])
uncertain = st.session_state.get("uncertain", [])
safe_files = st.session_state.get("safe_files", [])
has_results = st.session_state.get("findings") is not None or st.session_state.get("safe_files") is not None

if not has_results:
    st.info("Configure a target in the sidebar and click **Run AST Analysis** to begin.")
    st.stop()

# ── SECTION 1: AST ENGINE REPORT ─────────────────────────────────────────────
st.header("AST Engine Baseline Report")
st.caption("Generated by LeakGuard AST engine - path-sensitive, control-flow-aware analysis")

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("Safe")
    st.metric("Files", len(safe_files))
    if safe_files:
        for fp in safe_files:
            st.success(f"`{fp}`")

with col2:
    st.subheader("Definite Leaks")
    st.metric("Files", len(definite))
    if definite:
        for item in definite:
            st.error(
                f"`{item['file_name']}` :red[**Line {item['line_number']}**] "
                f"- `{item['resource_name']}` - {item['leak_type']}"
            )
    else:
        st.success("No definite leaks detected.")

with col3:
    st.subheader("Uncertain Ownership")
    st.metric("Files", len(uncertain))
    if uncertain:
        for item in uncertain:
            st.warning(
                f"`{item['file_name']}` :orange[**Line {item['line_number']}**] "
                f"- `{item['resource_name']}` - {item['leak_type']}"
            )
    else:
        st.success("No uncertain cases.")

st.markdown("---")

# ── SECTION 2: ML RISK DASHBOARD ─────────────────────────────────────────────
st.header("ML Risk Categorization")
st.caption("Uncertain AST items scored by Random Forest model - categorized into HIGH / MEDIUM / LOW risk")

if not uncertain:
    st.info("No uncertain items to categorize.")
elif get_leak_confidence is None:
    st.warning("ML model not available. Train it first: `python ml_pipeline/train_model.py`")
else:
    high_risks = []
    medium_risks = []
    low_risks = []

    for item in uncertain:
        fname = item["file_name"]
        if "/" in fname and not os.path.exists(fname):
            entry = {
                **item,
                "confidence": None,
                "risk": {"tier": "N/A", "action": "SKIP", "label": "REMOTE FILE", "color": "", "reset": "", "confidence": 0},
            }
            low_risks.append(entry)
            continue
        conf = get_leak_confidence(fname)
        if conf is not None:
            risk = categorize_risk(conf)
            entry = {**item, "confidence": conf, "risk": risk}
            if risk["tier"] == "HIGH":
                high_risks.append(entry)
            elif risk["tier"] == "MEDIUM":
                medium_risks.append(entry)
            else:
                low_risks.append(entry)
    ml_col1, ml_col2, ml_col3 = st.columns(3)

    with ml_col1:
        st.subheader("High Risk")
        st.metric("Count", len(high_risks))
        if high_risks:
            for entry in high_risks:
                st.error(
                    f"`{entry['file_name']}` :red[**Line {entry['line_number']}**] "
                    f"- `{entry['resource_name']}`\n"
                    f"Confidence: {entry['confidence']:.1f}% | Action: {entry['risk']['action']}"
                )

    with ml_col2:
        st.subheader("Medium Risk")
        st.metric("Count", len(medium_risks))
        if medium_risks:
            for entry in medium_risks:
                st.warning(
                    f"`{entry['file_name']}` :orange[**Line {entry['line_number']}**] "
                    f"- `{entry['resource_name']}`\n"
                    f"Confidence: {entry['confidence']:.1f}% | Action: {entry['risk']['action']}"
                )

    with ml_col3:
        st.subheader("Low Risk")
        st.metric("Count", len(low_risks))
        if low_risks:
            for entry in low_risks:
                if entry["confidence"] is not None:
                    st.success(
                        f"`{entry['file_name']}` :green[**Line {entry['line_number']}**] "
                        f"- `{entry['resource_name']}`\n"
                        f"Confidence: {entry['confidence']:.1f}% | Action: {entry['risk']['action']}"
                    )
                else:
                    st.info(
                        f"`{entry['file_name']}` **Line {entry['line_number']}** "
                        f"- `{entry['resource_name']}` | Remote file (ML skipped)"
                    )

st.markdown("---")

# ── SECTION 3: INTERACTIVE AI REMEDIATION ────────────────────────────────────
st.header("AI-Powered Auto-Remediation")
st.caption("Uses Google Gemini to refactor leaking code into safe patterns")

fixable = [f for f in definite if f["status"] == "LEAK"]

if not fixable:
    st.info("No definite leaks to remediate.")
else:
    st.write(f"**{len(fixable)}** resource leak(s) detected. Do you want to use AI to resolve these?")

    for item in fixable:
        st.write(
            f"- `{item['file_name']}` **Line {item['line_number']}**: "
            f"`{item['resource_name']}` ({item['leak_type']})"
        )

    st.markdown("")
    resolve_btn = st.button("Resolve All Leaks with AI", type="primary", use_container_width=True)

    if resolve_btn:
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            st.error("GEMINI_API_KEY not set. Export it or add it to your environment.")
        else:
            try:
                from ml_pipeline.genai_patcher import generate_safe_code
            except ImportError:
                st.error(
                    "google-genai package not installed. Run:\n\n"
                    "```\npip install google-genai\n```"
                )
                st.stop()

            progress = st.progress(0)
            log_area = st.empty()

            for idx, item in enumerate(fixable):
                fpath = item["file_name"]
                line_num = item["line_number"]
                var_name = item["resource_name"]

                st.write(f"Processing `{fpath}` Line {line_num} - `{var_name}`...")

                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        original_lines = f.readlines()
                except (FileNotFoundError, OSError):
                    st.warning(f"File `{fpath}` is on GitHub (read-only). AI fix will show the suggested code only.")
                    st.info(
                        f"**Suggested fix for `{fpath}` Line {line_num}:**\n"
                        f"Wrap `{var_name}` in a `with` statement or `try/finally` block."
                    )
                    continue

                open_line = original_lines[line_num - 1]
                indent = len(open_line) - len(open_line.lstrip())
                indent_str = " " * indent

                st.info(
                    f"**Before** (`{fpath}:{line_num}`):\n"
                    f"```python\n{open_line.rstrip()}\n```"
                )

                log_area.text(
                    f"[{idx+1}/{len(fixable)}] Consulting GenAI for {fpath} Line {line_num}..."
                )

                safe_code = generate_safe_code(fpath, line_num, var_name)

                if safe_code:
                    try:
                        with open(fpath, "w", encoding="utf-8") as f:
                            f.write(safe_code)
                    except (OSError, PermissionError):
                        st.warning(f"Cannot write to GitHub file `{fpath}`. Showing suggested code:")
                        st.code(safe_code, language="python")
                        continue

                    with open(fpath, "r", encoding="utf-8") as f:
                        new_lines = f.readlines()

                    new_line = ""
                    if line_num - 1 < len(new_lines):
                        new_line = new_lines[line_num - 1].rstrip()

                    st.success(
                        f"**After** (`{fpath}:{line_num}`):\n"
                        f"```python\n{new_line}\n```"
                    )
                    st.write(f"Full file overwritten with refactored code.")
                else:
                    patch = f"{indent_str}{var_name}.close()  # [LeakGuard Auto-Patch]"
                    original_lines.insert(line_num, patch + "\n")
                    try:
                        with open(fpath, "w", encoding="utf-8") as f:
                            f.writelines(original_lines)
                    except (OSError, PermissionError):
                        st.warning(f"Cannot write to GitHub file `{fpath}`. Showing suggested patch:")
                        st.code(patch, language="python")
                        continue

                    new_line = original_lines[line_num].rstrip()
                    st.success(
                        f"**After** (`{fpath}:{line_num}`):\n"
                        f"```python\n{new_line}\n```"
                    )
                    st.write(f"Injected `{var_name}.close()` after line {line_num}.")

                progress.progress((idx + 1) / len(fixable))

            log_area.text("All leaks processed.")
            st.success("AI remediation complete.")
