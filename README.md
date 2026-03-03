# 🛡️ Wi-Fi Fuzzer Crash Analysis Toolkit

A pair of Python modules for automated crash analysis and intelligence reporting during 802.11/WPA2/WPA3 fuzzing sessions.

---

## 📁 Modules

| File | Purpose |
|------|---------|
| `crash_explainer.py` | LLM-powered crash report generation from fuzzing logs |
| `log_intelligence.py` | Statistical crash aggregation and intelligence summary |

---

## 📋 Requirements

Install dependencies:

```bash
pip install langchain-core langchain-openai langchain-google-genai langchain-groq python-dotenv
```

Set up your `.env` file with the appropriate API key:

```env
# For Groq (default)
GROQ_API_KEY=your_key_here

# For OpenAI
OPENAI_API_KEY=your_key_here

# For Gemini
GOOGLE_API_KEY=your_key_here
```

---

## 🗂️ Expected Log Directory Structure

```
Logs/
├── fuzz_mngmt_frames/
│   ├── Aliveness_check_<timestamp>.log
│   └── frames_till_disr_<timestamp>.log
├── fuzz_ctrl_frames/
│   ├── Aliveness_check_<timestamp>.log
│   └── frames_till_disr_<timestamp>.log
└── fuzz_data_frames/
    ├── Aliveness_check_<timestamp>.log
    └── frames_till_disr_<timestamp>.log
```

- **`Aliveness_check_*`** — Logs written when a crash/disruption is detected. Each line with a `HH:MM:SS:` timestamp is treated as a crash event.
- **`frames_till_disr_*`** — Logs listing frames sent before a disruption occurred. Line count = frames before crash.

---

## 🔍 crash_explainer.py

### Overview

Uses an LLM to analyze raw fuzzing log content and produce a structured security crash report. Supports OpenAI, Google Gemini, and Groq as LLM backends.

### LLM Providers

| Provider | Model | Set via |
|----------|-------|---------|
| `groq` *(default)* | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| `gemini` | `gemini-2.0-flash` | `GOOGLE_API_KEY` |

### Generated Report Format

Each analyzed log produces a report in the following structure:

```
==== FUZZING CRASH REPORT ====

Summary:           — ≤50 words, high-level crash overview
Technical Analysis: — ~200 words with log snippets, frame fields, root cause, vulnerability class
Impact:            — ≤30 words, security implication
CVE Correlation:   — Specific CVE ID or "No match found"
Confidence Level:  — High | Medium | Low

================================
```

### Key Functions

#### `handle_crash()`
Interactive menu triggered when connectivity loss is detected:

```
[A] Analyze with LLM         → runs generate_crash_report()
[C] Close Fuzzing and Exit   → exits the program
[L] Log Intelligence         → runs CrashIntelligence analysis
[R] Resume without analysis  → continues fuzzing
```

#### `generate_crash_report(provider="groq")`
Automatically finds all `Aliveness_check_*` files across the three log directories, analyzes each with the LLM, and prints structured reports to stdout.

#### `explain_crash(log_content, llm)`
Lower-level function. Accepts raw log text and a LangChain LLM instance; returns a formatted crash report string.

#### `load_llm(provider)`
Returns a LangChain-compatible LLM instance for the specified provider.

---

## 📊 log_intelligence.py

### Overview

Scans all `fuzz_*` subdirectories under `Logs/` and produces a statistical intelligence summary — no LLM required. Useful for a fast, quantitative view of crash patterns.

### Usage

```python
from log_intelligence import CrashIntelligence

ci = CrashIntelligence()          # defaults to "Logs/" root
report = ci.analyze()
print(report)
```

Or with a custom log root:

```python
ci = CrashIntelligence(root_directory="path/to/logs")
```

### Output Format

```
==== FUZZING INTELLIGENCE SUMMARY ====

Total Crash Events: <N>

Frame Type Instability Ranking:
- <frame_type>: <count>
- ...

Sensitive Fields Ranking:
- <field_name>: <count>
- ...

Average Frames Before Disruption: <value>
Crash Density Score: <value> crashes/frame
Field Diversity Index: <value>

======================================
```

### Metrics Explained

| Metric | Description |
|--------|-------------|
| **Total Crash Events** | Count of timestamped crash lines across all `Aliveness_check_*` files |
| **Frame Type Instability Ranking** | Frame types most frequently associated with crashes (parsed from `"sending X frames"` patterns) |
| **Sensitive Fields Ranking** | Malformed fields most often linked to crashes (parsed from `"malformed X"` patterns) |
| **Average Frames Before Disruption** | Mean line count across all `frames_till_disr_*` files |
| **Crash Density Score** | `total_crashes / avg_frames` — higher = more crashes per frame sent |
| **Field Diversity Index** | `unique_malformed_fields / total_crashes` — higher = crashes spread across more field types |

---

## 🔗 Integration

Both modules are designed to work together. `crash_explainer.py` calls `CrashIntelligence` directly when the user selects option `[L]` in the `handle_crash()` menu:

```python
from log_intelligence import CrashIntelligence

ci = CrashIntelligence()
print(ci.analyze())
```

---

## 📝 Notes

- The LLM prompt is tuned for 802.11 wireless security analysis. It expects logs that may include protocol state markers such as `UNAUTHENTICATED`, `AUTHENTICATED`, `ASSOCIATED`, `CONNECTED`, or `DISRUPTED`.
- All three log directories (`fuzz_mngmt_frames`, `fuzz_ctrl_frames`, `fuzz_data_frames`) are optional — missing directories are safely skipped.
- `CrashIntelligence` only scans directories that start with `fuzz_` under the log root, ignoring unrelated folders.
