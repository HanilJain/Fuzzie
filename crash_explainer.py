import os
import sys
from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from log_intelligence import CrashIntelligence

load_dotenv()

LOG_DIRECTORIES = [
    "Logs/fuzz_mngmt_frames",
    "Logs/fuzz_ctrl_frames",
    "Logs/fuzz_data_frames"
]


CRASH_ANALYSIS_PROMPT = """
You are a wireless security expert specializing in 802.11, WPA2/WPA3, and Wi-Fi protocol vulnerabilities.

You are given raw fuzzing logs from a WPA/802.11 fuzzer (management, control, or data frames).

The logs may include protocol state information (e.g., UNAUTHENTICATED, AUTHENTICATED, ASSOCIATED, CONNECTED, DISRUPTED).
If state information is present, you MUST use it to explain why the crash in that specific state is significant.

You MUST strictly follow all formatting and length constraints below.

OUTPUT FORMAT (DO NOT ADD EXTRA TEXT):

==== FUZZING CRASH REPORT ====

Summary:
- Maximum 50 words.
- High-level overview of crash type and location.

Technical Analysis:
- Approximately 200 words.
- Must include quoted log snippets, frame fields, or relevant instructions (e.g., "status=200", "algo=9999").
- Clearly explain:
  - Frame type
  - Malformed field
  - Likely root cause
  - Vulnerability class
  - Protocol state at crash (if available)

Impact:
- Maximum 30 words.
- Clear security implication (e.g., "Potential denial of service" or "Possible memory corruption").

CVE Correlation:
- Provide a specific CVE ID if there is a strong match.
- Otherwise write exactly: No match found.

Confidence Level:
- Must be exactly one of: High, Medium, or Low.

================================

Here is the fuzzing log:

-------------------------
{log_content}
-------------------------
"""


def load_llm(provider: str = "groq"):
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o-mini", temperature=0.2)

    elif provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model="gemini-2.0-flash", temperature=0.2)

    elif provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(model="llama-3.3-70b-versatile", temperature=0.2)

    else:
        raise ValueError("Unsupported provider.")


def explain_crash(log_content: str, llm) -> str:
    prompt = PromptTemplate.from_template(CRASH_ANALYSIS_PROMPT)
    chain = prompt | llm | StrOutputParser()
    return chain.invoke({"log_content": log_content})


def process_all_aliveness_files(provider: str = "groq"):

    llm = load_llm(provider)
    reports = []

    for directory in LOG_DIRECTORIES:

        if not os.path.exists(directory):
            continue  # Skip missing directories safely

        files = sorted(os.listdir(directory))

        aliveness_files = [
            f for f in files if f.startswith("Aliveness_check_")
        ]
        
        if not aliveness_files:
            continue
        
        latest_file = max(
            aliveness_files, key=lambda f: os.path.getmtime(os.path.join(directory, f))
        )

        for filename in aliveness_files:

            file_path = os.path.join(directory, filename)

            if not os.path.isfile(file_path):
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    log_content = f.read()
            except Exception:
                continue

            report = explain_crash(log_content, llm)

            reports.append({
                "directory": directory,
                "file": filename,
                "report": report
            })

    return reports

def generate_crash_report():
    print("\n[!] Connectivity lost. Generating crash report...\n")
    try:
        reports = process_all_aliveness_files(provider="groq")

        if not reports:
            print("[!] No Aliveness_check logs found.")
            return

        for entry in reports:
            print("\n" + "=" * 80)
            print(f"Directory: {entry['directory']}")
            print(f"File: {entry['file']}")
            print("=" * 80)
            print(entry["report"])

    except Exception as e:
        print(f"[!] Failed to generate crash report: {e}")
    
def handle_crash():
    print("\n[!] Crash detected.")

    print("[A] Analyze with LLM")
    print("[C] Close Fuzzing and Exit the program")
    print("[L] Get Insights into the crash from the logs")
    print("[R] Resume without analysis")
    print()

    choice = input("Select option: ").strip().lower()

    if choice == "a":
        generate_crash_report()
        return "resume"

    elif choice == "c":
        print("Closing fuzzing...")
        sys.exit(0)
        
    elif choice == 'l':
        ci = CrashIntelligence()
        intelligence_report = ci.analyze()
        print(intelligence_report)

    elif choice == "r":
        return "resume"

    else:
        print("Invalid option.")
        return "resume"