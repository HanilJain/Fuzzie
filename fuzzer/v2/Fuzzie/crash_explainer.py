import os
from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

LOG_DIRECTORY = "Logs/fuzz_mngmt_frames"


CRASH_ANALYSIS_PROMPT = """
You are a wireless security expert specializing in 802.11, WPA2/WPA3, and Wi-Fi protocol vulnerabilities.

You are given raw fuzzing logs from a WPA/802.11 management frame fuzzer.

Your job is to:

1. Explain in clear human-readable terms:
   - What type of frame was being sent (if identifiable)
   - What field appears malformed
   - Why this could cause connectivity loss or crash
   - What class of vulnerability this likely represents 

2. Infer what part of the Wi-Fi stack is likely affected.

3. Try to correlate with known CVEs.
If no exact match exists, say so clearly.

4. Provide output in this format:

==== FUZZING CRASH REPORT ====

Summary:

Technical Analysis:
- Frame type:
- Malformed field:
- Likely root cause:
- Vulnerability class:

Impact:

Possible CVE Correlation:

Confidence Level:

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
    if not os.path.exists(LOG_DIRECTORY):
        raise FileNotFoundError(f"Directory not found: {LOG_DIRECTORY}")

    llm = load_llm(provider)

    files = sorted(os.listdir(LOG_DIRECTORY))
    aliveness_files = [
        f for f in files if f.startswith("Aliveness_check_")
    ]

    reports = []

    for filename in aliveness_files:
        file_path = os.path.join(LOG_DIRECTORY, filename)

        with open(file_path, "r", encoding="utf-8") as f:
            log_content = f.read()

        report = explain_crash(log_content, llm)

        reports.append({
            "file": filename,
            "report": report
        })

    return reports