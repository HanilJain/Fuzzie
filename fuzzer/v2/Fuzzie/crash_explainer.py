import os
import argparse
from dotenv import load_dotenv

from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

# Requires python-dotenv to load environment variables for API keys, etc.
# The Logs should be given as part of the running script, they are assumed to be stored in a folder called Logs/
# The way to runt his python script is python crash_explainer.py LogsAliveness_check_16-02-26__17:46:55 --provider groq


load_dotenv()


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
    """
    Dynamically load LLM provider.
    """

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0.2,
        )

    elif provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            temperature=0.2,
        )

    elif provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model="llama-3.3-70b-versatile",
            temperature=0.2,
        )

    else:
        raise ValueError("Unsupported provider. Choose from: openai, gemini, groq")


def explain_crash(file_path: str, provider: str = "groq") -> str:
    """
    Reads a fuzz log file and returns structured crash analysis.
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    llm = load_llm(provider)

    prompt = PromptTemplate.from_template(CRASH_ANALYSIS_PROMPT)

    # Modern LCEL pipeline
    chain = prompt | llm | StrOutputParser()

    result = chain.invoke({"log_content": log_content})

    return result


def main():
    parser = argparse.ArgumentParser(description="Fuzz Crash Report Explainer")
    parser.add_argument("file", help="Path to fuzz log .txt file")
    parser.add_argument(
        "--provider",
        default="groq",
        choices=["groq", "gemini", "openai"],
        help="LLM provider to use",
    )

    args = parser.parse_args()

    report = explain_crash(args.file, args.provider)

    print("\n")
    print(report)


if __name__ == "__main__":
    main()