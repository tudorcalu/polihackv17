#!/usr/bin/env python3

import sys
import os
import re
import r2pipe
import google.generativeai as genai
from datetime import datetime
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

###############################################################################
# Global variable for executable (DLL or EXE).
###############################################################################
EXECUTABLE = None  # We will set this in main() from sys.argv[1]


###############################################################################
# ---------------------------  decompile.py  ----------------------------------
###############################################################################
def get_functions_and_assembly_and_decomp(dll_path):
    """
    Returns a list of tuples: (function_name, disasm_text, decompiled_c)
    using r2pipe. For each discovered function:
      - 'pdr' or 'pdf' prints disassembly
      - 'pdc' prints pseudo-C code
    """
    if not os.path.isfile(dll_path):
        raise FileNotFoundError(f"{dll_path} does not exist")

    r2 = r2pipe.open(dll_path)
    r2.cmd('aaa')  # Full analysis
    funcs = r2.cmdj('aflj') or []

    results = []
    for f in funcs:
        name = f.get('name')
        offset = f.get('offset')
        if not name or offset is None:
            continue

        # Seek to the function offset
        r2.cmd(f's {offset}')

        # Get disassembly (you can switch between pdr/pdf if you like)
        asm = r2.cmd('pdr')

        # Get pseudo-C decompilation
        decompiled_c = r2.cmd('pdc')

        results.append((name, asm, decompiled_c))

    r2.quit()
    return results

def extract_instructions(disassembly_text):
    """
    Convert a single string of disassembly text into a list of raw instructions.
    Strips r2's graph characters and addresses, returning only the final instruction portion.
    """
    lines = disassembly_text.splitlines()
    instructions = []

    for line in lines:
        # Remove leading box/graph characters or spaces
        line = re.sub(r'^[│┌└├─>\s]+', '', line)
        if not line.strip():
            continue

        tokens = line.split()
        # Expecting: address, hex/opcodes, instruction
        if len(tokens) < 3:
            continue

        # If the first token is not an address, skip
        if not tokens[0].startswith('0x'):
            continue

        # Everything after the second token is the instruction
        instr = ' '.join(tokens[2:])
        # Remove any inline comment
        instr = instr.split(';', 1)[0].strip()

        if instr:
            instructions.append(instr)

    return instructions

def run_decompile(executable_path):
    """
    Replaces the original __main__ of decompile.py:
      - Decompiles the given executable using r2pipe.
      - Creates a folder named after the file's base name (without depending on extension).
      - Saves .txt instruction dumps and .c pseudo-code for each function.
    Returns the output folder name.
    """

    # Grab the base name of the executable (no extension-based logic)
    exe_basename = os.path.basename(executable_path)
    output_dir = exe_basename.split('.')[0]

    # If the folder exists, remove all files within it. Otherwise, create it.
    if os.path.isdir(output_dir):
        for file_name in os.listdir(output_dir):
            file_path = os.path.join(output_dir, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
    else:
        os.makedirs(output_dir)

    # Actually do the r2 analysis
    functions = get_functions_and_assembly_and_decomp(executable_path)

    # For each function, output (1) instructions and (2) radare2 pseudo-C
    for name, asm, decomp in functions:
        txt_path = os.path.join(output_dir, f"{name}.txt")
        c_path   = os.path.join(output_dir, f"decom_{name}.c")

        cleaned_instructions = extract_instructions(asm)
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(cleaned_instructions) + "\n")

        with open(c_path, "w", encoding="utf-8") as f:
            f.write(decomp)

    print(f"[decompile.py] Disassembly text and pseudo-C saved in folder: {output_dir}")
    return output_dir


###############################################################################
# ----------------------------  makec.py  -------------------------------------
###############################################################################
def make_c_code(folder):
    """
    Reads each .txt file in `folder`, uses the llm4decompile model
    to generate a pseudo-C listing for each, and writes it to a .c file.
    """

    model_name = "LLM4Binary/llm4decompile-1.3b-v1.5"
    print(f"[makec.py] Loading model: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.bfloat16
    ).cuda()  # if you have GPU support

    for filename in os.listdir(folder):
        if not filename.endswith(".txt"):
            continue

        file_path = os.path.join(folder, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            prompt = f.read().strip()

        input_ids = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            output_ids = model.generate(
                **input_ids,
                max_new_tokens=1024,
                do_sample=True,
                temperature=0.7
            )
        generated_text = tokenizer.decode(output_ids[0], skip_special_tokens=True)
        print(f"[makec.py] Generated pseudo-C for {filename}:")

        c_filename = "ai_" + os.path.splitext(filename)[0] + ".c"
        c_path = os.path.join(folder, c_filename)
        with open(c_path, "w", encoding="utf-8") as out_f:
            out_f.write(generated_text)

        print(f"[makec.py] Wrote {c_path}")


###############################################################################
# ---------------------------  make_report.py  --------------------------------
###############################################################################
def concatenate_files(folder):
    """
    In the specified folder, concatenate:
      1) All 'decom_*.c' files into 'big_decomp.c'
      2) All 'ai_*.c'    files into 'big_ai_decomp.c'
    Each file's contents are preceded by a separator line with its name.
    """

    big_decomp_path = os.path.join(folder, "big_decomp.c")
    big_ai_path     = os.path.join(folder, "big_ai_decomp.c")

    decom_files = [f for f in os.listdir(folder)
                   if f.startswith("decom_") and f.endswith(".c")]
    ai_files    = [f for f in os.listdir(folder)
                   if f.startswith("ai_") and f.endswith(".c")]

    decom_files.sort()
    ai_files.sort()

    with open(big_decomp_path, "w", encoding="utf-8") as out_decomp:
        for fname in decom_files:
            out_decomp.write(f"============= {fname} =============\n")
            file_path = os.path.join(folder, fname)
            with open(file_path, "r", encoding="utf-8") as src:
                out_decomp.write(src.read())
            out_decomp.write("\n\n")

    with open(big_ai_path, "w", encoding="utf-8") as out_ai:
        for fname in ai_files:
            out_ai.write(f"============= {fname} =============\n")
            file_path = os.path.join(folder, fname)
            with open(file_path, "r", encoding="utf-8") as src:
                out_ai.write(src.read())
            out_ai.write("\n\n")

    print(f"[make_report.py] Created '{big_decomp_path}' and '{big_ai_path}' in folder '{folder}'")


###############################################################################
# ----------------------------  gpt_anal.py  ----------------------------------
###############################################################################
def read_file(file_path):
    """Reads a file safely, returning its contents or empty string if not found."""
    if not os.path.isfile(file_path):
        print(f"Warning: File not found at {file_path}", file=sys.stderr)
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)
        return ""

def analyze_with_gemini(concatenated_text):
    """
    Sends the 'concatenated_text' to the configured Gemini model via the API,
    expecting a response that includes a line like 'CHEAT_CONFIDENCE=<score>' plus reasons.

    Returns: (confidence_score: float, reasons: [str])
    """
    # Hard-coded key in the original code (not recommended).
    API_KEY = "AIzaSyB5l886KhOWa0hgphMhHe_Pyb1VGD71IKk"

    # Safety settings to avoid blocking legitimate code analysis
    SAFETY_SETTINGS = [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    ]

    # Generation Configuration
    GENERATION_CONFIG = {
        "temperature": 0.2,
        "top_p": 0.95,
        "top_k": 40,
    }

    MODEL_NAME = "gemini-1.5-flash-latest"

    if not API_KEY:
        print("Error: GOOGLE_API_KEY environment variable not set.", file=sys.stderr)
        print("Please get an API key from https://aistudio.google.com/app/apikey and set the environment variable.", file=sys.stderr)
        return 0.0, ["[API Key missing. Analysis skipped.]"]

    try:
        # Configure the Gemini client
        genai.configure(api_key=API_KEY)

        # Create the Generative Model instance
        model = genai.GenerativeModel(
            MODEL_NAME,
            safety_settings=SAFETY_SETTINGS,
            generation_config=GENERATION_CONFIG
        )

        print(f"[gpt_anal.py] Sending prompt to Gemini model: {MODEL_NAME}...")
        response = model.generate_content(concatenated_text)
        print("[gpt_anal.py] Received response from Gemini.")

        # Check if the response was blocked or has no text
        if not response.parts:
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                block_reason = response.prompt_feedback.block_reason
                print(f"Warning: Prompt blocked by API. Reason: {block_reason}", file=sys.stderr)
                return 0.0, [f"[Prompt blocked by API. Reason: {block_reason}]"]
            else:
                finish_reason = (response.candidates[0].finish_reason
                                 if response.candidates else "UNKNOWN")
                print(f"Warning: Gemini response finished unexpectedly. Reason: {finish_reason}", file=sys.stderr)
                return 0.0, [f"[No content in Gemini response. Finish Reason: {finish_reason}]"]

        generated_text = response.text

    except Exception as e:
        print(f"Error during Gemini API call: {e}", file=sys.stderr)
        return 0.0, [f"[Error during Gemini API call: {e}]"]

    # Parse the response for 'CHEAT_CONFIDENCE='
    lines = generated_text.strip().splitlines()
    confidence_line = None
    reasons = []

    for line in lines:
        cleaned_line = line.strip()
        if not cleaned_line:
            continue
        if cleaned_line.upper().startswith("CHEAT_CONFIDENCE") and "=" in cleaned_line:
            confidence_line = cleaned_line
        else:
            reasons.append(cleaned_line)

    if not confidence_line:
        confidence_line = "CHEAT_CONFIDENCE=0.0"
        reasons.insert(0, "[No parseable CHEAT_CONFIDENCE line found in response. Setting to 0.0 by default.]")
        reasons.insert(1, "--- Full Gemini Response ---")
        reasons.extend(lines)
        reasons.insert(1, "--- End Full Gemini Response ---")

    conf_value = 0.0
    try:
        conf_str = confidence_line.split("=", 1)[1].strip()
        conf_value = float(conf_str)
        conf_value = max(0.0, min(1.0, conf_value))
    except (IndexError, ValueError) as e:
        print(f"Warning: Could not parse confidence value from line: '{confidence_line}'. Error: {e}", file=sys.stderr)
        reasons.insert(0, f"[Warning: Failed to parse confidence value from '{confidence_line}'. Using 0.0.]")

    return conf_value, reasons

def build_prompt(radare2_text, ai_text):
    """
    Builds a single text prompt that concatenates the content of
    big_decomp.c and big_ai_decomp.c for Gemini to analyze.
    """
    user_instructions = """
You are an expert security researcher specializing in reverse engineering game modifications and cheats.
Your task is to analyze two different pseudo-C decompilations of the same game-related DLL or EXE.
One decompilation comes from radare2 ('big_decomp.c'), and the other from an AI-assisted decompiler ('big_ai_decomp.c').

The goal is to identify potential cheat features within this code. Look for patterns indicative of:
- Memory reading/writing to game processes (especially player coordinates, health, ammo)
- Aimbots (calculating aiming angles, snapping aim)
- Wallhacks / ESP (reading enemy positions, drawing overlays, modifying rendering)
- Speed hacks / Tick manipulation (altering game speed or network timing)
- Field of View (FOV) manipulation
- Bypassing anti-cheat mechanisms
- Unusual network communication
- Direct manipulation of game engine structures or functions

Analyze the provided code snippets below. Consider both sources, noting any discrepancies or confirmations between them.

Based *only* on the provided code, output your analysis in the following format:

1. A single line starting exactly with `CHEAT_CONFIDENCE=` followed by a numerical score between 0.0 (no evidence of cheats) and 1.0 (strong evidence of cheats).
2. On subsequent lines, provide a concise explanation for your score. Detail the specific code fragments or functions that led to your conclusion. If you find no evidence, state that clearly.
"""

    if not radare2_text and not ai_text:
        return f"{user_instructions}\n\n[Error: Both input files were empty or could not be read.]"
    if not radare2_text:
        return (
            f"{user_instructions}\n\n"
            "[Warning: big_decomp.c was empty or not found.]\n\n"
            f"===== big_ai_decomp.c =====\n{ai_text}\n"
        )
    if not ai_text:
        return (
            f"{user_instructions}\n\n"
            f"===== big_decomp.c =====\n{radare2_text}\n\n"
            "[Warning: big_ai_decomp.c was empty or not found.]\n"
        )

    combined = (
        f"{user_instructions}\n\n"
        f"===== big_decomp.c =====\n{radare2_text}\n\n"
        f"===== big_ai_decomp.c =====\n{ai_text}\n"
    )
    return combined

def analyze_dll_for_cheats_gemini(folder):
    """
    1) Reads 'big_decomp.c' and 'big_ai_decomp.c' from `folder`.
    2) Builds a prompt and calls 'analyze_with_gemini' for cheat analysis.
    3) Prints the confidence and writes a report (report_gemini_YYYY-MM-DD.txt).
    """
    big_decomp_path = os.path.join(folder, "big_decomp.c")
    big_ai_decomp_path = os.path.join(folder, "big_ai_decomp.c")

    print(f"[gpt_anal.py] Reading radare2 decompilation from: {big_decomp_path}")
    radare2_text = read_file(big_decomp_path)
    print(f"[gpt_anal.py] Reading AI decompilation from: {big_ai_decomp_path}")
    ai_text = read_file(big_ai_decomp_path)

    if not radare2_text and not ai_text:
        print("Error: Both big_decomp.c and big_ai_decomp.c are empty or not found.", file=sys.stderr)
        return

    prompt = build_prompt(radare2_text, ai_text)
    conf_value, reasons = analyze_with_gemini(prompt)

    print(f"\nCHEAT_CONFIDENCE={conf_value:.2f}")

    today_str = datetime.now().strftime("%Y-%m-%d")
    report_name = f"report_gemini_{today_str}.txt"
    report_path = os.path.join(folder, report_name)

    try:
        print(f"[gpt_anal.py] Saving cheat-analysis report to {report_path}...")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Gemini Cheat Analysis Report ({datetime.now().isoformat()})\n")
            f.write("Model Used: gemini-1.5-flash-latest\n")
            f.write(f"Calculated Confidence: {conf_value:.4f}\n")
            f.write("="*40 + "\n")
            f.write("Analysis Reasons:\n")
            f.write("="*40 + "\n")
            f.write("\n".join(reasons).strip() + "\n")
        print("[gpt_anal.py] Successfully saved report.")
    except Exception as e:
        print(f"Error writing report file {report_path}: {e}", file=sys.stderr)


###############################################################################
# ----------------------  Single Main Entry Point  ----------------------------
###############################################################################
def main():
    global EXECUTABLE
    # We take the single argument as the path to the DLL or EXE
    if len(sys.argv) < 2:
        print("Usage: python combined.py <path/to/MyProgram.dll-or-exe>")
        sys.exit(1)

    EXECUTABLE = sys.argv[1]

    # 1) Decompile
    folder = run_decompile(EXECUTABLE)

    # 2) Use the AI model to generate .c from .txt
    make_c_code(folder)

    # 3) Concatenate everything into big_decomp.c and big_ai_decomp.c
    concatenate_files(folder)

    # 4) Analyze for potential cheats with the Gemini API
    analyze_dll_for_cheats_gemini(folder)


if __name__ == "__main__":
    main()
