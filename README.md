Intuitive Open Source Anti Cheat enhanced with AI for Polihack_v17.

### Injection and Hooking
- **OS Anticheat Integration:** The anticheat module is injected directly into the game executable. Once active, it hooks critical DLL loading functions—overriding their normal execution (via techniques such as trampulin hooking) to monitor and intercept suspicious activities.
- **Integrity Verification:** The hooked functions trigger a call to Traian's program, which verifies the hash integrity of loaded DLLs. This step is crucial for detecting unauthorized modifications or instances of sideloading, where a malicious DLL replaces a legitimate one.

### DLL Analysis Process
- **Collecting Suspect DLLs:** When a DLL is identified as suspect—either due to injection or integrity mismatches—it, along with any injected DLLs, is sent to an analyzer.
- **Decompilation:** The analyzer uses radare2 to decompile these DLLs, producing both low-level assembly code and high-level C pseudocode. In parallel, an LLM4Decompile module attempts to generate pseudocode directly from the assembly, offering an alternative view of the code structure.
- **In-Depth Analysis with Gemini:** Both the radare2 output and the LLM-inferred pseudocode are forwarded to Gemini, a module designed to handle large context windows. Gemini analyzes the decompiled code, generating a detailed report along with a confidence score that reflects the likelihood of malicious modifications.

### Response and Flexibility
- **Server-Side Integration:** The confidence score, along with the detailed analysis report, is sent to the game server. The server can then take appropriate actions—such as flagging the account for review or notifying administrators.
- **Enhanced Inference Options:** For faster inference, the system can leverage more advanced v2 models that work with specialized Ghidra output. Additionally, if the user's hardware is not powerful enough, the AI inference models can be hosted on a server, offloading the processing and ensuring efficient analysis.
