import json
import subprocess
import os
import re
import sys
import time
from openai import OpenAI

# Configuration
MODEL = "gpt-4o"
MAX_ITERATIONS = 25
MAX_OUTPUT_LENGTH = 10000
FLAG_PATTERN = re.compile(r'csawctf\{[^}]+\}', re.IGNORECASE)


SYSTEM_PROMPT = """You are a CTF solver for PWN challenges. Find the flag (format: csawctf{...}).

You can run shell commands by responding with JSON:
{"action": "run", "command": "your_command_here"}

When you find the flag, respond with:
{"action": "submit", "flag": "csawctf{...}"}

IMPORTANT RULES:
- You CANNOT read flag.txt directly - you must exploit the vulnerability
- You CANNOT read challenge source files directly - you must interact with the program
- NEVER run programs directly (e.g., "python3 program.py") - they will hang waiting for input!
- ALWAYS use pwntools process() to interact with programs
- NEVER use p.interactive() - it will hang! Use p.recvall(timeout=2) instead

ANALYSIS COMMANDS (for binaries only):
- checksec --file=./binary
- r2 -q -c "aaa; afl" ./binary (list functions)  
- r2 -q -c "aaa; pdf @main" ./binary (disassemble main)

FOR PYTHON CHALLENGES - use pwntools to interact:
Common Python CTF vulnerabilities to try:
1. eval()/exec() injection: If program evals input, try:
   - open('flag.txt').read()
   - __import__('os').popen('cat flag.txt').read()
2. Integer tricks: negative numbers, large numbers, 0x hex strings
3. Type confusion: strings vs integers
4. Format string bugs

Respond with ONLY valid JSON."""

def run_command(command: str, timeout: int = 30) -> str:
    """Execute a shell command and return the output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout + result.stderr
        
        if len(output) > MAX_OUTPUT_LENGTH:
            output = output[:MAX_OUTPUT_LENGTH] + "\n... [OUTPUT TRUNCATED]"
        
        return output
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


def load_config():
    """Load challenge configuration."""
    try:
        with open("challenge.json", 'r') as f:
            return json.load(f)
    except:
        return {"name": "unknown", "files": [], "internal_port": 0}

def parse_response(response: str) -> dict:
    """Parse JSON from LLM response."""
    try:
        return json.loads(response)
    except:
        match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except:
                pass
        return {"action": "error", "message": "Could not parse response"}

def query_llm(client, messages, retries=3):
    """Query LLM with retry logic for rate limiting."""
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model= MODEL,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                temperature=0.7,
                max_tokens=2048
            )
            return response.choices[0].message.content
        except Exception as e:
            # If we hit a rate limit, wait for a bit and try again
            if "rate_limit" in str(e).lower() or "429" in str(e):
                wait_time = (attempt + 1) * 2
                print(f"Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise e
    return '{"action": "error", "message": "Rate limit exceeded"}'

def main():
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set")
        sys.exit(1)
    
    client = OpenAI()
    config = load_config()
    
    print(f"=" * 50)
    print(f"CTF Agent - Solving: {config.get('name', 'Unknown')}")
    print(f"=" * 50)
    
    context = f"""
            Challenge: {config.get('name', 'Unknown')}
            Description: {config.get('description', 'N/A')}
            Files: {config.get('files', [])}

            HINT: The challenge description often contains clues about the vulnerability!

            Analyze this challenge and find the flag. 
            - For binaries: use checksec and radare2
            - For Python files: run the program and try common exploit techniques (type confusion, integer tricks, etc.)
            Remember: Use process() for exploits, NOT remote().
            """
    
    messages = [{"role": "user", "content": context}]
    flag_found = None
    
    for i in range(MAX_ITERATIONS):
        print(f"\n--- Iteration {i+1}/{MAX_ITERATIONS} ---")
        
        reply = query_llm(client, messages)
        print(f"LLM: {reply[:500]}...")
        messages.append({"role": "assistant", "content": reply})
        
        action = parse_response(reply)
        
        # If the action is to submit the flag, check if it matches the flag pattern
        if action.get("action") == "submit":
            flag = action.get("flag", "")
            if FLAG_PATTERN.match(flag):
                flag_found = flag
                break
        # If the action is to run a command, run the command and check if the result contains the flag
        elif action.get("action") == "run":
            command = action.get("command", "")
            
            # Check if trying to read flag.txt directly via shell commands
            read_commands = ["cat", "head", "tail", "less", "more"]
            is_reading_flag = any(
                command.strip().startswith(f"{cmd} flag.txt") or 
                command.strip().startswith(f"{cmd} ./flag.txt") 
                for cmd in read_commands
            )
            
            # Also block Python-based direct file reading of flag.txt
            # But allow it if it's inside a pwntools sendline (legitimate exploit)
            if ("open('flag.txt')" in command or 'open("flag.txt")' in command):
                if "sendline" not in command and "process" not in command:
                    is_reading_flag = True
            
            # Prevent LLM from reading flag.txt directly
            if is_reading_flag:
                result = "ERROR: Cannot read flag.txt directly - exploit the vulnerability!"
            else:
                # Check if trying to read challenge source python files directly
                source_files = [f for f in config.get("files", []) if f.endswith('.py')]
                is_reading_source = False
                
                for src_file in source_files:
                    # Block shell commands that read source files
                    for cmd in ["cat", "head", "tail", "less", "more", "strings"]:
                        if (command.strip().startswith(f"{cmd} {src_file}") or 
                            command.strip().startswith(f"{cmd} ./{src_file}")):
                            is_reading_source = True
                            break
                    
                    # Block Python open() calls to source files
                    # But allow if it's inside a pwntools sendline (legitimate exploit)
                    if (f"open('{src_file}')" in command or f'open("{src_file}")' in command):
                        if "sendline" not in command and "process" not in command:
                            is_reading_source = True
                    
                    if is_reading_source:
                        break
                
                # Prevent LLM from reading challenge source python files directly
                if is_reading_source:
                    result = "ERROR: Cannot read challenge source files directly - interact with the program to exploit it!"
                else:
                    result = run_command(command)
            
            print(f"Command: {command}")
            print(f"Result: {result[:500]}...")
            
            # Check if the result contains the flag
            match = FLAG_PATTERN.search(result)
            if match:
                flag_found = match.group(0)
                break
            
            messages.append({"role": "user", "content": f"Command output:\n{result}"})
        
        else:
            messages.append({"role": "user", "content": "Invalid action. Use 'run' or 'submit'."})
    
    print(f"\n{'=' * 50}")
    if flag_found:
        print(f"FLAG: {flag_found}")
    else:
        print("No flag found")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()