import os
import subprocess
import sys
import ctlabs_tools.kafka.kafka as kafka_app

def main():
    # Get the actual file path of your streamlit script
    script_path = kafka_app.__file__
    
    # Use subprocess to run the real streamlit command
    # This avoids all the "ScriptRunContext" and threading issues
    try:
        subprocess.run(["streamlit", "run", script_path] + sys.argv[1:], check=True)
    except KeyboardInterrupt:
        sys.exit(0)
