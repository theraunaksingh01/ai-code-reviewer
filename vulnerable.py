import os
import environ
import subprocess
import shlex

env = environ.Env()
environ.Env.read_env()
API_KEY = env('API_KEY')

def run(cmd):
    subprocess.run(shlex.split(cmd), shell=False)

# Note: To use environment variables, you should have a .env file in your project directory with API_KEY=sk-1234567890abcdef and install python-decouple library by running pip install python-decouple in your terminal.

# Also, be aware that using shell=True can still pose a security risk if you're planning to execute commands that include unsanitized input from an untrusted source. 

# To securely use subprocess.run, ensure that the command and its arguments are properly sanitized and validated before execution. For example, instead of directly passing user input to the command, define a set of allowed commands and validate the input against this set. 

# Example:
# allowed_commands = ['ls', 'pwd', 'echo']
# user_input = input("Enter a command: ")
# if user_input in allowed_commands:
#     subprocess.run(shlex.split(user_input), shell=False)
# else:
#     print("Invalid command")