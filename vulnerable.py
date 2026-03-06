import os
import environ
env = environ.Env()
environ.Env.read_env()
API_KEY = env('API_KEY')
def run(cmd):
    import subprocess
    subprocess.run(cmd, shell=True) #testing 

 
# Note: To use environment variables, you should have a .env file in your project directory with API_KEY=sk-1234567890abcdef and install python-decouple library by running pip install python-decouple in your terminal. 

# Also, be aware that using shell=True can still pose a security risk if you're planning to execute commands that include unsanitized input from an untrusted source.