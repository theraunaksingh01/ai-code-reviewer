import os
import environ
import subprocess
env = environ.Env()
environ.Env.read_env()
API_KEY = env('API_KEY')
def run(cmd):
    subprocess.run(cmd, shell=False)
 
import sys
sys.exit(0)