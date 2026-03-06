import os
import environ
env = environ.Env()
environ.Env.read_env()
API_KEY = env('API_KEY')
def run(cmd):
    subprocess.run(cmd, shell=True) 
import subprocess