# DELIBERATELY INSECURE demo for ai-security-atlas. Do not copy this code.
# Each block below is the kind of thing an AI assistant writes when asked to
# "just make it work".
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from flask import Flask, request

app = Flask(__name__)
client = None  # imagine an LLM client here


@app.route("/agent")
def agent():
    task = request.args.get("task")
    # VIBE002: user text pasted straight into the system prompt
    system_prompt = f"You are a helpful ops bot. The user's goal is: {request.args.get('goal')}"
    completion = client.chat(system=system_prompt, user=task)
    # VIBE001: running whatever the model returned
    exec(completion.choices[0].message.content)
    # VIBE003: and piping it into a shell for good measure
    subprocess.run(completion.choices[0].message.content, shell=True)
    return "done"


@app.route("/user")
def user():
    # TODO: add authentication before launch
    uid = request.args.get("id")
    db = sqlite3.connect("app.db")
    rows = db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()  # VIBE013
    return {"rows": rows}


@app.route("/report")
def report():
    name = request.args.get("file")
    with open("reports/" + request.args.get("file")) as fh:  # VIBE018
        body = fh.read()
    os.system("gzip " + name)  # VIBE012
    data = requests.get(request.args.get("url"), verify=False)  # VIBE016 + VIBE019
    cfg = yaml.load(open("config.yml"))  # VIBE015
    cache = pickle.loads(data.content)  # VIBE014
    return body


def make_reset_token():
    reset_token = str(random.randint(100000, 999999))  # VIBE050
    password_hash = hashlib.md5(b"hunter2").hexdigest()  # PQC001
    return reset_token, password_hash


def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # PQC004 + PQC012
    secret = private.public_key().encrypt(b"x", padding.OAEP(mgf=None, algorithm=None, label=None))  # PQC010
    shared = ec.generate_private_key(ec.SECP256R1()).exchange(ec.ECDH(), None)  # PQC011
    return secret, shared


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # VIBE017
