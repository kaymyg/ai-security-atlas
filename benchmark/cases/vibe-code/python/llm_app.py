# LLM-specific patterns: running model output, and user text in system prompts.
import json
import os
import subprocess
from datetime import date


def run_model_output(client, msgs, completion, llm_output):
    resp = client.messages.create(model="m", messages=msgs)
    exec(resp.content[0].text)  # expect[VIBE001]
    eval(completion.choices[0].message.content)  # expect[VIBE001]
    code = resp.content[0].text
    exec(code)  # expect[VIBE010] miss[VIBE001] model output stored in a variable first
    subprocess.run(resp.content[0].text, shell=True)  # expect[VIBE003,VIBE011]
    os.system(llm_output)  # expect[VIBE003]
    plan = json.loads(resp.content[0].text)  # safe[VIBE001] parsing as data is fine
    subprocess.run(["pytest", "-q"])  # safe[VIBE003] fixed command
    subprocess.run(["git", "commit", "-m", "Add generated docs"])  # noisy[VIBE003] fixed command; "generated" is just a word
    return plan


def prompts(request, user_text, user_name, SYSTEM):
    system_prompt = f"You are an assistant for {request.json['company']}"  # expect[VIBE002]
    system_prompt = "You are a helpful assistant."  # safe[VIBE002]
    system_prompt = f"Today is {date.today()}. Be concise."  # safe[VIBE002] only the date is inserted
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_text}]  # safe[VIBE002]
    messages = [{"role": "system", "content": f"Help {user_name} with anything"}]  # miss[VIBE002] user data in the system role
    return system_prompt, messages
