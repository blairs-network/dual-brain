import os
import subprocess
from datetime import datetime

BASE = os.path.expanduser("~/Desktop/mind")
CONTEXT = os.path.join(BASE, "context.md")
LOG = os.path.join(BASE, "log.md")
STATE = os.path.join(BASE, "state.md")
MODEL = "hermes3:8b"
MOVES = {"ADVISING", "ENCOURAGING", "QUESTIONING", "OBSERVING", "SILENT"}


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def write_file(path, text, mode="w"):
    with open(path, mode) as f:
        f.write(text)


def ollama(prompt, timeout=180):
    r = subprocess.run(
        ["ollama", "run", MODEL, prompt],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.stdout.strip()


def classify(response):
    if not response.strip():
        return "SILENT"
    prompt = (
        "Classify the following message as exactly ONE word from this list: "
        "ADVISING, ENCOURAGING, QUESTIONING, OBSERVING, SILENT. "
        "Reply with only the single word, no punctuation, no explanation.\n\n"
        f"Message:\n{response}"
    )
    out = ollama(prompt, timeout=60)
    word = out.split()[0].upper().strip(".,!?:;\"'") if out else ""
    return word if word in MOVES else "OBSERVING"


def generate(context, log, user_input, extra=""):
    prompt = (
        f"# Context\n{context}\n\n"
        f"# Recent log\n{log[-4000:]}\n\n"
        f"# User\n{user_input}\n\n{extra}\n"
        "Respond as a thoughtful companion. Silence is acceptable; "
        "if you have nothing real to add, reply with an empty message."
    )
    return ollama(prompt)


def turn(user_input, last_move):
    context, log = read_file(CONTEXT), read_file(LOG)
    response = generate(context, log, user_input)
    move = classify(response)
    if move == last_move:
        response = generate(
            context, log, user_input,
            extra=f"Your previous move was {move}. Make a different move.",
        )
        move = classify(response)
        if move == last_move:
            return "I don't have anything new.", last_move
    return response, move


def main():
    print(f"mind.py — model={MODEL}. Type 'exit' to quit.")
    while True:
        try:
            user_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if user_input.lower() == "exit":
            break
        if not user_input:
            continue
        last_move = read_file(STATE).strip()
        response, move = turn(user_input, last_move)
        print(f"\n[{move}]\n{response if response.strip() else '[SILENT]'}\n")
        write_file(STATE, move)
        ts = datetime.now().isoformat(timespec="seconds")
        write_file(
            LOG,
            f"\n## {ts} [{move}]\n**user:** {user_input}\n**mind:** {response}\n",
            mode="a",
        )


if __name__ == "__main__":
    main()
