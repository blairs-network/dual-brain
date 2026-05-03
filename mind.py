import os
import subprocess
from datetime import datetime

BASE = os.path.expanduser("~/Desktop/mind")
CONTEXT = os.path.join(BASE, "context.md")
LOG = os.path.join(BASE, "log.md")
STATE = os.path.join(BASE, "state.md")
GEN_MODEL = os.environ.get("MIND_GEN_MODEL", "hermes3:8b")
CLF_MODEL = os.environ.get("MIND_CLF_MODEL", "llama3.2:3b")
MOVES = ("ADVISING", "ENCOURAGING", "QUESTIONING", "OBSERVING", "SILENT")


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def ollama(prompt, model, timeout=180):
    r = subprocess.run(
        ["ollama", "run", model, prompt],
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
    out = ollama(prompt, CLF_MODEL, timeout=60)
    word = out.split()[0].upper().strip(".,!?:;\"'") if out else ""
    return word if word in MOVES else "OBSERVING"


def generate(context, log, user_input, extra=""):
    prompt = (
        f"# Context\n{context}\n\n"
        f"# Recent log\n{log}\n\n"
        f"# User\n{user_input}\n\n{extra}\n"
        "Respond as a thoughtful companion. Silence is acceptable; "
        "if you have nothing real to add, reply with an empty message."
    )
    return ollama(prompt, GEN_MODEL)


def turn(user_input, last_move):
    context, log = read_file(CONTEXT), read_file(LOG)
    parts = [p for p in log.split("\n## ") if p.strip()]
    recent = ("\n## " + "\n## ".join(parts[-6:])) if parts else ""
    response = generate(context, recent, user_input)
    move = classify(response)
    if move == last_move:
        target = next(m for m in MOVES if m != last_move and m != "SILENT")
        response = generate(
            context, recent, user_input,
            extra=f"Your previous move was {move}. Make a {target} move instead.",
        )
        move = classify(response)
        if move == last_move:
            return "I don't have anything new.", last_move
    return response, move


def main():
    print(f"mind.py — gen={GEN_MODEL} clf={CLF_MODEL}. Type 'exit' to quit.")
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
        with open(STATE, "w") as f:
            f.write(move)
        ts = datetime.now().isoformat(timespec="seconds")
        with open(LOG, "a") as f:
            f.write(f"\n## {ts} [{move}]\n**user:** {user_input}\n**mind:** {response}\n")


if __name__ == "__main__":
    main()
