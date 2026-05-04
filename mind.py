import os
import subprocess
from datetime import datetime

BASE = os.path.expanduser("~/Desktop/mind")
CONTEXT = os.path.join(BASE, "context.md")
LOG = os.path.join(BASE, "log.md")
STATE = os.path.join(BASE, "state.md")
MEMORY = os.path.join(BASE, "memory.md")
GEN_MODEL = os.environ.get("MIND_GEN_MODEL", "hermes3:8b")
CLF_MODEL = os.environ.get("MIND_CLF_MODEL", "llama3.2:3b")
MOVES = ("ADVISING", "ENCOURAGING", "QUESTIONING", "OBSERVING", "SILENT")
SUMMARIZE_EVERY = 10


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
        "Classify the message below as exactly ONE word from this list. "
        "ADVISING (advise/recommend), ENCOURAGING (support/warmth), "
        "QUESTIONING (ask a question), OBSERVING (reflect/notice), "
        "SILENT (only valid for empty messages). "
        "Reply with only the single word, no punctuation, no explanation.\n\n"
        f"Message:\n{response}"
    )
    out = ollama(prompt, CLF_MODEL, timeout=60)
    word = out.split()[0].upper().strip(".,!?:;\"'") if out else ""
    return "OBSERVING" if word == "SILENT" or word not in MOVES else word


def generate(context, memory, log, user_input, extra=""):
    prompt = (
        "Reply only to the latest User message. Apply Context as silent "
        "standing rules — never quote, address, or acknowledge them. "
        "Memory is a summary of older conversation; treat it as background.\n\n"
        f"# Context\n{context}\n\n# Memory\n{memory}\n\n"
        f"# Recent log\n{log}\n\n# User\n{user_input}\n\n"
        f"{extra}\nIf you have nothing genuine to add, reply with an empty message."
    )
    return ollama(prompt, GEN_MODEL)


def critique(user_input, response, context):
    if not response.strip():
        return "ACCEPT"
    prompt = (
        "Judge this AI reply. Reply with exactly ONE word:\n"
        "ACCEPT - genuine, specific, useful\n"
        "REVISE - vague, sycophantic, generic, or echoes the rules back\n"
        "REJECT - nothing real to say; silence would be better\n\n"
        f"Standing rules: {context[:300]}\n"
        f"User said: {user_input}\n"
        f"AI replied: {response}\n\n"
        "One word only:"
    )
    out = ollama(prompt, CLF_MODEL, timeout=60)
    word = out.split()[0].upper().strip(".,!?:;\"'") if out else "ACCEPT"
    return word if word in ("ACCEPT", "REVISE", "REJECT") else "ACCEPT"


def summarize(chunk):
    prompt = (
        "Compress this dialogue chunk into one short third-person paragraph "
        "(~3 sentences). Capture facts, themes, and decisions. No filler, "
        "no commentary, no quotation.\n\n" + chunk
    )
    return ollama(prompt, GEN_MODEL)


def maybe_summarize():
    log = read_file(LOG)
    parts = [p for p in log.split("\n## ") if p.strip()]
    needed = len(parts) // SUMMARIZE_EVERY
    done = read_file(MEMORY).count("--- chunk ")
    for i in range(done, needed):
        chunk_parts = parts[i * SUMMARIZE_EVERY:(i + 1) * SUMMARIZE_EVERY]
        chunk = "## " + "\n## ".join(chunk_parts)
        summary = summarize(chunk)
        with open(MEMORY, "a") as f:
            lo, hi = i * SUMMARIZE_EVERY + 1, (i + 1) * SUMMARIZE_EVERY
            f.write(f"\n--- chunk {i + 1} (turns {lo}-{hi}) ---\n{summary}\n")


def turn(user_input, last_move):
    context = read_file(CONTEXT)
    memory = read_file(MEMORY)
    log = read_file(LOG)
    parts = [p for p in log.split("\n## ") if p.strip()]
    recent = ("\n## " + "\n## ".join(parts[-6:])) if parts else ""
    response = generate(context, memory, recent, user_input)
    verdict = critique(user_input, response, context)
    if verdict == "REJECT":
        response = ""
    elif verdict == "REVISE":
        response = generate(
            context, memory, recent, user_input,
            extra="Previous attempt was vague, sycophantic, or generic. Be specific and direct.",
        )
    move = classify(response)
    if move == last_move:
        i = MOVES.index(last_move) if last_move in MOVES else -1
        target = next(m for m in MOVES[i + 1:] + MOVES[:i] if m != "SILENT")
        response = generate(
            context, memory, recent, user_input,
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
        maybe_summarize()


if __name__ == "__main__":
    main()
