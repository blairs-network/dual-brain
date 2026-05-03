import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import mind

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
ALLOWED = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
API = f"https://api.telegram.org/bot{TOKEN}"
maybe_summarize = getattr(mind, "maybe_summarize", lambda: None)


def call(method, **params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"{API}/{method}", data=data)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def send(chat_id, text):
    try:
        return call("sendMessage", chat_id=chat_id, text=text[:4000])
    except urllib.error.URLError as e:
        print(f"send failed: {e}", file=sys.stderr)


def handle(text, chat_id):
    last_move = mind.read_file(mind.STATE).strip()
    response, move = mind.turn(text, last_move)
    with open(mind.STATE, "w") as f:
        f.write(move)
    ts = datetime.now().isoformat(timespec="seconds")
    with open(mind.LOG, "a") as f:
        f.write(f"\n## {ts} [{move}]\n**user:** {text}\n**mind:** {response}\n")
    maybe_summarize()
    body = response.strip() or "[silent]"
    send(chat_id, f"[{move}]\n{body}")


def main():
    if not TOKEN:
        sys.exit("Set TELEGRAM_BOT_TOKEN. Get one from @BotFather.")
    print(f"bot.py — listening. allowed_chat={ALLOWED or 'any'}")
    offset = 0
    while True:
        try:
            updates = call("getUpdates", offset=offset, timeout=30)
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            print(f"poll error: {e}; retrying in 5s", file=sys.stderr)
            time.sleep(5)
            continue
        except KeyboardInterrupt:
            print()
            break
        for u in updates.get("result", []):
            offset = u["update_id"] + 1
            msg = u.get("message") or u.get("edited_message") or {}
            chat_id = str(msg.get("chat", {}).get("id", ""))
            text = (msg.get("text") or "").strip()
            if not text or not chat_id:
                continue
            if ALLOWED and chat_id != ALLOWED:
                send(chat_id, "Not whitelisted.")
                continue
            try:
                handle(text, chat_id)
            except Exception as e:
                send(chat_id, f"error: {e}")
                print(f"handle error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
