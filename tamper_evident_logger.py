import hashlib
import hmac
import json
import os
import shutil
import datetime
import time
import sys
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs.json")
ALERT_FILE = os.path.join(BASE_DIR, "alerts.log")
EXPORT_FILE = os.path.join(BASE_DIR, "logs_export.txt")
BACKUP_FILE = os.path.join(BASE_DIR, "logs.json.bak")
GENESIS_HASH = "0"
def _load_secret_key() -> bytes:
    """
    Securely retrieves the secret key from the environment.
    Ensures the key is present and converts it to bytes for HMAC use.
    """
    key = os.environ.get("SECRET_KEY")
    if not key:
        # Crucial security step: Do not proceed without a valid key.
        raise EnvironmentError(
            "CRITICAL SECURITY ERROR: 'SECRET_KEY' environment variable is not set. "
            "Please set it using 'export SECRET_KEY=your_key' or equivalent."
        )
    return key.encode("utf-8")


try:
    SECRET_KEY = _load_secret_key()
except EnvironmentError as e:
    print(f"\n[FATAL] {e}")
    sys.exit(1)
RATE_LIMIT_SECONDS = 2
_last_log_time: float = 0.0


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def _compute_hmac(timestamp: str, event: str, description: str, prev_hash: str) -> str:
    raw = f"{timestamp}|{event}|{description}|{prev_hash}"
    return hmac.new(SECRET_KEY, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def _load_logs() -> list:
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
        if not content:
            return []
        data = json.loads(content)
        data.sort(key=lambda e: e.get("index", 0))
        return data
    except json.JSONDecodeError as exc:
        print(f"[WARNING] Log file corrupted or invalid JSON: {exc}")
        return []
    except OSError as exc:
        print(f"[ERROR] Cannot read log file: {exc}")
        return []


def _save_logs(logs: list) -> None:
    logs_sorted = sorted(logs, key=lambda e: e.get("index", 0))
    if os.path.exists(LOG_FILE):
        shutil.copy2(LOG_FILE, BACKUP_FILE)
    tmp_path = LOG_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(logs_sorted, fh, indent=2, ensure_ascii=False)
        os.replace(tmp_path, LOG_FILE)
    except OSError as exc:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise exc


def _write_alert(index: int, reason: str) -> None:
    ts = _now_iso()
    line = f"[{ts}] ALERT | Entry {index} | {reason}\n"
    try:
        with open(ALERT_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def _validate_input(event: str, description: str) -> None:
    if not event or not event.strip():
        raise ValueError("Event type must not be empty.")
    if not description or not description.strip():
        raise ValueError("Description must not be empty.")
    if len(event.strip()) > 64:
        raise ValueError("Event type must not exceed 64 characters.")
    if len(description.strip()) > 512:
        raise ValueError("Description must not exceed 512 characters.")


def _enforce_rate_limit() -> None:
    global _last_log_time
    now = time.monotonic()
    elapsed = now - _last_log_time
    if elapsed < RATE_LIMIT_SECONDS:
        remaining = RATE_LIMIT_SECONDS - elapsed
        raise RuntimeError(
            f"Rate limit active. Wait {remaining:.1f}s before adding another log."
        )
    _last_log_time = now


def add_log(event: str, description: str) -> dict:
    _enforce_rate_limit()
    event = event.strip()
    description = description.strip()
    _validate_input(event, description)

    logs = _load_logs()
    if logs:
        next_index = logs[-1]["index"] + 1
        prev_hash = logs[-1]["current_hash"]
    else:
        next_index = 0
        prev_hash = GENESIS_HASH
    timestamp = _now_iso()
    current_hash = _compute_hmac(timestamp, event, description, prev_hash)

    entry = {
        "index": next_index,
        "timestamp": timestamp,
        "event": event,
        "description": description,
        "prev_hash": prev_hash,
        "current_hash": current_hash,
    }

    logs.append(entry)
    _save_logs(logs)

    print(
        f"[LOG ADDED] Index={entry['index']} | Event={event} | "
        f"Hash={current_hash[:16]}..."
    )
    return entry


def verify_logs() -> bool:
    logs = _load_logs()

    SEP = "=" * 66
    print(f"\n{SEP}")

    if not logs:
        print("  [INFO] Log file is empty. Nothing to verify.")
        print(f"{SEP}\n")
        return True

    print(f"  Verifying {len(logs)} log {'entry' if len(logs) == 1 else 'entries'}...")
    print(SEP)

    integrity_ok = True
    violations = 0
    tampered_indices = []

    for idx, entry in enumerate(logs):
        required_keys = {
            "index", "timestamp", "event",
            "description", "prev_hash", "current_hash"
        }
        if not required_keys.issubset(entry.keys()):
            reason = "Missing required fields — structural corruption."
            print(f"  [TAMPERED] Entry {idx}: {reason}")
            _write_alert(idx, reason)
            integrity_ok = False
            violations += 1
            tampered_indices.append(idx)
            continue

        entry_tampered = False

        if entry["index"] != idx:
            reason = (
                f"Index field is {entry['index']} but expected {idx}. "
                f"Index tampering detected."
            )
            print(f"  [TAMPERED] Entry {idx}: {reason}")
            _write_alert(idx, reason)
            integrity_ok = False
            violations += 1
            if idx not in tampered_indices:
                tampered_indices.append(idx)
            entry_tampered = True

        expected_hash = _compute_hmac(
            entry["timestamp"],
            entry["event"],
            entry["description"],
            entry["prev_hash"],
        )

        if not hmac.compare_digest(entry["current_hash"], expected_hash):
            reason = (
                f"HMAC mismatch — data modification or unauthorized recomputation detected.\n"
                f"    Stored   : {entry['current_hash']}\n"
                f"    Expected : {expected_hash}"
            )
            print(f"  [TAMPERED] Entry {idx}: {reason}")
            _write_alert(
                idx,
                f"HMAC mismatch | stored={entry['current_hash'][:16]}... "
                f"expected={expected_hash[:16]}..."
            )
            integrity_ok = False
            violations += 1
            if idx not in tampered_indices:
                tampered_indices.append(idx)
            entry_tampered = True
            continue

        if idx == 0:
            if entry["prev_hash"] != GENESIS_HASH:
                reason = (
                    f"Genesis prev_hash must be '{GENESIS_HASH}' "
                    f"but found '{entry['prev_hash']}'."
                )
                print(f"  [TAMPERED] Entry {idx}: {reason}")
                _write_alert(idx, reason)
                integrity_ok = False
                violations += 1
                if idx not in tampered_indices:
                    tampered_indices.append(idx)
                entry_tampered = True
        else:
            expected_prev = logs[idx - 1]["current_hash"]
            if entry["prev_hash"] != expected_prev:
                reason = (
                    f"Chain link broken — log deletion or reordering detected.\n"
                    f"    prev_hash stored   : {entry['prev_hash']}\n"
                    f"    predecessor hash   : {expected_prev}"
                )
                print(f"  [TAMPERED] Entry {idx}: {reason}")
                _write_alert(idx, "Chain link broken — deletion or reorder detected.")
                integrity_ok = False
                violations += 1
                if idx not in tampered_indices:
                    tampered_indices.append(idx)
                entry_tampered = True

        if not entry_tampered:
            print(
                f"  [OK]       Entry {idx} | Event={entry['event']} | "
                f"Hash={entry['current_hash'][:16]}..."
            )

    print(SEP)
    print(f"  Total entries checked : {len(logs)}")
    print(f"  Total violations      : {violations}")
    if tampered_indices:
        print(f"  Tampered at indices   : {tampered_indices}")
    print(SEP)
    if integrity_ok:
        print("  FINAL RESULT : INTACT — All logs verified successfully.")
    else:
        print("  FINAL RESULT : TAMPERED — Integrity violations detected.")
    print(f"{SEP}\n")
    return integrity_ok


def export_logs() -> None:
    logs = _load_logs()
    if not logs:
        print("[INFO] No logs to export.")
        return

    try:
        with open(EXPORT_FILE, "w", encoding="utf-8") as fh:
            fh.write("=" * 72 + "\n")
            fh.write("  TAMPER-EVIDENT LOG EXPORT\n")
            fh.write(f"  Generated     : {_now_iso()}\n")
            fh.write(f"  Total Entries : {len(logs)}\n")
            fh.write("=" * 72 + "\n\n")
            for entry in logs:
                fh.write(f"Index       : {entry['index']}\n")
                fh.write(f"Timestamp   : {entry['timestamp']}\n")
                fh.write(f"Event       : {entry['event']}\n")
                fh.write(f"Description : {entry['description']}\n")
                fh.write(f"Prev Hash   : {entry['prev_hash']}\n")
                fh.write(f"Curr Hash   : {entry['current_hash']}\n")
                fh.write("-" * 72 + "\n")
        print(f"[EXPORT] Logs written to '{os.path.abspath(EXPORT_FILE)}'.")
    except OSError as exc:
        print(f"[ERROR] Export failed: {exc}")


def simulate_tampering() -> None:
    logs = _load_logs()
    if not logs:
        print("[ERROR] No logs available to simulate tampering on.")
        return

    SEP = "-" * 50
    print(f"\n{SEP}")
    print("  Simulate Tampering")
    print(SEP)
    print("  1. Modify a field in an entry")
    print("  2. Delete an entry")
    print("  3. Reorder entries")
    print(f"{SEP}")

    try:
        sub = input("  Select tampering type [1-3]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if sub == "1":
        try:
            idx = int(input(f"  Entry index to modify [0-{len(logs)-1}]: ").strip())
            if idx < 0 or idx >= len(logs):
                print("[ERROR] Index out of range.")
                return
        except ValueError:
            print("[ERROR] Invalid index.")
            return

        field = input("  Field to modify (event/description): ").strip().lower()
        if field not in ("event", "description"):
            print("[ERROR] Only 'event' or 'description' can be modified.")
            return

        new_value = input(f"  New value for '{field}': ").strip()
        if not new_value:
            print("[ERROR] New value must not be empty.")
            return

        original = logs[idx][field]
        logs[idx][field] = new_value

        with open(LOG_FILE, "w", encoding="utf-8") as fh:
            json.dump(logs, fh, indent=2)

        print(
            f"\n  [SIMULATED] Entry {idx} field '{field}' changed:\n"
            f"    Before : {original}\n"
            f"    After  : {new_value}\n"
        )

    elif sub == "2":
        try:
            idx = int(input(f"  Entry index to delete [0-{len(logs)-1}]: ").strip())
            if idx < 0 or idx >= len(logs):
                print("[ERROR] Index out of range.")
                return
        except ValueError:
            print("[ERROR] Invalid index.")
            return

        deleted = logs.pop(idx)
        with open(LOG_FILE, "w", encoding="utf-8") as fh:
            json.dump(logs, fh, indent=2)

        print(
            f"\n  [SIMULATED] Entry {idx} (Event='{deleted['event']}') deleted "
            f"from logs.json.\n"
        )

    elif sub == "3":
        if len(logs) < 2:
            print("[ERROR] Need at least 2 entries to reorder.")
            return

        random.shuffle(logs)
        with open(LOG_FILE, "w", encoding="utf-8") as fh:
            json.dump(logs, fh, indent=2)

        print("\n  [SIMULATED] Entries randomly reordered in logs.json.\n")

    else:
        print("  Invalid option.")
        return

    print("  Running verification on tampered log chain...\n")
    verify_logs()


def _print_menu() -> None:
    print("\n+------------------------------------------------+")
    print("|     Tamper-Evident Logging System v3.0         |")
    print("+------------------------------------------------+")
    print("|  1. Add log entry                              |")
    print("|  2. Verify log integrity                       |")
    print("|  3. Export logs to text file                   |")
    print("|  4. Simulate tampering + auto-verify           |")
    print("|  5. Exit                                       |")
    print("+------------------------------------------------+")


def _run_demo() -> None:
    global _last_log_time

    print("\n" + "=" * 66)
    print("  DEMO: Tamper-Evident Logging System v3.0")
    print("=" * 66)

    for f in (LOG_FILE, BACKUP_FILE):
        if os.path.exists(f):
            os.remove(f)

    _last_log_time = 0.0

    samples = [
        ("SYSTEM_START",  "Application server initialised on port 8443."),
        ("USER_LOGIN",    "User 'alice' authenticated via MFA from 10.0.0.42."),
        ("PRIVILEGE_ESC", "User 'alice' granted temporary sudo for task #2031."),
        ("FILE_ACCESS",   "Sensitive file '/etc/shadow' read by process PID 4412."),
    ]

    print("\n[PHASE 1] Adding 4 legitimate log entries...\n")
    for event, desc in samples:
        _last_log_time = 0.0
        add_log(event, desc)

    print("\n[PHASE 2] Verifying intact chain...")
    verify_logs()

    print("[PHASE 3] Simulating data modification (single character change)...\n")
    with open(LOG_FILE, "r", encoding="utf-8") as fh:
        logs = json.load(fh)
    original_desc = logs[1]["description"]
    logs[1]["description"] = logs[1]["description"].replace("alice", "mallory")
    with open(LOG_FILE, "w", encoding="utf-8") as fh:
        json.dump(logs, fh, indent=2)
    print(f"  Before: {original_desc}")
    print(f"  After : {logs[1]['description']}\n")

    print("[PHASE 4] Verifying after data modification...")
    verify_logs()

    print("[PHASE 5] Simulating log deletion (removing index 2)...\n")
    with open(LOG_FILE, "r", encoding="utf-8") as fh:
        logs = json.load(fh)
    logs[1]["description"] = original_desc
    recomputed = _compute_hmac(
        logs[1]["timestamp"], logs[1]["event"],
        logs[1]["description"], logs[1]["prev_hash"]
    )
    logs[1]["current_hash"] = recomputed
    del logs[2]
    with open(LOG_FILE, "w", encoding="utf-8") as fh:
        json.dump(logs, fh, indent=2)
    print("  Entry at index 2 removed from logs.json.\n")

    print("[PHASE 6] Verifying after deletion...")
    verify_logs()

    print("[PHASE 7] Simulating entry reordering...\n")
    with open(LOG_FILE, "r", encoding="utf-8") as fh:
        logs = json.load(fh)
    logs[0], logs[1] = logs[1], logs[0]
    with open(LOG_FILE, "w", encoding="utf-8") as fh:
        json.dump(logs, fh, indent=2)
    print("  Entries 0 and 1 swapped in logs.json.\n")

    print("[PHASE 8] Verifying after reordering...")
    verify_logs()

    print("[PHASE 9] Simulating index field tampering...\n")
    with open(LOG_FILE, "r", encoding="utf-8") as fh:
        logs = json.load(fh)
    logs[0]["index"] = 999
    with open(LOG_FILE, "w", encoding="utf-8") as fh:
        json.dump(logs, fh, indent=2)
    print("  Entry 0 index changed to 999.\n")

    print("[PHASE 10] Verifying after index tampering...")
    verify_logs()

    print("[PHASE 11] Exporting logs to text file...")
    export_logs()

    print(f"\n[DEMO COMPLETE] Alerts written to '{os.path.abspath(ALERT_FILE)}'.\n")


def main() -> None:
    print("\nWelcome to the Tamper-Evident Logging System.")
    print(f"Log file    : {os.path.abspath(LOG_FILE)}")
    print(f"Alert file  : {os.path.abspath(ALERT_FILE)}")
    print(f"Backup file : {os.path.abspath(BACKUP_FILE)}")

    while True:
        _print_menu()
        try:
            choice = input("Select option [1-5]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nExiting. Goodbye.\n")
            sys.exit(0)

        if choice == "1":
            try:
                event = input("  Event type   : ").strip()
                description = input("  Description  : ").strip()
                add_log(event, description)
            except (ValueError, RuntimeError) as exc:
                print(f"[ERROR] {exc}")

        elif choice == "2":
            verify_logs()

        elif choice == "3":
            export_logs()

        elif choice == "4":
            simulate_tampering()

        elif choice == "5":
            print("\nExiting. Goodbye.\n")
            break

        else:
            print("  Invalid option. Enter 1, 2, 3, 4, or 5.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        _run_demo()
    else:
        main()
