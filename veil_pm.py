#!/usr/bin/env python3
"""
veil_pm - password manager with its own passphrase.

Works like veil: run `pm` (or `veil_pm`), it shows the banner, asks for the
passphrase and opens an interactive `>>> ` prompt. One terminal = one session:
a new terminal asks the passphrase again. The passphrase is never stored.
"""
import argparse
import ctypes
import getpass
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
from base64 import urlsafe_b64encode
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import readline
except ImportError:
    pass

MAGIC = b"VEILPM\x00\x01"
ARGON2_TEMPO = 3
ARGON2_MEMORIA_KIB = 65536
ARGON2_PARALLELISMO = 4
SALT_SIZE = 16

CONFIG_DIR = Path.home() / ".config" / "veil_pm"
KDF_FILE = CONFIG_DIR / "kdf"
SALT_FILE = CONFIG_DIR / "salt"
CHECK_FILE = CONFIG_DIR / "check"
DB_FILE = Path(os.environ.get("VEIL_PM_DB", Path.home() / ".local" / "share" / "veil_pm" / "entries.json"))


def prepara_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass


def scrivi_privato(percorso, dati):
    prepara_config()
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dati)


def kdf_attivo():
    scelta = os.environ.get("VEIL_PM_KDF")
    if scelta in ("argon2id", "pbkdf2"):
        return scelta
    prepara_config()
    if KDF_FILE.exists():
        salvato = KDF_FILE.read_text().strip()
        if salvato in ("argon2id", "pbkdf2"):
            return salvato
    try:
        ctypes.CDLL("libargon2.so.1")
        scelta = "argon2id"
    except OSError:
        scelta = "pbkdf2"
    scrivi_privato(KDF_FILE, (scelta + "\n").encode())
    return scelta


def argon2id(segreto, sale):
    try:
        lib = ctypes.CDLL("libargon2.so.1")
    except OSError:
        return None
    lib.argon2id_hash_raw.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
    ]
    uscita = ctypes.create_string_buffer(32)
    rc = lib.argon2id_hash_raw(
        ARGON2_TEMPO, ARGON2_MEMORIA_KIB, ARGON2_PARALLELISMO,
        segreto, len(segreto), sale, len(sale), uscita, 32,
    )
    if rc != 0:
        raise RuntimeError(f"argon2 error {rc}")
    return uscita.raw


def radice_kdf(passphrase, sale):
    dati = passphrase.encode()
    if kdf_attivo() == "argon2id":
        chiave = argon2id(dati, sale)
        if chiave is not None:
            return chiave
    return hashlib.pbkdf2_hmac("sha256", dati, sale, 600_000)


def sottochiave(radice, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(radice)


def deriva(passphrase):
    prepara_config()
    if not SALT_FILE.exists():
        return None
    return radice_kdf(passphrase, SALT_FILE.read_bytes())


def verifica(radice):
    if not CHECK_FILE.exists():
        return False
    atteso = CHECK_FILE.read_bytes()
    if len(atteso) != 16:
        return False
    calcolato = hmac.new(radice, b"veil-pm-check", hashlib.sha256).digest()[:16]
    return hmac.compare_digest(calcolato, atteso)


def _chiedi_frase(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    return input(prompt).strip()


def legge_frase():
    return _chiedi_frase("veil_pm passphrase: ")


# ----- encrypted database -----

def chiave_db(radice, sale_db):
    return Fernet(urlsafe_b64encode(sottochiave(radice, b"veil-pm-db-" + sale_db)))


def carica_db(radice):
    if not DB_FILE.exists():
        return []
    dati = DB_FILE.read_bytes()
    if not dati.startswith(MAGIC) or len(dati) < len(MAGIC) + SALT_SIZE + 1:
        raise ValueError("not a veil_pm database")
    sale_db = dati[len(MAGIC):len(MAGIC) + SALT_SIZE]
    token = dati[len(MAGIC) + SALT_SIZE:]
    try:
        return json.loads(chiave_db(radice, sale_db).decrypt(token))
    except InvalidToken:
        raise ValueError("wrong passphrase or corrupted database")


def salva_db(radice, voci):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    sale_db = os.urandom(SALT_SIZE)
    confezione = MAGIC + sale_db + chiave_db(radice, sale_db).encrypt(json.dumps(voci).encode())
    fd = os.open(DB_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(confezione)


# ----- authentication -----

def primo_avvio(args):
    prepara_config()
    if SALT_FILE.exists():
        raise SystemExit("veil_pm: already initialized")
    while True:
        frase = _chiedi_frase("Choose a veil_pm passphrase (at least 12 characters): ")
        if not frase:
            continue
        if len(frase) < 12 and input("Very short, use it anyway? [y/N]: ").strip().lower() != "y":
            continue
        conferma = _chiedi_frase("Repeat the passphrase: ")
        if conferma != frase:
            print("They differ, try again")
            continue
        break
    sale = os.urandom(SALT_SIZE)
    scrivi_privato(SALT_FILE, sale)
    radice = radice_kdf(frase, sale)
    scrivi_privato(CHECK_FILE, hmac.new(radice, b"veil-pm-check", hashlib.sha256).digest()[:16])
    print(f"veil_pm initialized. KDF: {kdf_attivo()} | Database: {DB_FILE}")


def sblocca():
    prepara_config()
    if not SALT_FILE.exists():
        print("First launch: this password manager has no passphrase yet.")
        primo_avvio(None)
    for _ in range(3):
        frase = legge_frase()
        if not frase:
            continue
        radice = deriva(frase)
        if radice is not None and verifica(radice):
            return radice
        print("[!] Wrong passphrase")
    raise SystemExit("veil_pm: too many failed attempts")


# ----- commands -----

def do_list(radice):
    voci = carica_db(radice)
    if not voci:
        print("(empty)")
        return
    for v in voci:
        extra = f" ({v.get('username', '')})" if v.get("username") else ""
        print(f"{v['site']}{extra}")


def do_add(radice, sito):
    if not sito:
        print("Usage: add <site>")
        return
    voci = carica_db(radice)
    if any(v["site"] == sito for v in voci):
        print(f"{sito} already saved (use 'change' to update)")
        return
    username = input(f"username for {sito}: ").strip()
    password = _chiedi_frase(f"password for {sito}: ")
    nota = input("note (optional): ").strip()
    voci.append({"site": sito, "username": username, "password": password, "note": nota})
    salva_db(radice, voci)
    print(f"Saved: {sito}")


def do_get(radice, sito, copia=False):
    voci = carica_db(radice)
    for v in voci:
        if v["site"] == sito:
            print(f"site:     {v['site']}")
            if v.get("username"):
                print(f"username: {v['username']}")
            print(f"password: {v['password']}")
            if v.get("note"):
                print(f"note:     {v['note']}")
            if copia:
                if _copia(v["password"]):
                    print("(password copied to clipboard)")
                else:
                    print("(failed to copy to clipboard)")
            return
    print(f"not found: {sito}")


def do_find(radice, testo):
    voci = carica_db(radice)
    trovati = [v for v in voci if testo.lower() in v["site"].lower()]
    if not trovati:
        print("(no matches)")
        return
    for v in trovati:
        extra = f" ({v.get('username', '')})" if v.get("username") else ""
        print(f"{v['site']}{extra}")


def do_change(radice, sito):
    voci = carica_db(radice)
    for v in voci:
        if v["site"] == sito:
            nuova = _chiedi_frase(f"new password for {sito}: ")
            if not nuova:
                print("cancelled (empty password)")
                return
            v["password"] = nuova
            salva_db(radice, voci)
            print(f"Updated: {sito}")
            return
    print(f"not found: {sito}")


def do_rm(radice, sito):
    voci = carica_db(radice)
    rimanenti = [v for v in voci if v["site"] != sito]
    if len(rimanenti) == len(voci):
        print(f"not found: {sito}")
        return
    salva_db(radice, rimanenti)
    print(f"Removed: {sito}")


def _copia(testo):
    def prova(cmd, testo):
        if not shutil.which(cmd):
            return False
        try:
            env = os.environ.copy()
            args = [cmd]
            if cmd == "xclip":
                args.extend(["-selection", "clipboard", "-in"])
            elif cmd == "xsel":
                args.extend(["--clipboard", "--input"])
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            out, err = proc.communicate(testo.encode(), timeout=2)
            return proc.returncode == 0
        except Exception:
            return False

    # Preferiti per ambiente corrente
    preferiti = []
    if os.environ.get("WAYLAND_DISPLAY"):
        preferiti.extend(["wl-copy", "wl-clipboard"])
        if os.environ.get("DISPLAY"):
            preferiti.extend(["xclip", "xsel"])
    elif os.environ.get("DISPLAY"):
        preferiti.extend(["xclip", "xsel", "wl-copy"])
    preferiti.append("pbcopy")

    # 1. prova comandi specifici
    for cmd in preferiti:
        if prova(cmd, testo):
            return True

    # 2. prova tutti gli altri
    for cmd in ("wl-copy", "wl-clipboard", "xclip", "xsel", "pbcopy", "termux-clipboard-set"):
        if cmd in preferiti:
            continue
        if prova(cmd, testo):
            return True

    # 3. fallback con GTK
    try:
        import gi
        gi.require_version('Gtk', '3.0')
        from gi.repository import Gtk, Gdk
        d = Gdk.Display.get_default()
        if d is None:
            raise RuntimeError("no display")
        clip = Gtk.Clipboard.get_for_display(d, Gdk.SELECTION_CLIPBOARD)
        clip.set_text(str(testo), -1)
        clip.store()
        return True
    except Exception:
        try:
            import gi
            gi.require_version('Gtk', '3.0')
            from gi.repository import Gtk, Gdk
            clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clip.set_text(str(testo), -1)
            clip.store()
            return True
        except Exception:
            pass

    # 4. fallback con tkinter
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(str(testo))
        r.update()
        r.destroy()
        return True
    except Exception:
        pass

    return False


def banner():
    try:
        subprocess.run(["figlet", "-f", "slant", "Veil_pm"])
    except FileNotFoundError:
        print("V E I L _ P M")


AIUTO = """Commands:
  list                  show all saved sites
  add <site>            add a new password (asks for username/password)
  get <site> [-c]       show an entry (-c copies the password to the clipboard)
  find <text>           search sites by name
  change <site>         update the password of a site
  rm <site>             delete an entry
  help                  show this help
  q / quit              exit
"""


def elabora(riga, radice):
    pulito = riga.strip()
    if not pulito:
        return True
    parole = pulito.split()
    cmd = parole[0].lower()
    if cmd in ("q", "quit", "exit"):
        return False
    if cmd in ("h", "help", "?"):
        print(AIUTO)
        return True
    if cmd in ("list", "ls"):
        try:
            do_list(radice)
        except ValueError as e:
            print(e)
        return True
    if cmd == "add":
        try:
            do_add(radice, parole[1] if len(parole) > 1 else None)
        except ValueError as e:
            print(e)
        return True
    if cmd == "get":
        if len(parole) < 2:
            print("Usage: get <site> [-c]")
            return True
        try:
            do_get(radice, parole[1], "-c" in parole)
        except ValueError as e:
            print(e)
        return True
    if cmd == "find":
        if len(parole) < 2:
            print("Usage: find <text>")
            return True
        try:
            do_find(radice, parole[1])
        except ValueError as e:
            print(e)
        return True
    if cmd == "change":
        if len(parole) < 2:
            print("Usage: change <site>")
            return True
        do_change(radice, parole[1])
        return True
    if cmd in ("rm", "del"):
        if len(parole) < 2:
            print("Usage: rm <site>")
            return True
        do_rm(radice, parole[1])
        return True
    print(f"Unknown command: {cmd} (try 'help')")
    return True


def main():
    parser = argparse.ArgumentParser(
        prog="pm",
        description="veil_pm - password manager. Run it, unlock with the passphrase and "
                    "use the interactive prompt.",
    )
    parser.parse_args()
    banner()
    radice = None
    while radice is None:
        print("Unlock the password manager (this terminal session only).")
        try:
            radice = sblocca()
        except SystemExit as e:
            print(e)
            return
    print(f"Database: {DB_FILE}")
    print("(q to quit)\n")
    try:
        while True:
            try:
                riga = input(">>> ")
            except (KeyboardInterrupt, EOFError):
                print("\nBye!")
                break
            if not elabora(riga, radice):
                print("Bye!")
                break
    finally:
        pass


if __name__ == "__main__":
    main()
