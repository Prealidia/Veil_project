#!/usr/bin/env python3
# chatdefender / newVeil.py
# Chat e scambio file cifrati end-to-end sulla LAN (versione 4 del protocollo).
#
# Correzioni rispetto a veil.py:
#   - il pin dell'identita' del peer viene scritto SOLO dopo che l'handshake e'
#     stato autenticato (prima un impostore senza passphrase poteva avvelenare
#     il pin e bloccare per sempre il peer legittimo)
#   - la passphrase non viene piu' scritta in chiaro su disco: si digita a ogni
#     avvio, e diventa persistente solo con --save-passphrase
#   - passphrase corte o predicibili rifiutate con avviso esplicito: chi cattura
#     un handshake puo' verificarle OFFLINE senza limiti di tentativi, quindi
#     l'unica difesa e' l'entropia (5-6 parole casuali)
#   - il mini-ban sugli IP non autorizzati viene davvero applicato, e il log di
#     sicurezza dice la verita'
#   - tetto alle connessioni TCP contemporanee: oltre, si chiude senza creare thread
#   - tetto di spazio (QUOTA_RICEZIONE) sui file ricevuti
#   - config.json scritto direttamente a 0600 (niente finestra con i permessi
#     dell'umask) e pulizia anche dei controlli di terminale C1 a 8 bit
import argparse
import atexit
import codecs
import ctypes
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime
from pathlib import Path

try:
    import readline
except ImportError:
    pass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PORT = 50000
BUFFER_SIZE = 65536
CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_TOKEN = CHUNK_SIZE + 4096
MAX_MSG_SIZE = 1024 * 1024
SOCKET_TIMEOUT = 120
ARGON2_TEMPO = 3
ARGON2_MEMORIA_KIB = 65536
ARGON2_PARALLELISMO = 4
DROP_DIR = Path.home() / "localdrop"
MESSAGGI_DIR = DROP_DIR / "messaggi"
SECURITY_LOG = Path.home() / ".local" / "state" / "chatdefender" / "sicurezza.log"

# Versione del protocollo di handshake: deve coincidere sui due PC
VERSIONE_PROTOCOLLO = 4

# Proof-of-work: l'iniziatore deve trovare un nonce tale che
# sha256(prefisso+sfida+nonce) abbia DIFFICOLTA_POW zeri binari in testa,
# altrimenti il server non spreca i suoi 64MB di argon2
DIFFICOLTA_POW = 17

# Prima dell'autenticazione niente gentilezze: timeout corto per chi si fa
# desiderare (dopo l'handshake vale il timeout pieno, serve ai file grandi)
TIMEOUT_PRE_AUTH = 30

# Mini-ban: dopo TENTATIVI_BAN rifiuti in DURATA_BAN secondi l'IP viene bloccato
TENTATIVI_BAN = 5
DURATA_BAN = 600

# Massimo di handshake contemporanei: ogni argon2id occupa 64MB, meglio non farli
# tutti in parallelo o bastano poche connessioni per soffocare la macchina
SEM_HANDSHAKE = threading.Semaphore(3)

# Connessioni TCP contemporanee accettate: oltre questo numero chiudiamo subito,
# senza creare un thread. Senza tetto, un flood di connessioni aperte a meta'
# handshake consumerebbe thread e memoria fino a far cadere il processo.
MAX_CONNESSIONI = 16
SEM_CONNESSIONI = threading.BoundedSemaphore(MAX_CONNESSIONI)
RICEVUTE = {"connessioni": 0, "rifiutate": 0}
LOCK_RICEVUTE = threading.Lock()

# Tetto di spazio per i file ricevuti nella cartella condivisa: un peer
# autenticato non deve poterci riempire il disco.
# La verifica dello spazio va accoppiata alla prenotazione: con piu'
# connessioni in parallelo, ognuna vede il disco "libero" prima che le
# altre scrivano e il tetto finisce per essere superato.
QUOTA_RICEZIONE = 2 * 1024 * 1024 * 1024
LOCK_QUOTA = threading.Lock()
RISERVATA_QUOTA = {"byte": 0}

# Passphrase: di norma NON viene scritta su disco. Chiunque legga il file
# 'password' ottiene la chiave madre di log e identita', quindi conviene
# digitarla a ogni avvio. Con --save-passphrase torna a essere salvata.
LUNGHEZZA_MINIMA_PASSPHRASE = 16
PASSPHRASE_PERSISTENTE = False
_SCHELERI = None

# I messaggi vengono gonfiati fino alla soglia successiva per nascondere le lunghezze
PADDING_SOGLIE = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
                  131072, 262144, 524288]

CONFIG_DIR = Path.home() / ".config" / "localdrop"
CONFIG_FILE = CONFIG_DIR / "config.json"
IDENTITY_FILE = CONFIG_DIR / "identity.key"
PEER_IDENTITY_FILE = CONFIG_DIR / "peer_identity.key"
PASSWORD_FILE = CONFIG_DIR / "password"
LOG_SALT_FILE = CONFIG_DIR / "log_salt"
KDF_FILE = CONFIG_DIR / "kdf"

STATO_INPUT = {"bozza": "", "attivo": False}
LOCK_OUTPUT = threading.Lock()
RE_CONTROLLO = re.compile(
    r"\x1b\[[0-9;:?]*[a-zA-Z]|\x1b\][^\x07]*(?:\x07|\x1b\\)"
    r"|[\x00-\x1f\x7f\x80-\x9f]"
)
PASSWORD_GLOBALE = ""
AVVISO_KDF = False

# Stato del mini-ban: tentativi di rifiuto per IP e scadenze dei ban attivi
# (solo in memoria: si azzera al riavvio). La struttura viene ripulita
# periodicamente, altrimenti un attacco da tanti IP la farebbe crescere
# senza limite e consuma memoria.
BAN = {"tentativi": {}, "scadenze": {}, "ultimo_sweep": 0.0}
LOCK_BAN = threading.Lock()
SWEEP_BAN = 60.0

# Rotation guard for the (plaintext, local) security log
LOCK_SEC_LOG = threading.Lock()

# Fernet per i log dei messaggi, derivato dalla passphrase (creazione pigra)
CHIAVE_LOG = None
CHIAVE_IDENTITA = None
LOCK_CHIAVE_LOG = threading.Lock()
LOCK_PEER = threading.Lock()


def _radice_con(metodo, sale):
    segreto = PASSWORD_GLOBALE.encode()
    if metodo == "argon2id":
        return argon2id(segreto, sale)
    return hashlib.pbkdf2_hmac("sha256", segreto, sale, 600_000)


def _ricifra_log_con(fernet_log_vecchio):
    if not MESSAGGI_DIR.exists():
        return
    lasciate = 0
    nuovo_fernet = ottieni_chiave_log()
    for cronologia in sorted(MESSAGGI_DIR.glob("*.log")):
        uscita = []
        for riga in cronologia.read_text().splitlines():
            try:
                uscita.append(nuovo_fernet.encrypt(fernet_log_vecchio.decrypt(riga.encode())).decode())
            except (InvalidToken, ValueError):
                uscita.append(riga)
                lasciate += 1
        scrivi_privato(cronologia, ("\n".join(uscita) + "\n").encode())
    if lasciate:
        print(f"[!] {lasciate} lines not re-encrypted, left as they were")


def riallinea_identita(dati):
    sale = LOG_SALT_FILE.read_bytes() if LOG_SALT_FILE.exists() else os.urandom(16)
    attivo = kdf_attivo()
    ordine = [attivo] + [m for m in ("argon2id", "pbkdf2") if m != attivo]
    global CHIAVE_LOG, CHIAVE_IDENTITA
    for metodo in ordine:
        radice = _radice_con(metodo, sale)
        if radice is None:
            continue
        chiave_id = Fernet(urlsafe_b64encode(sottochiave_hkdf(radice, b"chatdefender-identita")))
        try:
            privata = chiave_id.decrypt(dati)
        except InvalidToken:
            continue
        if metodo != attivo:
            scrivi_privato(KDF_FILE, (metodo + "\n").encode())
            CHIAVE_LOG = None
            CHIAVE_IDENTITA = None
            scrivi_privato(IDENTITY_FILE, ottieni_chiave_identita().encrypt(privata) + b"\n")
            print(f"[!] Environment changed: local KDF switched back to {metodo}, identity re-encrypted")
            _ricifra_log_con(Fernet(urlsafe_b64encode(radice)))
        return privata
    return None


def prepara_cartella_privata(percorso):
    # 0700: nessun altro utente puo' vedere i nomi dei file ricevuti,
    # i log delle chat o i file di configurazione (metadati = privacy)
    try:
        percorso.mkdir(parents=True, exist_ok=True)
        percorso.chmod(0o700)
    except OSError:
        pass


def prepara_cartella_config():
    prepara_cartella_privata(CONFIG_DIR)
    # I file creati da versioni vecchie del programma potevano restare 0644:
    # si rimettono a 0600 a ogni avvio, cosi' nessuno legge identita' e salti
    try:
        for voce in CONFIG_DIR.iterdir():
            if voce.is_file() and not voce.is_symlink():
                try:
                    voce.chmod(0o600)
                except OSError:
                    pass
    except OSError:
        pass


def scrivi_privato(percorso, dati):
    prepara_cartella_config()
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, "wb") as f:
        f.write(dati)


def copia_privata(sorgente, destinazione):
    # Copia in 0600 e con O_NOFOLLOW: niente file del drop leggibili da
    # altri utenti, e nessuna sovrascrittura se il percorso e' un symlink
    with open(sorgente, "rb") as fsrc:
        fd = os.open(destinazione, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)


def kdf_attivo():
    scelta = os.environ.get("CHATDEFENDER_KDF")
    if scelta in ("argon2id", "pbkdf2"):
        return scelta
    prepara_cartella_config()
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


def radice_kdf(sale):
    segreto = PASSWORD_GLOBALE.encode()
    if kdf_attivo() == "argon2id":
        chiave = argon2id(segreto, sale)
        if chiave is not None:
            return chiave
        avvisa("[!] libargon2 is missing but the data is encrypted with argon2: PBKDF2 will not decrypt it!")
    return hashlib.pbkdf2_hmac("sha256", segreto, sale, 600_000)


def sottochiave_hkdf(radice, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(radice)


def sanifica(testo):
    return RE_CONTROLLO.sub(" ", testo)


def ridisegna_input():
    sys.stdout.write(f"\r\x1b[2K> {STATO_INPUT['bozza']}")
    sys.stdout.flush()


def avvisa(testo):
    # Unico punto da cui parlano i thread in background: qualsiasi cosa
    # arrivi da un peer (nomi, errori) passa da qui, quindi viene ripulita
    # prima di toccare il terminale (iniezione di sequenze di controllo)
    testo = sanifica(str(testo))
    with LOCK_OUTPUT:
        sys.stdout.write("\r\x1b[2K\n" + testo + "\n")
        if STATO_INPUT["attivo"]:
            ridisegna_input()
        sys.stdout.flush()


def scarta_sequenza(fd):
    while True:
        pronto, _, _ = select.select([fd], [], [], 0.05)
        if not pronto:
            return False
        byte = os.read(fd, 1)
        if byte and 0x40 <= byte[0] <= 0x7E:
            return True


def attiva_input_raw():
    try:
        fd = sys.stdin.fileno()
        STATO_INPUT["salvate"] = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        STATO_INPUT["attivo"] = True
        STATO_INPUT["raw"] = True
    except (termios.error, ValueError):
        STATO_INPUT["raw"] = False


def ripristina_input():
    if STATO_INPUT.get("raw"):
        try:
            fd = sys.stdin.fileno()
            if STATO_INPUT.get("salvate"):
                termios.tcsetattr(fd, termios.TCSADRAIN, STATO_INPUT["salvate"])
        except (ValueError, termios.error, OSError):
            pass
    STATO_INPUT["raw"] = False
    STATO_INPUT["attivo"] = False
    STATO_INPUT["bozza"] = ""


def completa_percorso():
    with LOCK_OUTPUT:
        bozza = STATO_INPUT["bozza"]
        parti = bozza.rsplit(" ", 1)
        token = parti[-1]
        if not token:
            return
        citato = token.startswith('"')
        espanso = os.path.expanduser(token.strip('"'))
        head, sep, prefisso = espanso.rpartition("/")
        if sep:
            cartella_str = (head + sep) if head else "/"
        else:
            cartella_str, prefisso = ".", espanso
        try:
            corrispondenze = sorted(Path(cartella_str).glob(prefisso + "*"))
        except (OSError, ValueError):
            return
        if not corrispondenze:
            return
        nomi = [c.name + ("/" if c.is_dir() else "") for c in corrispondenze]
        comune = os.path.commonprefix(nomi)
        completato = cartella_str + comune
        if " " in completato or citato:
            completato = '"' + completato + '"'
        STATO_INPUT["bozza"] = parti[0] + " " + completato if len(parti) > 1 else completato
        ridisegna_input()
        if len(corrispondenze) > 1:
            anteprima = "  ".join(nomi[:15]) + (" ..." if len(nomi) > 15 else "")
            sys.stdout.write("\n" + anteprima + "\n")
            ridisegna_input()
        sys.stdout.flush()


def leggi_riga():
    if not STATO_INPUT.get("raw"):
        return input(">>> ")
    fd = sys.stdin.fileno()
    decodificatore = codecs.getincrementaldecoder("utf-8")()
    stato_esc = 0
    while True:
        dati = os.read(fd, 256)
        if not dati:
            raise EOFError
        for carattere in decodificatore.decode(dati):
            if stato_esc == 2:
                if 0x40 <= ord(carattere) <= 0x7E:
                    stato_esc = 0
                continue
            if stato_esc == 1:
                stato_esc = 2 if carattere in ("[", "O") else 0
                continue
            if carattere in ("\r", "\n"):
                with LOCK_OUTPUT:
                    riga = STATO_INPUT["bozza"]
                    STATO_INPUT["bozza"] = ""
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                return riga
            if carattere in ("\x7f", "\x08"):
                with LOCK_OUTPUT:
                    STATO_INPUT["bozza"] = STATO_INPUT["bozza"][:-1]
                    ridisegna_input()
            elif carattere == "\x1b":
                stato_esc = 1
            elif carattere == "\x03":
                raise KeyboardInterrupt
            elif carattere == "\x04":
                raise EOFError
            elif carattere == "\t":
                completa_percorso()
            elif carattere >= " ":
                with LOCK_OUTPUT:
                    STATO_INPUT["bozza"] += carattere
                    ridisegna_input()
        if stato_esc != 0 and not scarta_sequenza(fd):
            stato_esc = 0


def banner():
    try:
        subprocess.run(["figlet", "-f", "slant", "Veil"])
    except FileNotFoundError:
        print("V E I L")


def ottieni_chiave_log():
    global CHIAVE_LOG
    if CHIAVE_LOG is not None:
        return CHIAVE_LOG
    with LOCK_CHIAVE_LOG:
        if CHIAVE_LOG is not None:
            return CHIAVE_LOG
        prepara_cartella_config()
        if LOG_SALT_FILE.exists():
            sale = LOG_SALT_FILE.read_bytes()
        else:
            sale = os.urandom(16)
            scrivi_privato(LOG_SALT_FILE, sale)
        CHIAVE_LOG = Fernet(urlsafe_b64encode(radice_kdf(sale)))
        return CHIAVE_LOG


def ottieni_chiave_identita():
    global CHIAVE_IDENTITA
    if CHIAVE_IDENTITA is not None:
        return CHIAVE_IDENTITA
    with LOCK_CHIAVE_LOG:
        if CHIAVE_IDENTITA is not None:
            return CHIAVE_IDENTITA
        if LOG_SALT_FILE.exists():
            sale = LOG_SALT_FILE.read_bytes()
        else:
            sale = os.urandom(16)
            scrivi_privato(LOG_SALT_FILE, sale)
        radice = radice_kdf(sale)
        CHIAVE_IDENTITA = Fernet(urlsafe_b64encode(
            sottochiave_hkdf(radice, b"chatdefender-identita")
        ))
        return CHIAVE_IDENTITA


def registra_messaggio(direzione, peer_ip, testo):
    prepara_cartella_privata(MESSAGGI_DIR)
    # Sanifica PRIMA di scrivere: le righe vengono rilette e stampate con
    # --read-log, quindi non devono mai contenere sequenze di controllo
    testo = sanifica(str(testo)).strip()
    ora = datetime.now()
    cronologia = MESSAGGI_DIR / f"{ora:%Y-%m-%d}.log"
    riga = f"[{ora:%d/%m/%Y %H:%M:%S}] {direzione} {peer_ip}: {testo}"
    token = ottieni_chiave_log().encrypt(riga.encode())
    fd = os.open(cronologia, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, "ab") as f:
        f.write(token + b"\n")


def leggi_log():
    if not MESSAGGI_DIR.exists():
        print("No messages saved.")
        return
    chiave = ottieni_chiave_log()
    for cronologia in sorted(MESSAGGI_DIR.glob("*.log")):
        print(f"--- {cronologia.name} ---")
        scartate = 0
        for riga in cronologia.read_text().splitlines():
            try:
                print(sanifica(chiave.decrypt(riga.encode()).decode()))
            except (InvalidToken, ValueError):
                scartate += 1
        if scartate:
            print(f"({scartate} lines not decryptable: passphrase changed or old-format log)")


def dimentica_storico(giorni):
    # Lo storico chat resta su disco per sempre se nessuno lo cancella:
    # chiunque legga il backup della cartella ha il passato delle chat.
    # 0 = elimina tutto, N = solo i file piu' vecchi di N giorni.
    if not MESSAGGI_DIR.exists():
        return 0
    limite = time.time() - max(0, int(giorni)) * 86400
    rimossi = 0
    for cronologia in MESSAGGI_DIR.glob("*.log"):
        try:
            if int(giorni) == 0 or cronologia.stat().st_mtime < limite:
                cronologia.unlink()
                rimossi += 1
        except OSError:
            pass
    return rimossi


def registra_sicurezza(ip, motivo, ban=False):
    motivo = sanifica(str(motivo)).strip() or "unknown"
    azione = "ban" if ban else "note"
    riga = f"{datetime.now():%Y-%m-%d %H:%M:%S} REJECTED ip={ip} reason={motivo} action={azione}\n"
    try:
        prepara_cartella_privata(SECURITY_LOG.parent)
        with LOCK_SEC_LOG:
            # Rotazione: il log e' in chiaro (indirizzi + motivi) e un attacco
            # puo' farlo crescere senza limite, riempiendo il disco
            if SECURITY_LOG.exists() and SECURITY_LOG.stat().st_size > 5 * 1024 * 1024:
                rotato = SECURITY_LOG.with_name(SECURITY_LOG.name + ".vecchio")
                rotato.unlink(missing_ok=True)
                SECURITY_LOG.replace(rotato)
            fd = os.open(SECURITY_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "ab") as f:
                f.write(riga.encode())
    except OSError:
        pass


def registra_rifiuto(ip):
    with LOCK_BAN:
        ora = time.monotonic()
        if ora - BAN["ultimo_sweep"] > SWEEP_BAN:
            # Ripulisce le voci scadute: senza questo, il dizionario cresce
            # senza limite (una voci per IP sconosciuto, per sempre)
            BAN["ultimo_sweep"] = ora
            for ip2 in list(BAN["tentativi"]):
                vivi = [t for t in BAN["tentativi"][ip2] if ora - t < DURATA_BAN]
                if vivi:
                    BAN["tentativi"][ip2] = vivi
                else:
                    del BAN["tentativi"][ip2]
            for ip2 in [k for k, sc in BAN["scadenze"].items() if ora >= sc]:
                del BAN["scadenze"][ip2]
        tentativi = [t for t in BAN["tentativi"].get(ip, []) if ora - t < DURATA_BAN]
        tentativi.append(ora)
        BAN["tentativi"][ip] = tentativi
        if len(tentativi) >= TENTATIVI_BAN:
            BAN["scadenze"][ip] = ora + DURATA_BAN
            BAN["tentativi"].pop(ip, None)
            return True
    return False


def bannato(ip):
    with LOCK_BAN:
        scadenza = BAN["scadenze"].get(ip)
        if scadenza is None:
            return False
        if time.monotonic() >= scadenza:
            del BAN["scadenze"][ip]
            return False
        return True


def leggi_config(notifica=True):
    if not CONFIG_FILE.exists():
        return None
    try:
        dati = json.loads(CONFIG_FILE.read_text())
        if isinstance(dati, dict):
            return dati
    except (json.JSONDecodeError, TypeError):
        pass
    if notifica:
        print("Corrupted configuration, enter it again")
    return None


def aggiorna_config(**campi):
    prepara_cartella_config()
    dati = {}
    if CONFIG_FILE.exists():
        try:
            letti = json.loads(CONFIG_FILE.read_text())
            if isinstance(letti, dict):
                dati = letti
        except (json.JSONDecodeError, TypeError):
            pass
    dati.update(campi)
    scrivi_privato(CONFIG_FILE, json.dumps(dati).encode())


def carica_peer_ip(cfg):
    prepara_cartella_config()
    if cfg is not None:
        dati = cfg.get("peer_ip")
        if isinstance(dati, str):
            return [dati]
        if isinstance(dati, list) and dati:
            return [str(x) for x in dati]
        print("Corrupted configuration, enter it again")
    ip = input("First setup - IP of the second computer (multiple IPs separated by commas: LAN and/or Tailscale): ").strip()
    while not ip:
        ip = input("Invalid IP, try again: ").strip()
    ip_list = [x.strip() for x in ip.split(",") if x.strip()]
    aggiorna_config(peer_ip=ip_list)
    print(f"IPs saved to {CONFIG_FILE}: {', '.join(ip_list)}")
    return ip_list


def risolvi_consentiti(voci):
    # L'allowlist confronta gli indirizzi sorgente (stringhe IP): se
    # l'utente ha configurato un nome (es. il nome Tailscale) il peer
    # verrebbe scambiato per intruso e bannato. Si risolve quindi all'avvio.
    ip_consentiti = []
    for voce in voci:
        voce = str(voce).strip()
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", voce)
        if m:
            voce = m.group(1)
        m = re.fullmatch(r"\[([^\]]+)\](?::\d+)?", voce)
        if m:
            voce = m.group(1)
        try:
            ipaddress.ip_address(voce)
            if voce not in ip_consentiti:
                ip_consentiti.append(voce)
            continue
        except ValueError:
            pass
        try:
            risolti = sorted({info[4][0] for info in
                              socket.getaddrinfo(voce, PORT, proto=socket.IPPROTO_TCP)})
        except OSError:
            print(f"[!] Cannot resolve '{voce}': it will NOT be accepted as a peer "
                  "(put its IP address instead)")
            continue
        for ip in risolti:
            if ip not in ip_consentiti:
                ip_consentiti.append(ip)
        print(f"'{voce}' resolves to: {', '.join(risolti)}")
    return ip_consentiti


def connetti(peers):
    ultimo = None
    for peer in peers:
        try:
            return socket.create_connection((peer, PORT), timeout=5)
        except OSError as e:
            ultimo = e
    raise ultimo


def salva_passphrase_su_disco(salvala):
    """Scrive o cancella il file 'password'. La passphrase non deve MAI restare
    in chiaro su disco senza che l'utente lo chieda esplicitamente."""
    global PASSPHRASE_PERSISTENTE
    PASSPHRASE_PERSISTENTE = salvala
    if salvala:
        PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            PASSWORD_FILE.parent.chmod(0o700)
        except OSError:
            pass
        scrivi_privato(PASSWORD_FILE, (PASSWORD_GLOBALE + "\n").encode())
        print(f"Passphrase saved to {PASSWORD_FILE} (use the SAME one on the other PC!)")
    else:
        try:
            PASSWORD_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        print("Passphrase kept in memory only, NOT written to disk. "
              "Use --save-passphrase if you prefer to store it.")


def _scheletri_comuni():
    # Parole/cifre tipiche: se la passphrase contiene una di queste, e' una
    # parola sola piu' qualche numero, la tipo "Nome2024" o "Password123!"
    global _SCHELERI
    if _SCHELERI is None:
        basi = (
            "password admin root user utente veil chat defender chatdefender "
            "qwerty asdf zxcv secret segreto chiave key login access ciao benvenuto"
        ).split()
        parole = {p for p in basi if len(p) >= 4}
        numeri = ("1", "12", "123", "1234", "12345", "2020", "2021", "2022", "2023",
                  "2024", "2025", "2026", "00", "01", "007")
        for p in list(parole):
            for n in numeri:
                parole.add(p + n)
                parole.add(n + p)
        _SCHELERI = parole
    return _SCHELERI


def forza_passphrase(valore):
    """Restituisce i motivi per cui la passphrase e' debole (lista vuota = ok)."""
    motivi = []
    pezzi = [p for p in re.split(r"[^A-Za-z]+", valore) if p]
    if len(valore) < LUNGHEZZA_MINIMA_PASSPHRASE:
        motivi.append(f"only {len(valore)} characters (minimum {LUNGHEZZA_MINIMA_PASSPHRASE})")
    if len(pezzi) <= 1 and not any(c.isdigit() for c in valore):
        motivi.append("a single word with no numbers")
    elif len(pezzi) <= 1 and len(valore) < LUNGHEZZA_MINIMA_PASSPHRASE + 4:
        motivi.append("one word plus a short number")
    elif len(pezzi) < 4 and len(valore) < 24:
        motivi.append("few words: prefer 5-6 random words")
    if valore.lower() in _scheletri_comuni():
        motivi.append("too predictable")
    return motivi


def chiedi_passphrase(messaggio, conferma_messaggio=None):
    try:
        stdin_is_tty = sys.stdin.isatty()
    except Exception:
        stdin_is_tty = False
    while True:
        try:
            if stdin_is_tty:
                valore = getpass.getpass(messaggio).strip()
            else:
                sys.stdout.write(messaggio)
                sys.stdout.flush()
                linea = sys.stdin.readline()
                if not linea:
                    raise EOFError
                valore = linea.rstrip("\n\r").strip()
        except (EOFError, KeyboardInterrupt):
            raise
        if not valore:
            continue
        if conferma_messaggio is not None:
            try:
                if stdin_is_tty:
                    conf = getpass.getpass(conferma_messaggio).strip()
                else:
                    sys.stdout.write(conferma_messaggio)
                    sys.stdout.flush()
                    linea = sys.stdin.readline()
                    if not linea:
                        raise EOFError
                    conf = linea.rstrip("\n\r").strip()
            except (EOFError, KeyboardInterrupt):
                raise
            if conf != valore:
                print("They differ, try again")
                continue
        motivi = forza_passphrase(valore)
        if motivi:
            print("Weak passphrase:")
            for m in motivi:
                print(f"  - {m}")
            print("Anyone who captures one handshake can try it OFFLINE against the "
                  "passphrase, at full speed, with no limit on attempts. Only entropy "
                  "protects you here: use 5-6 random words, or a random string.")
            try:
                if stdin_is_tty:
                    resp = input("Use it anyway? [y/N]: ").strip().lower()
                else:
                    sys.stdout.write("Use it anyway? [y/N]: ")
                    sys.stdout.flush()
                    r = sys.stdin.readline()
                    resp = r.rstrip("\n\r").strip().lower() if r else 'n'
            except Exception:
                resp = 'n'
            if resp != 'y':
                continue
        return valore

def carica_password():
    global PASSWORD_GLOBALE, PASSPHRASE_PERSISTENTE
    prepara_cartella_config()
    salvata = ""
    if PASSWORD_FILE.exists():
        try:
            salvata = PASSWORD_FILE.read_text().strip()
        except OSError:
            salvata = ""
    if salvata and not PASSPHRASE_PERSISTENTE:
        # Un file 'password' e' rimasto da un precedente --save-passphrase:
        # non lo cancelliamo in silenzio (chi l'ha salvato potrebbe restare
        # fuori da log e identita'), ma lo chiediamo e l'utente decide
        if sys.stdin.isatty():
            print(f"[!] A passphrase is saved ON DISK at {PASSWORD_FILE}.")
            print("    Anyone who reads that file can decrypt your logs and identity.")
            try:
                risposta = input("    Keep it and use it? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                risposta = "n"
            if risposta == "y":
                PASSPHRASE_PERSISTENTE = True
        if not PASSPHRASE_PERSISTENTE:
            try:
                PASSWORD_FILE.unlink(missing_ok=True)
            except OSError:
                pass
            print(f"[!] Saved passphrase removed from {PASSWORD_FILE} "
                  "(privacy default: nothing secret stays on disk)")
            salvata = ""
    if salvata and PASSPHRASE_PERSISTENTE:
        PASSWORD_GLOBALE = salvata
        if not forza_passphrase(salvata):
            return
        print("[!] The saved passphrase is weak: anyone capturing a handshake "
              "could try it offline. Run --change-password to replace it.")
    valore = chiedi_passphrase(
        f"Passphrase (at least {LUNGHEZZA_MINIMA_PASSPHRASE} characters, "
        "5-6 random words recommended): ",
        "Repeat it: ",
    )
    PASSWORD_GLOBALE = valore
    if PASSPHRASE_PERSISTENTE:
        scrivi_privato(PASSWORD_FILE, (valore + "\n").encode())
        print(f"Passphrase saved to {PASSWORD_FILE} (use the SAME one on the other PC!)")
    else:
        salva_passphrase_su_disco(False)


def argon2id(segreto, sale):
    try:
        lib = ctypes.CDLL("libargon2.so.1")
    except OSError:
        return None
    lib.argon2id_hash_raw.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    uscita = ctypes.create_string_buffer(32)
    rc = lib.argon2id_hash_raw(
        ARGON2_TEMPO,
        ARGON2_MEMORIA_KIB,
        ARGON2_PARALLELISMO,
        segreto,
        len(segreto),
        sale,
        len(sale),
        uscita,
        32,
    )
    if rc != 0:
        raise RuntimeError(f"argon2 error {rc}")
    return uscita.raw


def deriva_psk(sale):
    global AVVISO_KDF
    metodo = kdf_attivo()
    chiave = radice_kdf(sale[:16])
    if metodo != "argon2id" and not AVVISO_KDF:
        AVVISO_KDF = True
        avvisa("[!] Handshake using PBKDF2 (the method must be the same on both PCs!)")
    return chiave


def chiave_pubblica_raw(chiave):
    return chiave.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def impronta(pub_raw):
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def risolvi_pow(sale, bit):
    base = hashlib.sha256(b"chatdefender-pow" + sale)
    obiettivo = 1 << (256 - bit)
    contatore = 0
    while True:
        h = base.copy()
        h.update(contatore.to_bytes(8, "big"))
        if int.from_bytes(h.digest(), "big") < obiettivo:
            return contatore.to_bytes(8, "big")
        contatore += 1


def verifica_pow(sale, nonce, bit):
    obiettivo = 1 << (256 - bit)
    blocco = b"chatdefender-pow" + sale + nonce
    return int.from_bytes(hashlib.sha256(blocco).digest(), "big") < obiettivo


def ritardo_tarpit(ip):
    with LOCK_BAN:
        n = len(BAN["tentativi"].get(ip, []))
    if n > 0:
        time.sleep(min(n * 0.5, 3))


def carica_identita():
    prepara_cartella_config()
    if IDENTITY_FILE.exists():
        dati = IDENTITY_FILE.read_bytes().strip()
        chiave_id = ottieni_chiave_identita()
        try:
            privata = chiave_id.decrypt(dati)
        except InvalidToken:
            privata = riallinea_identita(dati)
        if privata is None:
            try:
                candidata = urlsafe_b64decode(dati)
            except Exception:
                candidata = b""
            if len(candidata) == 32:
                print("Identity found in plaintext: encrypting it with the passphrase")
                privata = candidata
                scrivi_privato(IDENTITY_FILE, chiave_id.encrypt(privata) + b"\n")
            else:
                raise SystemExit(
                    "Cannot read identity: different passphrase than the one used to encrypt it?\n"
                    "Restore the correct passphrase, or delete identity.key "
                    "(the peer will need to re-learn your new fingerprint)"
                )
        return X25519PrivateKey.from_private_bytes(privata)
    identita = X25519PrivateKey.generate()
    privata_raw = identita.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    scrivi_privato(IDENTITY_FILE, ottieni_chiave_identita().encrypt(privata_raw) + b"\n")
    print(f"Generated permanent encrypted identity: {impronta(chiave_pubblica_raw(identita))}")
    return identita


def ricorda_peer(pub_raw):
    # Scrive il pin solo DOPO che l'handshake e' stato autenticato: prima
    # autenticazione, un impostore potrebbe avvelenare il pin e bloccare per
    # sempre il peer vero. Il lock evita che un thread legga il file mentre
    # un altro lo sta troncando e riscrivingo.
    with LOCK_PEER:
        PEER_IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not PEER_IDENTITY_FILE.exists():
            scrivi_privato(PEER_IDENTITY_FILE, pub_raw)
            print(f"New peer stored (fingerprint {impronta(pub_raw)})")
    return


def verifica_peer(pub_raw):
    with LOCK_PEER:
        if PEER_IDENTITY_FILE.exists() and PEER_IDENTITY_FILE.read_bytes() != pub_raw:
            raise ValueError(
                "peer identity differs from the usual one: someone may be impersonating "
                "the other PC, or its key has been changed"
            )


def scambio_chiavi(sock, identita, iniziatore):
    effimero = X25519PrivateKey.generate()
    mio = bytes([VERSIONE_PROTOCOLLO]) + chiave_pubblica_raw(effimero) + chiave_pubblica_raw(identita)
    sock.sendall(struct.pack(">I", len(mio)) + mio)
    primo = recvall(sock, 4)
    if primo.startswith(b"ERR") or primo.startswith(b"OK"):
        motivo = sanifica(primo.decode(errors="replace")).strip()
        raise ValueError(f"rejection from peer before handshake ({motivo}): server busy or old version")
    lun = struct.unpack(">I", primo)[0]
    if lun == 64:
        raise ValueError("peer running an old version: update Veil on the other PC")
    if lun != 65:
        raise ValueError("invalid handshake")
    ricevuto = recvall(sock, lun)
    if ricevuto[0] != VERSIONE_PROTOCOLLO:
        raise ValueError(f"protocol version {ricevuto[0]} differs from ours ({VERSIONE_PROTOCOLLO}): align the versions on both PCs")
    altrui_eff = X25519PublicKey.from_public_bytes(ricevuto[1:33])
    altrui_ident = X25519PublicKey.from_public_bytes(ricevuto[33:])
    if iniziatore:
        pacchetto = recvall(sock, 4)
        if struct.unpack(">I", pacchetto)[0] != 17:
            raise ValueError("invalid proof-of-work challenge")
        sfida = recvall(sock, 16)
        difficolta = recvall(sock, 1)[0]
        if not 8 <= difficolta <= 26:
            raise ValueError("absurd proof-of-work difficulty")
        nonce = risolvi_pow(sfida, difficolta)
        sock.sendall(struct.pack(">I", 8) + nonce)
    else:
        sfida = os.urandom(16)
        sock.sendall(struct.pack(">I", 17) + sfida + bytes([DIFFICOLTA_POW]))
        lun_nonce = struct.unpack(">I", recvall(sock, 4))[0]
        if lun_nonce != 8:
            raise ValueError("invalid proof-of-work solution")
        nonce = recvall(sock, 8)
        if not verifica_pow(sfida, nonce, DIFFICOLTA_POW):
            raise ValueError("proof-of-work not solved")
    if iniziatore:
        trascrizione_proprio = b"I" + mio + ricevuto
        trascrizione_peer = b"R" + mio + ricevuto
    else:
        trascrizione_proprio = b"R" + ricevuto + mio
        trascrizione_peer = b"I" + ricevuto + mio
    sale = mio[:32] if iniziatore else ricevuto[:32]
    chiave_psk = deriva_psk(sale)
    mac_mio = hmac.new(chiave_psk, trascrizione_proprio, hashlib.sha256).digest()
    sock.sendall(mac_mio)
    mac_altrui = recvall(sock, 32)
    mac_atteso = hmac.new(chiave_psk, trascrizione_peer, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_altrui, mac_atteso):
        raise ValueError("wrong passphrase, different KDFs on the two PCs, or interference")
    # Solo ora l'altro PC ha dimostrato di conoscere la passphrase: e' il
    # momento giusto per confrontare (e solo se assente, salvare) la sua identita'
    verifica_peer(ricevuto[33:])
    ricorda_peer(ricevuto[33:])
    segreto = effimero.exchange(altrui_eff) + identita.exchange(altrui_ident)
    if iniziatore:
        trascrizione = mio + ricevuto
        mac_ordinati = mac_mio + mac_altrui
    else:
        trascrizione = ricevuto + mio
        mac_ordinati = mac_altrui + mac_mio
    chiave = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chatdefender-handshake" + trascrizione + mac_ordinati,
    ).derive(segreto)
    return Fernet(urlsafe_b64encode(chiave))


def recvall(conn, n):
    buf = b""
    while len(buf) < n:
        blocco = conn.recv(min(BUFFER_SIZE, n - len(buf)))
        if not blocco:
            raise ConnectionError("connection interrupted")
        buf += blocco
    return buf


def imballa_messaggio(dati):
    obiettivo = len(dati) + 4
    for soglia in PADDING_SOGLIE:
        if len(dati) + 4 <= soglia:
            obiettivo = soglia
            break
    return len(dati).to_bytes(4, "big") + dati + os.urandom(obiettivo - 4 - len(dati))


def invia_payload(sock, fernet, meta, payload_path=None, testo=None):
    if payload_path is not None:
        size = payload_path.stat().st_size
        meta = {**meta, "size": size}
        sorgente = open(payload_path, "rb")
    else:
        dati = imballa_messaggio(testo.encode())
        size = len(dati)
        meta = {**meta, "size": size}
        sorgente = None

    header = fernet.encrypt(json.dumps(meta).encode())
    sock.sendall(header + b"\n")

    try:
        if sorgente is not None:
            with sorgente:
                while chunk := sorgente.read(CHUNK_SIZE):
                    token = fernet.encrypt(chunk)
                    sock.sendall(struct.pack(">I", len(token)) + token)
        else:
            token = fernet.encrypt(dati)
            sock.sendall(struct.pack(">I", len(token)) + token)
    except BrokenPipeError:
        raise ConnectionError("the peer closed the connection")


def send_file(percorso, peers, identita):
    src = Path(percorso.strip().strip('"').strip("'")).expanduser()
    if not src.is_file():
        print("File not found")
        return
    prepara_cartella_privata(DROP_DIR)
    destinazione_locale = DROP_DIR / src.name
    if src.resolve() != destinazione_locale.resolve():
        try:
            copia_privata(src, destinazione_locale)
        except OSError as e:
            print(f"[!] Could not keep a copy in {DROP_DIR}: {e}")
    try:
        with connetti(peers) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            fernet = scambio_chiavi(sock, identita, iniziatore=True)
            invia_payload(sock, fernet, {"type": "file", "filename": src.name}, payload_path=src)
            risposta = ricevi_risposta(sock)
        if risposta.startswith(b"OK"):
            print("File share successful (encrypted)")
        elif not risposta:
            print("The peer closed the connection without responding")
        else:
            print(f"Share failed: {sanifica(risposta.decode(errors='replace'))}")
    except TimeoutError:
        print("Timeout: the peer did not respond (is it on? updated version?)")
    except ConnectionRefusedError:
        print(f"No one answers on {', '.join(peers)}:{PORT}: is Veil running on the other PC?")
    except ValueError as e:
        print(f"Connection rejected by the peer: {sanifica(str(e))}")
    except ConnectionError:
        print("The peer interrupted the connection during transfer")
    except OSError as e:
        print(f"Cannot reach the peer {', '.join(peers)} ({e})")


def send_message(testo, peers, identita):
    if len(testo.encode()) > MAX_MSG_SIZE:
        print("Message too long: the maximum is 1 MB")
        return
    try:
        with connetti(peers) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            fernet = scambio_chiavi(sock, identita, iniziatore=True)
            invia_payload(sock, fernet, {"type": "msg"}, testo=testo)
            risposta = ricevi_risposta(sock)
        if risposta.startswith(b"OK"):
            registra_messaggio("inviato a", peers[0], testo)
            print("Message sent (encrypted)")
        elif not risposta:
            print("The peer closed the connection without responding")
        else:
            print(f"Send failed: {sanifica(risposta.decode(errors='replace'))}")
    except TimeoutError:
        print("Timeout: the peer did not respond (is it on? updated version?)")
    except ConnectionRefusedError:
        print(f"No one answers on {', '.join(peers)}:{PORT}: is Veil running on the other PC?")
    except ValueError as e:
        print(f"Connection rejected by the peer: {sanifica(str(e))}")
    except ConnectionError:
        print("The peer interrupted the connection during transfer")
    except OSError as e:
        print(f"Cannot reach the peer {', '.join(peers)} ({e})")


def spazio_usato(cartella):
    totale = 0
    try:
        for p in cartella.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    totale += p.stat().st_size
            except OSError:
                pass
    except OSError:
        pass
    return totale


def quota_libera():
    with LOCK_QUOTA:
        return max(0, QUOTA_RICEZIONE - (spazio_usato(DROP_DIR) + RISERVATA_QUOTA["byte"]))


def riserva_quota(n):
    # Sotto lock si somma anche quanto e' gia' impegnato dai trasferimenti
    # in corso: solo il controllo "libero" preso piu' volte in parallelo
    # avrebbe lasciato passare tutti e superare il tetto.
    with LOCK_QUOTA:
        if spazio_usato(DROP_DIR) + RISERVATA_QUOTA["byte"] + n > QUOTA_RICEZIONE:
            return False
        RISERVATA_QUOTA["byte"] += n
        return True


def rilascia_quota(n):
    with LOCK_QUOTA:
        RISERVATA_QUOTA["byte"] = max(0, RISERVATA_QUOTA["byte"] - n)


def gestisci_connessione(conn, addr, consentiti, identita):
    with conn:
        if bannato(addr[0]):
            registra_sicurezza(addr[0], "connessione-da-ip-bannato", ban=True)
            avvisa(f"[⛔] Connection from {addr[0]} rejected: IP banned")
            return
        if addr[0] not in consentiti:
            # il mini-ban scatta davvero a soglia raggiunta, e il log dice la
            # verita': prima 'azione=ban' veniva scritto senza applicare nulla.
            # Il tarpit rallenta anche il primo tentativo: senza, un IP abusante
            # puo' scrivere centinaia di righe di log al secondo
            ritardo_tarpit(addr[0])
            ora_bannato = registra_rifiuto(addr[0])
            registra_sicurezza(addr[0], "ip-non-autorizzato", ban=ora_bannato)
            if ora_bannato:
                avvisa(f"[⛔] {addr[0]} banned for {DURATA_BAN // 60} minutes (too many attempts)")
            else:
                avvisa(f"[🚨] INTRUDER: {addr[0]} tried to connect (only {', '.join(consentiti)} allowed), connection closed")
            return
        try:
            conn.settimeout(TIMEOUT_PRE_AUTH)
            if not SEM_HANDSHAKE.acquire(timeout=15):
                registra_sicurezza(addr[0], "server-occupato-troppi-handshake")
                conn.sendall(b"ERR server busy, try again shortly\n")
                return
            try:
                fernet = scambio_chiavi(conn, identita, iniziatore=False)
            finally:
                SEM_HANDSHAKE.release()
            conn.settimeout(SOCKET_TIMEOUT)
            riga = b""
            while b"\n" not in riga:
                buf = conn.recv(4096)
                if not buf:
                    return
                riga += buf
                if len(riga) > MAX_CHUNK_TOKEN:
                    conn.sendall(b"ERR header too large\n")
                    return
            header_token, avanzati = riga.split(b"\n", 1)
            meta = json.loads(fernet.decrypt(header_token))

            in_sospeso = bytearray(avanzati)

            def leggi_esatti(n):
                while len(in_sospeso) < n:
                    blocco = conn.recv(min(BUFFER_SIZE, n - len(in_sospeso)))
                    if not blocco:
                        raise ConnectionError("connection interrupted")
                    in_sospeso.extend(blocco)
                dati = bytes(in_sospeso[:n])
                del in_sospeso[:n]
                return dati

            # Tutto cio' che e' malformato diventa ValueError: finisce nel
            # ramo che conta il rifiuto, applica il tarpit e logga il motivo
            if not isinstance(meta, dict):
                raise ValueError("header not valid")
            tipo = meta.get("type")
            try:
                dimensione = int(meta["size"])
            except (KeyError, TypeError, ValueError):
                raise ValueError("header without valid size") from None
            limite = MAX_MSG_SIZE + 4 if tipo == "msg" else 10 * 1024**3
            if tipo not in ("file", "msg") or dimensione < 0 or dimensione > limite:
                raise ValueError("request type or size not valid")

            ricevuti = 0
            contenuto = bytearray() if tipo == "msg" else None
            if tipo == "file":
                raw_name = meta.get("filename")
                if not isinstance(raw_name, str):
                    raise ValueError("filename not valid")
                nome = sanifica(Path(raw_name).name).strip()
                # Solo un nome semplice: niente traversal, niente symlink,
                # niente dotfile (prima questo controllo era codice morto)
                if (not nome or nome in (".", "..") or "/" in nome
                        or "\\" in nome or nome.startswith(".")):
                    registra_sicurezza(addr[0], "nome-file-non-valido")
                    raise ValueError("filename not valid")
                base_nome = nome
                prepara_cartella_privata(DROP_DIR)
                drop_res = DROP_DIR.resolve()
                destinazione = DROP_DIR / base_nome
                if destinazione.exists() and destinazione.is_symlink():
                    registra_sicurezza(addr[0], "symlink-esistente-rifiutato")
                    conn.sendall(b"ERR invalid request\n")
                    return
                try:
                    dest_res = destinazione.resolve(strict=False)
                    if not str(dest_res).startswith(str(drop_res) + os.sep) and dest_res != drop_res:
                        registra_sicurezza(addr[0], "path-traversal-tentativo")
                        conn.sendall(b"ERR invalid request\n")
                        return
                except OSError:
                    conn.sendall(b"ERR invalid request\n")
                    return
                # tetto di spazio: un peer autentico non puo' riempirci il
                # disco. La prenotazione resta attiva fino a fine trasferimento
                # (ogni uscita successiva deve rilasciarla)
                if not riserva_quota(dimensione):
                    libera = quota_libera()
                    registra_sicurezza(
                        addr[0],
                        f"quota-superata servono={dimensione} liberi={libera}",
                    )
                    conn.sendall(b"ERR shared folder full, file not accepted\n")
                    avvisa(f"[⛔] {addr[0]} refused: shared folder full "
                            f"(needs {dimensione} bytes, {libera} free)")
                    return
                out = None
                fd = -1
                progressivo = 0
                while True:
                    if progressivo == 0:
                        cand = DROP_DIR / base_nome
                    else:
                        stem = Path(base_nome).stem
                        suff = Path(base_nome).suffix
                        cand = DROP_DIR / f"{stem}-{progressivo}{suff}"
                    try:
                        fd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        out = os.fdopen(fd, "wb")
                        destinazione = cand
                        break
                    except FileExistsError:
                        progressivo += 1
                        if progressivo > 5000:
                            rilascia_quota(dimensione)
                            conn.sendall(b"ERR too many files with same name\n")
                            return
                    except OSError:
                        # ELOOP o altro
                        rilascia_quota(dimensione)
                        conn.sendall(b"ERR invalid request\n")
                        return
            else:
                out = None

            trasferito = False
            try:
                while ricevuti < dimensione:
                    lun = struct.unpack(">I", leggi_esatti(4))[0]
                    if lun == 0 or lun > MAX_CHUNK_TOKEN:
                        raise ValueError("chunk non valido")
                    pezzo = fernet.decrypt(leggi_esatti(lun))
                    if ricevuti + len(pezzo) > dimensione:
                        raise ValueError("payload piu' grande del dichiarato")
                    if out:
                        out.write(pezzo)
                    else:
                        contenuto += pezzo
                    ricevuti += len(pezzo)
                trasferito = True
            finally:
                if out:
                    out.close()
                    if not trasferito:
                        destinazione.unlink(missing_ok=True)
                        avvisa(f"[!] Incomplete transfer, partial file '{destinazione.name}' deleted")
                if tipo == "file":
                    # a questo punto il file (o il suo pezzo) e' su disco:
                    # il suo spazio lo conta direttamente spazio_usato()
                    rilascia_quota(dimensione)

            conn.sendall(b"OK\n")
            if tipo == "file":
                avvisa(f"[+] Received '{destinazione.name}' from {addr[0]} ({dimensione} bytes, encrypted)")
            else:
                n = int.from_bytes(contenuto[:4], "big")
                if 4 + n > len(contenuto):
                    raise ValueError("messaggio corrotto (padding non valido)")
                testo = sanifica(contenuto[4:4 + n].decode("utf-8", errors="replace"))
                registra_messaggio("ricevuto da", addr[0], testo)
                avvisa(f"[💬] Message from {addr[0]}: {testo}")
        except InvalidToken:
            ritardo_tarpit(addr[0])
            ora_bannato = registra_rifiuto(addr[0])
            registra_sicurezza(addr[0], "invalid-data-or-different-key", ban=ora_bannato)
            rispondi_err(conn)
            if ora_bannato:
                avvisa(f"[⛔] {addr[0]} banned for {DURATA_BAN // 60} minutes")
            else:
                avvisa(f"[!] Invalid data or different key ({addr[0]}), connection rejected")
        except ValueError as e:
            ritardo_tarpit(addr[0])
            ora_bannato = registra_rifiuto(addr[0])
            registra_sicurezza(addr[0], str(e), ban=ora_bannato)
            rispondi_err(conn)
            if ora_bannato:
                avvisa(f"[⛔] {addr[0]} banned for {DURATA_BAN // 60} minutes")
            else:
                avvisa(f"[🚨] Connection rejected from {addr[0]}: {e}")
        except TimeoutError:
            registra_sicurezza(addr[0], "timeout")
            rispondi_err(conn)
            avvisa(f"[!] Timed out ({addr[0]}), connection closed")
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError,
                ConnectionError, OSError):
            registra_sicurezza(addr[0], "invalid-transfer")
            rispondi_err(conn)


def rispondi_err(conn):
    try:
        conn.sendall(b"ERR invalid transfer\n")
    except OSError:
        pass


def ricevi_risposta(sock):
    buf = b""
    while not buf.endswith(b"\n") and len(buf) < 64:
        pezzo = sock.recv(64 - len(buf))
        if not pezzo:
            break
        buf += pezzo
    return buf.strip()


def ip_sorgente(addr):
    # Su un socket dual-stack un collegamento IPv4 puo' arrivare come
    # indirizzo mappato "::ffff:1.2.3.4": l'allowlist e i ban usano la
    # forma breve, quindi va normalizzato prima di ogni confronto.
    ip = addr[0]
    if isinstance(ip, str) and ip.startswith("::ffff:") and ":" not in ip[7:]:
        return ip[7:]
    return ip


def ricevi_loop(consentiti, identita, bind_ip="0.0.0.0"):
    try:
        prepara_cartella_privata(DROP_DIR)
        if ":" in bind_ip:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                # dual-stack: ascolta anche in IPv4 quando il bind e' "::"
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        else:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind_ip, PORT))
            server.listen(64)
            while True:
                conn, addr = server.accept()
                addr = (ip_sorgente(addr),) + tuple(addr[1:])
                if not SEM_CONNESSIONI.acquire(blocking=False):
                    # oltre il tetto non creiamo proprio il thread
                    with LOCK_RICEVUTE:
                        RICEVUTE["rifiutate"] += 1
                    conn.close()
                    continue
                with LOCK_RICEVUTE:
                    RICEVUTE["connessioni"] += 1
                thread = threading.Thread(
                    target=_gestisci_e_libera,
                    args=(conn, addr, consentiti, identita),
                    daemon=True,
                )
                try:
                    thread.start()
                except RuntimeError:
                    # sistema ai limiti di thread: senza questo rilascio il
                    # semaforo resterebbe occupato e il server perderebbe
                    # canali a ogni tentativo fallito
                    SEM_CONNESSIONI.release()
                    with LOCK_RICEVUTE:
                        RICEVUTE["connessioni"] -= 1
                        RICEVUTE["rifiutate"] += 1
                    conn.close()
    except OSError as e:
        avvisa(f"[!] Cannot listen on {bind_ip}:{PORT} ({e}): is another instance "
               "already running, or that address does not exist on this machine?")


def _gestisci_e_libera(conn, addr, consentiti, identita):
    try:
        gestisci_connessione(conn, addr, consentiti, identita)
    finally:
        SEM_CONNESSIONI.release()
        with LOCK_RICEVUTE:
            RICEVUTE["connessioni"] -= 1


def migra_kdf(nuovo):
    carica_password()
    vecchio = kdf_attivo()
    if vecchio == nuovo:
        print(f"KDF already set to {nuovo}, nothing to do")
        return
    prepara_cartella_config()
    sale = LOG_SALT_FILE.read_bytes() if LOG_SALT_FILE.exists() else os.urandom(16)
    radice_vecchia = radice_kdf(sale)
    fernet_log_vecchio = Fernet(urlsafe_b64encode(radice_vecchia))
    chiave_ident_vecchia = Fernet(urlsafe_b64encode(sottochiave_hkdf(radice_vecchia, b"chatdefender-identita")))
    privata_raw = None
    if IDENTITY_FILE.exists():
        dati = IDENTITY_FILE.read_bytes().strip()
        try:
            privata_raw = chiave_ident_vecchia.decrypt(dati)
        except InvalidToken:
            candidata = urlsafe_b64decode(dati)
            if len(candidata) == 32:
                privata_raw = candidata
        if privata_raw is None:
            raise SystemExit("Identity unreadable with the current setup: migration cancelled")
    scrivi_privato(KDF_FILE, (nuovo + "\n").encode())
    global CHIAVE_LOG, CHIAVE_IDENTITA
    CHIAVE_LOG = None
    CHIAVE_IDENTITA = None
    scrivi_privato(IDENTITY_FILE, ottieni_chiave_identita().encrypt(privata_raw) + b"\n")
    print(f"Identity re-encrypted with {nuovo}")
    if MESSAGGI_DIR.exists():
        lasciate = 0
        nuovo_fernet = ottieni_chiave_log()
        for cronologia in sorted(MESSAGGI_DIR.glob("*.log")):
            uscita = []
            for riga in cronologia.read_text().splitlines():
                try:
                    uscita.append(nuovo_fernet.encrypt(fernet_log_vecchio.decrypt(riga.encode())).decode())
                except (InvalidToken, ValueError):
                    uscita.append(riga)
                    lasciate += 1
            scrivi_privato(cronologia, ("\n".join(uscita) + "\n").encode())
        if lasciate:
            print(f"[!] {lasciate} lines not re-encrypted, left as they were")
        print(f"Logs re-encrypted with {nuovo}")
    print(f"Active KDF now: {nuovo} (the other PC must use the same method for the handshake)")


def cambia_password():
    banner()
    carica_password()
    print("Changing passphrase: logs and identity will be re-encrypted under the new phrase.")
    nuova = chiedi_passphrase(
        f"New passphrase (at least {LUNGHEZZA_MINIMA_PASSPHRASE} characters): ",
        "Repeat the new passphrase: ",
    )
    prepara_cartella_config()
    sale_vecchio = LOG_SALT_FILE.read_bytes() if LOG_SALT_FILE.exists() else os.urandom(16)
    radice_vecchia = radice_kdf(sale_vecchio)
    fernet_log_vecchio = Fernet(urlsafe_b64encode(radice_vecchia))
    chiave_ident_vecchia = Fernet(urlsafe_b64encode(sottochiave_hkdf(radice_vecchia, b"chatdefender-identita")))
    privata_raw = None
    if IDENTITY_FILE.exists():
        dati = IDENTITY_FILE.read_bytes().strip()
        try:
            privata_raw = chiave_ident_vecchia.decrypt(dati)
        except InvalidToken:
            candidata = urlsafe_b64decode(dati)
            if len(candidata) == 32:
                privata_raw = candidata
        if privata_raw is None:
            raise SystemExit("Identity unreadable with the current passphrase: change cancelled")
    global PASSWORD_GLOBALE, CHIAVE_LOG, CHIAVE_IDENTITA
    global PASSPHRASE_PERSISTENTE
    PASSWORD_GLOBALE = nuova
    salva_passphrase_su_disco(PASSPHRASE_PERSISTENTE)
    scrivi_privato(LOG_SALT_FILE, os.urandom(16))
    CHIAVE_LOG = None
    CHIAVE_IDENTITA = None
    if privata_raw is not None:
        scrivi_privato(IDENTITY_FILE, ottieni_chiave_identita().encrypt(privata_raw) + b"\n")
        print("Identity re-encrypted")
    if MESSAGGI_DIR.exists():
        lasciate = 0
        nuovo_fernet = ottieni_chiave_log()
        for cronologia in sorted(MESSAGGI_DIR.glob("*.log")):
            uscita = []
            for riga in cronologia.read_text().splitlines():
                try:
                    uscita.append(nuovo_fernet.encrypt(fernet_log_vecchio.decrypt(riga.encode())).decode())
                except (InvalidToken, ValueError):
                    uscita.append(riga)
                    lasciate += 1
            scrivi_privato(cronologia, ("\n".join(uscita) + "\n").encode())
        if lasciate:
            print(f"[!] {lasciate} lines not re-encrypted (old format or corrupted), left as they were")
        print("Message logs re-encrypted")
    print("Passphrase changed! Use the SAME one on the other PC too, otherwise you will no longer connect")


def main():
    global PASSPHRASE_PERSISTENTE
    parser = argparse.ArgumentParser(description="End-to-end encrypted chat and file sharing over LAN")
    parser.add_argument("--read-log", action="store_true", help="show saved messages (decrypted)")
    parser.add_argument("--change-password", action="store_true", help="change the passphrase, re-encrypting logs and identity")
    parser.add_argument("--migrate-kdf", choices=["argon2id", "pbkdf2"], help="convert local files to a different KDF")
    parser.add_argument("--save-passphrase", action="store_true",
                        help="store the passphrase on disk (convenient, but whoever reads "
                             "the file gets the key to your logs and identity)")
    parser.add_argument("--forget", type=int, metavar="DAYS",
                        help="delete the saved chat history older than DAYS "
                             "(0 = delete all of it); no passphrase needed")
    parser.add_argument("--bind", metavar="IP",
                        help="listen only on this local address instead of every "
                             "interface (saved in config.json)")
    args = parser.parse_args()
    if args.forget is not None and args.forget < 0:
        parser.error("--forget expects 0 or more days")
    if args.save_passphrase:
        PASSPHRASE_PERSISTENTE = True
    cfg = leggi_config()
    bind_ip = str(args.bind if args.bind is not None
                  else (cfg or {}).get("bind_ip") or "0.0.0.0").strip()
    try:
        ipaddress.ip_address(bind_ip)
    except ValueError:
        raise SystemExit(f"Not a valid local address to listen on: {bind_ip!r} "
                         "(use an IP address, e.g. 0.0.0.0, 127.0.0.1, ::)") from None
    retention = (cfg or {}).get("retention_days")
    if isinstance(retention, (int, float)) and not isinstance(retention, bool) and retention > 0:
        scartati = dimentica_storico(retention)
        if scartati:
            print(f"[!] Expired chat history removed: {scartati} file(s) "
                  f"(retention {int(retention)} days)")
    if args.forget is not None:
        scartati = dimentica_storico(args.forget)
        if scartati:
            print(f"Chat history deleted: {scartati} file(s) "
                  + ("(everything)" if args.forget == 0 else f"(older than {args.forget} days)"))
        else:
            print("No chat history to delete")
        return
    if args.read_log:
        carica_password()
        leggi_log()
        return
    if args.change_password:
        cambia_password()
        return
    if args.migrate_kdf:
        migra_kdf(args.migrate_kdf)
        return

    banner()
    prepara_cartella_privata(DROP_DIR)
    if args.bind is not None:
        aggiorna_config(bind_ip=bind_ip)
        print(f"Listening address saved to {CONFIG_FILE}: {bind_ip}")
    peers = carica_peer_ip(cfg)
    carica_password()
    identita = carica_identita()
    consentiti = risolvi_consentiti(peers)
    if not consentiti:
        raise SystemExit(
            "None of the configured peer addresses is usable: edit "
            f"{CONFIG_FILE} and put a plain IP address"
        )
    if PEER_IDENTITY_FILE.exists() and sys.stdin.isatty():
        impronta_attuale = impronta(PEER_IDENTITY_FILE.read_bytes())
        conferma = input(
            f"Stored peer fingerprint: {impronta_attuale}\n"
            "Compare it with the other PC (the two fingerprints MUST match): "
            "do you confirm it? [Y/n]: "
        ).strip().lower()
        if conferma == "n":
            PEER_IDENTITY_FILE.unlink()
            raise SystemExit("Pin deleted: it will be remembered again at the next connection. Re-verify the fingerprint in person!")
    print("Handshake key derivation:", kdf_attivo())
    print(f"Anti-flood: {DIFFICOLTA_POW}-bit proof-of-work, mini-ban after {TENTATIVI_BAN} rejections")
    if PEER_IDENTITY_FILE.exists():
        print(f"Stored peer fingerprint: {impronta(PEER_IDENTITY_FILE.read_bytes())} (verify it in person with the other PC)")
    # Il listener deve partire SEMPRE: e' l'handshake in entrata a creare il
    # pin del peer al primo avvio, e senza thread non arriva mai nessuno
    threading.Thread(target=ricevi_loop, args=(consentiti, identita, bind_ip), daemon=True).start()
    print(f"Listening on port {PORT}"
          + (f" (bound to {bind_ip})" if bind_ip != "0.0.0.0" else "")
          + f" | Shared folder: {DROP_DIR} (quota {QUOTA_RICEZIONE // 1024**2} MiB) | History: {MESSAGGI_DIR}")
    print(f"Max simultaneous connections: {MAX_CONNESSIONI} | Passphrase: "
          + ("saved on disk" if PASSPHRASE_PERSISTENTE else "memory only, never written to disk"))
    print(f"Accepted peers: {', '.join(consentiti)}")
    print('Type the path of a file to share, or any message (quotes optional): hello or "hello"')
    print("(q to quit)\n")
    # Se il processo muore con un segnale, il terminale non deve restare
    # in modalita' cbreak (altrimenti la riga di comando successiva va in
    # modo strano): atexit copre l'uscita normale, i segnali il resto
    atexit.register(ripristina_input)

    def _esci_per_segnale(signum, frame):
        raise SystemExit(128 + signum)

    for segnale in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(segnale, _esci_per_segnale)
        except (ValueError, OSError):
            pass
    attiva_input_raw()
    try:
        while True:
            try:
                scelta = leggi_riga()
            except (KeyboardInterrupt, EOFError):
                print("\nBye!")
                break
            if not elabora(scelta, peers, identita):
                break
    finally:
        ripristina_input()


def elabora(riga, peers, identita):
    pulito = riga.strip()
    if pulito.lower() in ("q", "quit", "exit"):
        return False
    if not pulito:
        return True
    senza_virgolette = pulito
    if len(pulito) >= 2 and pulito[0] == pulito[-1] and pulito[0] in "\"'":
        senza_virgolette = pulito[1:-1]
    try:
        esiste = Path(senza_virgolette).expanduser().is_file()
    except OSError:
        esiste = False
    if esiste:
        send_file(senza_virgolette, peers, identita)
        return True
    if pulito[0] in "\"'":
        q = pulito[0]
        corpo = pulito[1:]
        if corpo.endswith(q):
            corpo = corpo[:-1]
        if corpo.strip():
            send_message(corpo, peers, identita)
    elif "/" in pulito or pulito.startswith("~"):
        print("File not found")
    else:
        send_message(pulito, peers, identita)
    return True


if __name__ == "__main__":
    main()
