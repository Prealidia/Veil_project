#!/usr/bin/env python3
# veil_2.py - Chat e file cifrati end-to-end attraverso un relay anonimo.
#
# Un solo file, nessuna dipendenza obbligatoria, nessun permesso speciale:
# gira come utente normale su Void, Mint, Debian, quello che vuoi.
#
# COME FUNZIONA
#   Il tuo PC apre una connessione TCP in uscita verso l'hub e ci resta. L'hub
#   e' una casella postale in RAM: quando anche l'altro PC arriva, apre una pipe
#   fra i due e poi si mette da parte. Nessun account, nessuna email, nessun
#   nickname registrato, nessun database: al riavvio l'hub non sa piu' nulla.
#
#   Perche' non si collegano direttamente i due PC? Perche' stanno dietro
#   router diversi, e uno dei due probabilmente anche dietro CGNAT. Con una
#   sola connessione in uscita funziona sempre, e nessuno deve aprire porte.
#
#   L'hub non puo' leggere nulla: copia byte da una socket all'altra senza
#   interpretarli. Non vede la passphrase, non vede le chiavi, non vede i
#   messaggi. E non puo' neppure sostituirsi a qualcuno: le chiavi viaggiano
#   dentro lo stesso flusso del negoziato, e il codice di autenticazione copre
#   anche l'identita', quindi un man-in-the-middle senza la passphrase non
#   puo' neppure cambiare la chiave di nessuno.
#
#   Non serve sapere l'IP dell'altro: e' il punto. E non serve che l'hub sappia
#   niente di te: vede una stanza (uno sha256 di un segreto casuale) e una
#   chiave pubblica, entrambe le due che chi e' nel contatto gia' condivide.
#
# GUIDA RAPIDA
#  veil2.py nuovo mario               genera le credenziali per un contatto
#   veil2.py aggiungi mario <invito>   le mette nel tuo PC
#   veil2.py hub miohub.duckdns.org    dice quale hub usare
#   veil2.py                          chat
#
#   Nell'invito c'e' tutto quello che serve. Portalo di persona o su un canale
#   fidato: chi lo ha puo' leggere i messaggi. Come una chiave.

import argparse
import base64
import binascii
import codecs
import ctypes
import ctypes.util
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import select
import socket
import ssl
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
    import readline          # noqa: F401  (solo per la history)
except ImportError:
    pass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSIONE_PROTOCOLLO = 5
PREDA = b"VEIL2/1"

# Come in veil.py: ogni messaggio e' gonfiato alla soglia successiva, cosi' la
# lunghezza vera non si legge dal traffico.
PADDING_SOGLIE = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
                  131072, 262144, 524288]

MAX_MSG_SIZE = 1024 * 1024
CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_TOKEN = CHUNK_SIZE * 2 + 8192
MAX_FILE_SIZE = 10 * 1024 ** 3
BUFFER_SIZE = 65536
SOCKET_TIMEOUT = 120
TIMEOUT_PRE_AUTH = 30
HEARTBEAT = 20               # pausa fra un tentativo di riconnessione e il
PAUSA_MAX = 25               # successivo, con scarto casuale
SEM_HANDSHAKE = threading.Semaphore(3)

ARGON2_TEMPO = 3
ARGON2_MEMORIA_KIB = 65536
ARGON2_PARALLELISMO = 4
DIFFICOLTA_POW = 17

TENTATIVI_BAN = 5
DURATA_BAN = 600

DROP_DIR = Path.home() / "localdrop"
MESSAGGI_DIR = DROP_DIR / "messaggi"
SECURITY_LOG = Path.home() / ".local" / "state" / "veil2" / "sicurezza.log"

CONFIG_DIR = Path.home() / ".config" / "veil2"
CONFIG_FILE = CONFIG_DIR / "config.json"
IDENTITY_FILE = CONFIG_DIR / "identity.key"
SALT_FILE = CONFIG_DIR / "salt"
KDF_FILE = CONFIG_DIR / "kdf"
CONTATTI_FILE = CONFIG_DIR / "contatti.enc"
PEER_DIR = CONFIG_DIR / "peer"

RE_NICK = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,31}$")
RE_CONTROLLO = re.compile(
    r"\x1b\[[0-9;:?]*[a-zA-Z]|\x1b\][^\x07]*(?:\x07|\x1b\\)|[\x00-\x1f\x7f]"
)

# Tipi di frame che viaggiano dentro la sessione cifrata.
T_MSG, T_FILE, T_CHUNK, T_DONE, T_ACK, T_ERR, T_BYE = range(1, 8)

STATO = {}                  # nick -> {"stato":..., "sessione":..., "errore":...}
VISTI = {}                  # nick -> errori gia' mostrati (non ripetere a ogni giro)
FASE = {"nome": "collegamento all'hub"}   # in che punto siamo, se la sessione cade
LOCK_STATO = threading.RLock()
LOCK_OUTPUT = threading.Lock()
STATO_INPUT = {"bozza": "", "attivo": False}
PASSWORD_GLOBALE = ""
AVVISO_KDF = False
CONTATTI = {}
IDENTITA = None
IL_MIO_NICK = ""

CHIAVE_CONTATTI = None
LOCK_CHIAVE = threading.RLock()
BAN = {"tentativi": {}, "scadenze": {}}
LOCK_BAN = threading.Lock()


# --------------------------------------------------------------------------
# filesystem e rumore di fondo
# --------------------------------------------------------------------------

def prepara_cartella_config():
    for ditta in (CONFIG_DIR, PEER_DIR):
        ditta.mkdir(parents=True, exist_ok=True)
        try:
            ditta.chmod(0o700)
        except OSError:
            pass


def scrivi_privato(percorso, dati):
    prepara_cartella_config()
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dati)


def sanifica(testo):
    return RE_CONTROLLO.sub(" ", testo)


def avvisa(testo):
    with LOCK_OUTPUT:
        sys.stdout.write("\r\x1b[2K\n" + testo + "\n")
        if STATO_INPUT["attivo"]:
            ridisegna_input()
        sys.stdout.flush()


def ridisegna_input():
    sys.stdout.write("\r\x1b[2K> " + STATO_INPUT["bozza"])
    sys.stdout.flush()


def banner():
    try:
        subprocess.run(["figlet", "veil 2"], check=False)
    except FileNotFoundError:
        print("V E I L   2")
    print("chat cifrata end-to-end · nessun account · l'hub non puo' leggerci")


def registra_sicurezza(motivo, ban=False):
    riga = "%s %s azione=%s\n" % (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        sanifica(str(motivo)).strip() or "sconosciuto",
        "ban" if ban else "nota",
    )
    try:
        SECURITY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(SECURITY_LOG, "a") as f:
            f.write(riga)
    except OSError:
        pass


# --------------------------------------------------------------------------
# KDF
# --------------------------------------------------------------------------

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
        raise RuntimeError("argon2 errore %d" % rc)
    return uscita.raw


def kdf_attivo():
    scelta = os.environ.get("VEIL2_KDF")
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


def radice_kdf(segreto, sale):
    if kdf_attivo() == "argon2id":
        chiave = argon2id(segreto, sale)
        if chiave is not None:
            return chiave
    return hashlib.pbkdf2_hmac("sha256", segreto, sale, 600_000)


def sottochiave(radice, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(radice)


def sale_disponibile():
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    sale = os.urandom(16)
    scrivi_privato(SALT_FILE, sale)
    return sale


def chiave_dispositivo(info):
    """Chiave derivata dalla passphrase di questo PC. Serve per cifrare
    l'identita' e il DB dei contatti: non esce mai da qui."""
    global CHIAVE_CONTATTI
    if info == b"contatti" and CHIAVE_CONTATTI is not None:
        return CHIAVE_CONTATTI
    radice = radice_kdf(PASSWORD_GLOBALE.encode(), sale_disponibile())
    chiave = Fernet(urlsafe_b64encode(sottochiave(radice, b"veil2-" + info)))
    if info == b"contatti":
        CHIAVE_CONTATTI = chiave
    return chiave


# --------------------------------------------------------------------------
# passphrase del dispositivo e identita'
# --------------------------------------------------------------------------

def chiedi_passphrase_dispositivo(nuova=False):
    global PASSWORD_GLOBALE
    PASSWORD_FILE = CONFIG_DIR / "password"
    if PASSWORD_FILE.exists():
        valore = PASSWORD_FILE.read_text().strip()
        if valore:
            PASSWORD_GLOBALE = valore
            return
    while True:
        if nuova:
            primo = getpass.getpass("Nuova passphrase di questo PC (non e' quella del contatto!): ")
            secondo = getpass.getpass("Ripetila: ")
            if primo != secondo:
                print("Le due non coincidono.")
                continue
        else:
            primo = getpass.getpass("Passphrase di questo PC: ")
        if len(primo) < 12:
            if input("Meno di 12 caratteri. Usarla comunque? [s/N]: ").strip().lower() != "s":
                continue
        if primo:
            break
    scrivi_privato(PASSWORD_FILE, (primo + "\n").encode())
    PASSWORD_GLOBALE = primo
    if nuova:
        print("Passphrase di questo PC cambiata. Log e contatti ricifrati.")


def carica_identita():
    """Una sola identita' per questo PC, per tutte le chat. Viene pinnata dai
    contatti per nickname, quindi non puo' essere sostituita silenziosamente."""
    global IDENTITA
    if IDENTITY_FILE.exists():
        dati = IDENTITY_FILE.read_bytes().strip()
        try:
            privata = chiave_dispositivo(b"identita").decrypt(dati)
        except InvalidToken:
            raise SystemExit(
                "Non riesco a aprire l'identita': passphrase di questo PC diversa?\n"
                "Se l'hai dimenticata, puoi cancellare %s: verra' generata un'altra,\n"
                "ma i contatti dovranno riverificare la tua impronta la prima volta."
                % IDENTITY_FILE
            )
        IDENTITA = X25519PrivateKey.from_private_bytes(privata)
        return IDENTITA
    IDENTITA = X25519PrivateKey.generate()
    privata = IDENTITA.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    scrivi_privato(IDENTITY_FILE, chiave_dispositivo(b"identita").encrypt(privata) + b"\n")
    print("Identita' di questo PC generata e cifrata: %s" % impronta(chiave_pubblica_raw(IDENTITA)))
    return IDENTITA


# --------------------------------------------------------------------------
# contatti
# --------------------------------------------------------------------------

def carica_contatti():
    global CONTATTI
    if not CONTATTI_FILE.exists():
        CONTATTI = {}
        return CONTATTI
    try:
        grezzo = chiave_dispositivo(b"contatti").decrypt(CONTATTI_FILE.read_bytes().strip())
        CONTATTI = json.loads(grezzo)
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
        raise SystemExit("Il DB dei contatti non si apre: passphrase di questo PC diversa?")
    return CONTATTI


def salva_contatti():
    grezzo = json.dumps(CONTATTI, sort_keys=True).encode()
    scrivi_privato(CONTATTI_FILE, chiave_dispositivo(b"contatti").encrypt(grezzo) + b"\n")


def stanza_di(contatto):
    """La stanza e' uno sha256 di un segreto casuale, non della passphrase.
    Cosi' l'hub non riceve nessuna verifica offline della passphrase: ha solo
    una stringa casuale che non puo' indovinare ne' usare per attaccare."""
    grezzo = base64.b64decode(contatto["segreto"] + "=")
    return hashlib.sha256(b"veil2-stanza-v5|" + grezzo).hexdigest()


def nuovo_contatto(nick):
    if not RE_NICK.match(nick):
        raise SystemExit(
            "Nickname non valido: solo a-z 0-9 . _ -, 2-32 caratteri, deve iniziare\n"
            "con una lettera o un numero (l'hub li accetta cosi' e nient'altro)."
        )
    if nick == IL_MIO_NICK:
        raise SystemExit("Il nickname deve essere diverso dal tuo.")
    if nick in CONTATTI:
        raise SystemExit("Il contatto '%s' c'e' gia'." % nick)
    segreto = base64.b64encode(os.urandom(32)).decode().rstrip("=")
    return {
        "passphrase": secrets.token_urlsafe(24),
        "segreto": segreto,
        "peer": None,
        "aggiunto": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


def invito(nick, contatto):
    return base64.urlsafe_b64encode(json.dumps({
        "v": VERSIONE_PROTOCOLLO, "n": nick,
        "p": contatto["passphrase"], "s": contatto["segreto"],
    }).encode()).decode().rstrip("=")


def leggi_invito(testo):
    testo = testo.strip()
    if testo.startswith("veil2:add:"):
        testo = testo[len("veil2:add:"):]
    try:
        grezzo = urlsafe_b64decode(testo + "=" * (-len(testo) % 4))
        dati = json.loads(grezzo)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise SystemExit("Questo non e' un invito valido. Deve essere la riga 'veil2.py aggiungi ...'.")
    for campo in ("v", "n", "p", "s"):
        if campo not in dati:
            raise SystemExit("Invito incompleto: manca '%s'." % campo)
    if dati["v"] != VERSIONE_PROTOCOLLO:
        raise SystemExit(
            "L'invito e' di una versione diversa (invito v%s, questo veil2.py e' v%d).\n"
            "Aggiornaveil2.py sull'altro PC e genera un invito nuovo."
            % (dati["v"], VERSIONE_PROTOCOLLO)
        )
    return dati


# --------------------------------------------------------------------------
# crittografia della sessione (ripresa da veil.py, con passphrase per contatto)
# --------------------------------------------------------------------------

def chiave_pubblica_raw(chiave):
    return chiave.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def impronta(pub_raw):
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def risolvi_pow(sale, bit):
    base = hashlib.sha256(b"veil2-pow" + sale)
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
    return int.from_bytes(
        hashlib.sha256(b"veil2-pow" + sale + nonce).digest(), "big"
    ) < obiettivo


def chiave_registro():
    """La chiave che ci presentiamo all'hub. Non serve che sia segreta: e' la
    stessa identita' che il negoziato rivela comunque all'altro peer, e serve
    solo all'hub per distinguere due PC con la stessa stanza."""
    return base64.b64encode(chiave_pubblica_raw(IDENTITA)).decode()


def recvall(conn, n):
    buf = b""
    while len(buf) < n:
        blocco = conn.recv(min(BUFFER_SIZE, n - len(buf)))
        if not blocco:
            raise ConnectionError("connessione interrotta")
        buf += blocco
    return buf


def scambio_chiavi(sock, identita, passphrase, nick_peer):
    """Come in veil.py, ma la passphrase e' quella di questo contatto e la
    chiave del peer viene pinnata per nickname (non per IP: l'IP non c'entra,
    e pinnare per IP sarebbe un buco)."""
    if not SEM_HANDSHAKE.acquire(timeout=20):
        raise ValueError("troppi handshake in corso, riprova")
    try:
        return _scambio_chiavi(sock, identita, passphrase, nick_peer)
    finally:
        SEM_HANDSHAKE.release()


def _scambio_chiavi(sock, identita, passphrase, nick_peer):
    FASE["nome"] = "prova del canale"
    effimero = X25519PrivateKey.generate()
    mio = bytes([VERSIONE_PROTOCOLLO]) + chiave_pubblica_raw(effimero) + chiave_pubblica_raw(identita)
    sock.sendall(struct.pack(">I", len(mio)) + mio)
    FASE["nome"] = "attendo l'hello del peer"

    primo = recvall(sock, 4)
    if primo.startswith(b"ERR") or primo.startswith(b"OK"):
        raise ValueError("rifiuto dal peer (%s)" % primo.decode(errors="replace").strip())
    lung = struct.unpack(">I", primo)[0]
    if lung == 64:
        raise ValueError("peer con versione vecchia: aggiorna veil_2.py sull'altro PC")
    if lung != 65:
        raise ValueError("handshake non valido")
    ricevuto = recvall(sock, lung)
    if ricevuto[0] != VERSIONE_PROTOCOLLO:
        raise ValueError(
            "protocollo %d contro il nostro %d: i due PC hanno versioni diverse"
            % (ricevuto[0], VERSIONE_PROTOCOLLO)
        )
    altrui_eff = X25519PublicKey.from_public_bytes(ricevuto[1:33])
    altrui_ident = X25519PublicKey.from_public_bytes(ricevuto[33:])
    FASE["nome"] = "impronta del peer"

    # Chi dei due parla per primo?
    #
    # NON si puo' decidere confrontando i nomi. I due PC archiviano lo stesso
    # contatto sotto lo stesso nome, quindi i nomi sono identici: se la
    # regola fosse "parla chi ha il nome minore", il risultato dipenderebbe
    # dal nome che ciascuno ha scelto per se' e i due potrebbero decidere
    # entrambi di essere l'iniziatore, aspettandosi a vicenda per sempre.
    #
    # Si decide invece sulle chiavi di identita', che sono diverse per
    # costruzione e che l'hub non puo' inventare senza farsi notare.
    if mio[33:] == ricevuto[33:]:
        raise ValueError(
            "stessa chiave di identita' ai due lati: due processi di veil_2.py sullo\n"
            "stesso PC, oppure una copia di ~/.config/veil2/identita. Sul PC che ha\n"
            "lo stesso contatto: 'veil2.py rimuovi <nick>', poi riesegui 'nuovo'."
        )
    iniziatore = mio[33:] < ricevuto[33:]

    pinnalo(nick_peer, ricevuto[33:], iniziatore)
    FASE["nome"] = "proof-of-work"

    if iniziatore:
        if struct.unpack(">I", recvall(sock, 4))[0] != 17:
            raise ValueError("sfida proof-of-work non valida")
        sfida = recvall(sock, 16)
        difficolta = recvall(sock, 1)[0]
        if not 8 <= difficolta <= 26:
            raise ValueError("difficolta' proof-of-work assurda")
        sock.sendall(struct.pack(">I", 8) + risolvi_pow(sfida, difficolta))
    else:
        sfida = os.urandom(16)
        sock.sendall(struct.pack(">I", 17) + sfida + bytes([DIFFICOLTA_POW]))
        if struct.unpack(">I", recvall(sock, 4))[0] != 8:
            raise ValueError("soluzione proof-of-work non valida")
        if not verifica_pow(sfida, recvall(sock, 8), DIFFICOLTA_POW):
            raise ValueError("proof-of-work non risolto")

    # La trascrizione NON puo' dipendere da chi parla per primo: se i due lati
    # costruiscono la stessa etichetta in ordine diverso ottengono due HMAC
    # diversi e la sessione non si apre mai. Si mettono in fila in modo
    # canonico, così "io" e "peer" non esistono: conta solo la coppia.
    basso, alto = sorted((mio, ricevuto))
    FASE["nome"] = "verifica della passphrase"
    chiave_psk = radice_kdf(passphrase.encode(), basso[:16])
    mac_io = hmac.new(chiave_psk, b"I" + basso + alto, hashlib.sha256).digest()
    mac_peer = hmac.new(chiave_psk, b"R" + basso + alto, hashlib.sha256).digest()
    mac_mio, mac_atteso = (mac_io, mac_peer) if iniziatore else (mac_peer, mac_io)
    sock.sendall(mac_mio)
    mac_altrui = recvall(sock, 32)
    if not hmac.compare_digest(mac_altrui, mac_atteso):
        raise ValueError("passphrase o room_secret sbagliate per '%s'" % nick_peer)

    segreto = effimero.exchange(altrui_eff) + identita.exchange(altrui_ident)
    mac_ordinati = b"".join(sorted((mac_io, mac_peer)))
    chiave = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"veil2-handshake-v5" + basso + alto + mac_ordinati,
    ).derive(segreto)
    return Fernet(urlsafe_b64encode(chiave))


def pinnalo(nick, pub_raw, iniziatore):
    """Pin della chiave del peer, per nickname. La prima volta gliela
    ricordiamo e chiediamo conferma: una chat fra due macchine nuove non ha
    nessun modo di essere sicura da sola, quindi l'unica verifica possibile e'
    guardarsi le impronte in faccia."""
    percorso = PEER_DIR / (nick + ".key")
    if not percorso.exists():
        PEER_DIR.mkdir(parents=True, exist_ok=True)
        scrivi_privato(percorso, pub_raw)
        CONTATTI[nick]["peer"] = impronta(pub_raw)
        salva_contatti()
        avvisa("[+] Prima connessione con '%s': impronta %s" % (nick, impronta(pub_raw)))
        if not iniziatore:
            risposta = input("Confermi questa impronta con l'altro PC? [s/N]: ").strip().lower()
            if risposta != "s":
                percorso.unlink()
                CONTATTI[nick]["peer"] = None
                salva_contatti()
                raise ValueError("impronta non confermata, contatto non pinato")
        return
    if percorso.read_bytes() != pub_raw:
        raise ValueError(
            "l'identita' di '%s' e' cambiata rispetto al pin salvato.\n"
            "Se hai cancellato la sua identity.key, rimuovi il pin con:\n"
            "  veil2.py dimentica %s   (poi riverificateli in persona)" % (nick, nick)
        )


# --------------------------------------------------------------------------
# frame sopra la sessione cifrata
# --------------------------------------------------------------------------

def imballa(testo):
    dati = testo.encode()
    obiettivo = len(dati) + 4
    for soglia in PADDING_SOGLIE:
        if len(dati) + 4 <= soglia:
            obiettivo = soglia
            break
    return len(dati).to_bytes(4, "big") + dati + os.urandom(obiettivo - 4 - len(dati))


def spedisci(sess, tipo, payload=b""):
    token = sess["fernet"].encrypt(payload)
    if len(token) > MAX_CHUNK_TOKEN:
        raise ValueError("frame troppo grande")
    sess["sock"].sendall(bytes([tipo]) + struct.pack(">I", len(token)) + token)


def ricevi_frame(sess):
    testa = recvall(sess["sock"], 5)
    tipo = testa[0]
    if tipo < T_MSG or tipo > T_BYE:
        raise ValueError("frame sconosciuto %d" % tipo)
    lung = struct.unpack(">I", testa[1:])[0]
    if lung == 0 or lung > MAX_CHUNK_TOKEN:
        raise ValueError("frame non valido")
    return tipo, sess["fernet"].decrypt(recvall(sess["sock"], lung))


# --------------------------------------------------------------------------
# verso l'hub
# --------------------------------------------------------------------------

def leggi_config():
    prepara_cartella_config()
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except json.JSONDecodeError:
            print("[!] config.json corrotto, riparto da zero")
    return {}


def salva_config(dati):
    scrivi_privato(CONFIG_FILE, (json.dumps(dati, indent=2) + "\n").encode())


def indirizzo_hub(cfg):
    host = (cfg.get("hub") or "").strip()
    if not host:
        raise SystemExit(
            "Non so ancora quale hub usare.\n"
            "  veil2.py hub miohub.duckdns.org      (host, o host:porta)"
        )
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.rstrip("/")
    if "/" in host:
        host = host.split("/", 1)[0]
    porta = 443
    if ":" in host:
        host, _, p = host.rpartition(":")
        porta = int(p)
    if cfg.get("tls") == "off":
        porta = porta if porta != 443 else 8080
    return host, porta


def apri_hub(cfg):
    host, porta = indirizzo_hub(cfg)
    pin = (cfg.get("pin") or "").replace(":", "").strip().lower()
    usa_tls = cfg.get("tls", "on") != "off"

    grezzo = socket.create_connection((host, porta), timeout=20)
    if not usa_tls:
        return grezzo, pin, False

    if pin:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        sock = ctx.wrap_socket(grezzo, server_hostname=host)
    except ssl.SSLCertVerificationError:
        grezzo.close()
        grezza, leggibile = _impronta_remota(host, porta)
        if not pin:
            raise SystemExit(
                "Il certificato di %s non e' firmato da nessuna autorita' che\n"
                "questo PC conosca:\n  %s\n"
                "Se e' il tuo hub, pinnalo con:\n  veil2.py pin %s"
                % (host, leggibile, grezza)
            )
        raise
    except OSError:
        grezzo.close()
        raise

    if pin:
        grezza, leggibile = _impronta_da_socket(sock)
        if grezza != pin:
            sock.close()
            raise SystemExit(
                "Il certificato di %s NON coincide con quello pinnato.\n"
                "  atteso: %s\n  trovato: %s\n"
                "Se hai cambiato hub o rigenerato il certificato, aggiorna il pin\n"
                "con 'veil2.py pin <impronta>'. Se non ti aspettavi nulla, fermati:\n"
                "qualcuno potrebbe starsi mettendo in mezzo."
                % (host, pin, leggibile)
            )
    sock.settimeout(None)
    return sock, pin, usa_tls


def _impronta_remota(host, porta):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, porta), timeout=15) as g:
        with ctx.wrap_socket(g, server_hostname=host) as s:
            return _impronta_da_socket(s)


def _impronta_da_socket(sock):
    der = sock.getpeercert(binary_form=True)
    grezza = hashlib.sha256(der).hexdigest()
    return grezza, ":".join(grezza[i:i + 2] for i in range(0, len(grezza), 2))


def scambia_preludio(sock, stanza, nick, pub):
    preludio = "%s\nstanza=%s\nnick=%s\npub=%s\n\n" % (
        PREDA.decode(), stanza, nick, pub)
    sock.sendall(preludio.encode())
    while True:
        riga = b""
        while not riga.endswith(b"\n"):
            blocco = sock.recv(1)
            if not blocco:
                raise ConnectionError("l'hub ha chiuso durante il preludio")
            riga += blocco
        testo = riga.decode(errors="replace").strip()
        if not testo:
            continue
        if testo.startswith("ERR"):
            raise ConnectionError(testo[3:].strip())
        if testo == "OK accoppiato":
            return True
        if testo == "OK attesa":
            return False
        raise ConnectionError("risposta hub non riconosciuta: %s" % testo[:60])


# --------------------------------------------------------------------------
# il ciclo di un contatto
# --------------------------------------------------------------------------

def segna(nick, **campi):
    with LOCK_STATO:
        STATO.setdefault(nick, {}).update(campi)


def leggi_stato(nick):
    with LOCK_STATO:
        return dict(STATO.get(nick, {"stato": "ignoto"}))


def ciclo_contatto(nick, contatto):
    """Un thread per contatto: si collega, tiene la sessione aperta, e quando
    cade la riapre. Niente thread che nasce e muore a ogni messaggio: e' il
    motivo per cui non serve fare Argon2id 64 MiB per ogni riga scritta."""
    tentativo = 0
    while True:
        try:
            tentativo = 0
            cfg = leggi_config()
            sock, _, _ = apri_hub(cfg)
            try:
                FASE["nome"] = "preludio con l'hub"
                accoppiato = scambia_preludio(sock, stanza_di(contatto), nick, chiave_registro())
                if not accoppiato:
                    segna(nick, stato="attesa", errore="l'altro PC non e' collegato")
                    FASE["nome"] = "in attesa che l'altro PC arrivi"
                    # Si torna qui GIA' ACCOPPIATI, e su questo stesso socket.
                    # Ricollegarsi qui ucciderebbe la coppia che l'hub ha appena
                    # aperto: lui la chiude, e anche l'altro PC ricomincia.
                    attende_accoppiamento(sock, nick)
                segna(nick, stato="negozia")
                FASE["nome"] = "negoziato"
                fernet = scambio_chiavi(sock, IDENTITA, contatto["passphrase"], nick)
                segna(nick, stato="online", errore=None,
                      sessione={"sock": sock, "fernet": fernet},
                      lock=threading.Lock(), ack=threading.Event())
                FASE["nome"] = "sessione aperta"
                ricevi_ciclo(nick, sock, fernet)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        except SystemExit:
            raise
        except Exception as errore:
            testo = "%s, %s" % (FASE["nome"], sanifica(str(errore))[:160])
            registra_sicurezza("%s: %s" % (nick, testo))
            if testo not in VISTI.get(nick, ()):
                VISTI.setdefault(nick, []).append(testo)
                avvisa("[!] %s: %s" % (nick, testo))

        finally:
            segna(nick, stato="offline", sessione=None)
            tentativo = min(tentativo + 1, 6)
            # backoff con scarto: due PC che rientrano insieme non si
            # martellano a vicenda per un'ora
            attesa = min(2 ** tentativo, PAUSA_MAX) * (0.7 + secrets.randbelow(6) / 10)
            time.sleep(attesa)


def attende_accoppiamento(sock, nick):
    """L'hub ha detto 'OK attesa': l'altro non e' ancora collegato. Restiamo
    appesi finche' l'hub non ci scrive 'OK accoppiato' e poi comincia il
    negoziato. Se l'hub chiude, si riprova con un backoff."""
    while True:
        riga = b""
        while not riga.endswith(b"\n"):
            blocco = sock.recv(1)
            if not blocco:
                raise ConnectionError("l'hub ha chiuso mentre aspettavamo l'altro peer")
            riga += blocco
        testo = riga.decode(errors="replace").strip()
        if testo == "OK accoppiato":
            return
        if testo.startswith("ERR"):
            raise ConnectionError(testo[3:].strip())


def ricevi_ciclo(nick, sock, fernet):
    """Legge i frame finche' la sessione dura. Messaggi e file arrivano
    intrecciati: e' il motivo per cui esiste una sessione sola invece di
    riaprire la connessione a ogni messaggio."""
    sess = {"sock": sock, "fernet": fernet}
    file_aperta = None
    destinazione = None
    scaricati = 0
    attesi = 0
    try:
        while True:
            tipo, payload = ricevi_frame(sess)
            if tipo == T_MSG:
                lung = int.from_bytes(payload[:4], "big")
                if 4 + lung > len(payload):
                    raise ValueError("messaggio corrotto (padding non valido)")
                testo = sanifica(payload[4:4 + lung].decode("utf-8", errors="replace"))
                registra_messaggio(nick, "ricevuto da", testo)
                avvisa("[%s] %s" % (nick, testo))
            elif tipo == T_FILE:
                meta = json.loads(payload)
                nome = sanifica(Path(str(meta.get("nome", ""))).name).strip()
                attesi = int(meta.get("size", -1))
                if not nome or nome in (".", "..") or attesi < 0 or attesi > MAX_FILE_SIZE:
                    spedisci(sess, T_ERR, b"richiesta non valida")
                    break
                DROP_DIR.mkdir(exist_ok=True)
                destinazione = DROP_DIR / nome
                n = 1
                while destinazione.exists():
                    destinazione = DROP_DIR / ("%s-%d%s" % (
                        Path(nome).stem, n, Path(nome).suffix))
                    n += 1
                file_aperta = open(destinazione, "wb")
                scaricati = 0
                spedisci(sess, T_ACK)
                avvisa("[+] %s sta inviando '%s' (%d byte)" % (nick, nome, attesi))
            elif tipo == T_CHUNK:
                if file_aperta is None:
                    raise ValueError("chunk senza intestazione")
                file_aperta.write(payload)
                scaricati += len(payload)
                if scaricati % (8 * CHUNK_SIZE) < CHUNK_SIZE:
                    avvisa("    %s: %d/%d byte" % (nick, scaricati, attesi))
            elif tipo == T_DONE:
                if file_aperta is not None:
                    file_aperta.close()
                    file_aperta = None
                    avvisa("[+] File ricevuto: %s (%d byte)" % (destinazione, scaricati))
                spedisci(sess, T_ACK)
            elif tipo == T_ACK:
                with LOCK_STATO:
                    evento = STATO.get(nick, {}).get("ack")
                if evento:
                    evento.set()
            elif tipo == T_ERR:
                avvisa("[!] %s: %s" % (nick, sanifica(payload.decode(errors="replace"))))
            elif tipo == T_BYE:
                break
    except (InvalidToken, ValueError, json.JSONDecodeError, KeyError) as errore:
        avvisa("[!] Sessione con %s interrotta: %s" % (nick, errore))
    except (ConnectionError, OSError):
        pass
    finally:
        if file_aperta is not None:
            # trasferimento incompleto: il file a meta' non resta li' a fare
            # finta di essere un file
            file_aperta.close()
            try:
                destinazione.unlink()
                avvisa("[!] File incompleto eliminato: %s" % destinazione)
            except (OSError, UnboundLocalError):
                pass


# --------------------------------------------------------------------------
# invio
# --------------------------------------------------------------------------

_MUTEX_GLOBALE = threading.Lock()


def lock_di(nick):
    with LOCK_STATO:
        return STATO.get(nick, {}).get("lock") or _MUTEX_GLOBALE


def aspetta_ack(nick, secondi=30):
    with LOCK_STATO:
        evento = STATO.get(nick, {}).get("ack")
    if evento is None:
        return False
    evento.clear()
    return evento.wait(secondi)


def invia_messaggio(nick, testo):
    if len(testo.encode()) > MAX_MSG_SIZE:
        print("Messaggio troppo lungo: il massimo e' 1 MB")
        return
    with lock_di(nick):
        sess = leggi_stato(nick).get("sessione")
        if not sess:
            print("[!] %s non e' collegato" % nick)
            return
        spedisci(sess, T_MSG, imballa(testo))
    registra_messaggio(nick, "inviato a", testo)
    print("messaggio inviato")


def invia_file(nick, percorso):
    src = Path(percorso.strip().strip('"').strip("'")).expanduser()
    if not src.is_file():
        print("File non esistente")
        return
    dimensione = src.stat().st_size
    if dimensione > MAX_FILE_SIZE:
        print("File troppo grande: il massimo e' 10 GB")
        return
    DROP_DIR.mkdir(exist_ok=True)
    with lock_di(nick):
        sess = leggi_stato(nick).get("sessione")
        if not sess:
            print("[!] %s non e' collegato" % nick)
            return
        spedisci(sess, T_FILE, json.dumps({"nome": src.name, "size": dimensione}).encode())
        if not aspetta_ack(nick):
            print("[!] %s non ha confermato, file non inviato" % nick)
            return
        inviati = 0
        with open(src, "rb") as f:
            while True:
                blocco = f.read(CHUNK_SIZE)
                if not blocco:
                    break
                spedisci(sess, T_CHUNK, blocco)
                inviati += len(blocco)
                sys.stdout.write("\r\x1b[2K  inviato %d/%d byte" % (inviati, dimensione))
                sys.stdout.flush()
        spedisci(sess, T_DONE)
        sys.stdout.write("\r\x1b[2K")
        if aspetta_ack(nick, 60):
            print("file inviato: %s" % src.name)
        else:
            print("[!] il peer non ha confermato la ricezione")


# --------------------------------------------------------------------------
# cronologia
# --------------------------------------------------------------------------

def chiave_log(nick, contatto):
    sale = hashlib.sha256(b"veil2-log-v5|" + stanza_di(contatto).encode()).digest()[:16]
    radice = radice_kdf(contatto["passphrase"].encode(), sale)
    return Fernet(urlsafe_b64encode(sottochiave(radice, b"veil2-log")))


def cartella_log(nick):
    return MESSAGGI_DIR / nick


def registra_messaggio(nick, direzione, testo):
    cartella = cartella_log(nick)
    cartella.mkdir(parents=True, exist_ok=True)
    try:
        cartella.chmod(0o700)
    except OSError:
        pass
    ora = datetime.now()
    percorso = cartella / ("%s.log" % ora.strftime("%Y-%m-%d"))
    riga = "[%s] %s: %s" % (ora.strftime("%d/%m/%Y %H:%M:%S"), direzione, testo)
    try:
        with open(percorso, "a") as f:
            f.write(chiave_log(nick, CONTATTI[nick]).encrypt(riga.encode()).decode() + "\n")
    except (InvalidToken, KeyError):
        pass


def leggi_log(nick):
    cartella = cartella_log(nick)
    if not cartella.exists():
        print("Nessun messaggio salvato con '%s'." % nick)
        return
    chiave = chiave_log(nick, CONTATTI[nick])
    for cronologia in sorted(cartella.glob("*.log")):
        print("--- %s / %s ---" % (nick, cronologia.stem))
        scartate = 0
        for riga in cronologia.read_text().splitlines():
            try:
                print(chiave.decrypt(riga.encode()).decode())
            except (InvalidToken, ValueError):
                scartate += 1
        if scartate:
            print("(%d righe non decifrabili: passphrase cambiata o log in vecchio formato)" % scartate)


# --------------------------------------------------------------------------
# input a terminale
# --------------------------------------------------------------------------

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
        fd = sys.stdin.fileno()
        if STATO_INPUT.get("salvate"):
            termios.tcsetattr(fd, termios.TCSADRAIN, STATO_INPUT["salvate"])
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
        testa, sep, prefisso = espanso.rpartition("/")
        cartella = (testa + sep) if sep else "."
        if not sep:
            prefisso = espanso
        try:
            corrispondenze = sorted(Path(cartella).glob(prefisso + "*"))
        except (OSError, ValueError):
            return
        if not corrispondenze:
            return
        nomi = [c.name + ("/" if c.is_dir() else "") for c in corrispondenze]
        completato = cartella + os.path.commonprefix(nomi)
        if " " in completato or citato:
            completato = '"' + completato + '"'
        STATO_INPUT["bozza"] = (parti[0] + " " + completato) if len(parti) > 1 else completato
        ridisegna_input()
        if len(corrispondenze) > 1:
            sys.stdout.write("\n" + "  ".join(nomi[:15]) + (" ..." if len(nomi) > 15 else "") + "\n")
            ridisegna_input()
        sys.stdout.flush()


def leggi_riga():
    if not STATO_INPUT.get("raw"):
        return input("> ")
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


# --------------------------------------------------------------------------
# il ciclo di chat
# --------------------------------------------------------------------------

def mostra_contatti():
    if not CONTATTI:
        print("\nNessun contatto. Creane uno con:  veil2.py nuovo <nickname>")
        return
    print("\nI tuoi contatti:")
    for nick in sorted(CONTATTI):
        info = leggi_stato(nick)
        etichetta = {
            "online": "\033[32monline\033[0m",
            "attesa": "in attesa (l'altro non e' collegato)",
            "negozia": "negoziando la sessione",
            "offline": "non collegato",
        }.get(info.get("stato"), info.get("stato", "ignoto"))
        riga = "  %-16s %s" % (nick, etichetta)
        if info.get("errore"):
            riga += "  (%s)" % sanifica(info["errore"])[:60]
        print(riga)
    print()


def elabora(riga, selezionato):
    globale_selezionato = selezionato
    pulito = riga.strip()
    if not pulito:
        return selezionato, True
    basso = pulito.lower()
    if basso in ("x", "esci", "quit"):
        return selezionato, False
    if basso in ("?", "lista", "contatti"):
        mostra_contatti()
        return selezionato, True
    if selezionato is None:
        if " " in pulito:
            destinatario, _, resto = pulito.partition(" ")
            if destinatario in CONTATTI:
                return invia_quello(destinatario, resto.strip())
            print("Nessun contatto '%s'. Usa ? per la lista." % destinatario)
            return selezionato, True
        if pulito in CONTATTI:
            info = leggi_stato(pulito)
            if info.get("stato") != "online":
                print("[!] %s non e' collegato (%s)" % (pulito, info.get("stato")))
                return selezionato, True
            return pulito, True
        print("Scrivi un nickname per scegliere il contatto, ? per la lista, x per uscire.")
        return selezionato, True
    if basso == "q":
        return None, True
    # "nick messaggio" resta valido anche quando hai gia' scelto quel
    # contatto: e' quello che scriverebbe istintivamente chi ha appena
    # cambiato interlocutore. Tolto solo se il resto e' un percorso, cosi'
    # un messaggio che comincia per il nome di un contatto non viene
    # mutilato ("mario va bene" resta "mario va bene").
    for altro in sorted(CONTATTI):
        if pulito.lower().startswith(altro + " "):
            resto = pulito[len(altro) + 1:].strip()
            if resto.startswith(("/", "~/", "./", '"/', '"~/')):
                pulito = resto
            break
    return invia_quello(selezionato, pulito)


def invia_quello(nick, testo):
    if not testo:
        print("[+] Parli con %s. Scrivi il messaggio, un percorso per un file, q per cambiare." % nick)
        return nick, True
    if testo.startswith('"') and len(testo) > 1 and testo[-1] == '"':
        testo = testo[1:-1]
    elif "/" in testo or testo.startswith("~"):
        if not Path(testo.strip('"')).expanduser().is_file():
            print("File non esistente")
            return nick, True
        invia_file(nick, testo)
        return nick, True
    invia_messaggio(nick, testo)
    return nick, True


def chat():
    cfg = primo_avvio(leggi_config())
    banner()
    print("Hub:  %s" % (cfg.get("hub") or "(non impostato)"))
    print("Tu:   %s" % IL_MIO_NICK)
    if not CONTATTI:
        print("\nNon hai contatti. Crea le credenziali con 'veil2.py nuovo <nickname>'")
        return
    for nick in sorted(CONTATTI):
        segna(nick, stato="collegamento", sessione=None, errore=None)
        threading.Thread(target=ciclo_contatto, args=(nick, CONTATTI[nick]), daemon=True).start()

    print("\nAttendo che i contatti si colleghino...")
    tempo = 0
    while tempo < 4:
        if any(leggi_stato(n)["stato"] == "online" for n in CONTATTI):
            break
        time.sleep(0.5)
        tempo += 0.5
    mostra_contatti()
    print("? per la lista · un nickname per scegliere · 'nick messaggio' per scrivere subito")
    print("un percorso per inviare un file · q cambia contatto · x esce\n")

    attiva_input_raw()
    selezionato = None
    try:
        while True:
            try:
                riga = leggi_riga()
            except (KeyboardInterrupt, EOFError):
                print("\nCiao!")
                break
            selezionato, continua = elabora(riga, selezionato)
            if not continua:
                break
    finally:
        ripristina_input()
        for nick in CONTATTI:
            info = leggi_stato(nick)
            if info.get("sessione"):
                try:
                    spedisci(info["sessione"], T_BYE)
                except OSError:
                    pass


# --------------------------------------------------------------------------
# riga di comando
# --------------------------------------------------------------------------

def primo_avvio(cfg):
    """Il nostro nickname e l'hub: si chiedono solo quando servono davvero,
    cioe' quando si avvia la chat. Creare un contatto non richiede nessuna
    delle due cose."""
    global IL_MIO_NICK
    if not cfg.get("nick"):
        while True:
            nick = input(
                "Il tuo nickname (a-z 0-9 . _ -, 2-32 caratteri, deve iniziare\n"
                "con una lettera o un numero): "
            ).strip().lower()
            if RE_NICK.match(nick):
                cfg["nick"] = nick
                salva_config(cfg)
                break
            print("Non valido.")
    IL_MIO_NICK = cfg["nick"]

    if not cfg.get("hub"):
        print()
        print("Non hai ancora un hub. Il tuo contatto te ne passera' uno, e poi:")
        print("  veil2.py imposta-hub miohub.duckdns.org")
        print("Se invece vuoi provarlo in rete locale:")
        print("  veil2.py --senza-tls imposta-hub 192.168.1.10:8080")
        print()
    return cfg


def main():
    ap = argparse.ArgumentParser(
        prog="veil2.py",
        description="Chat e file cifrati end-to-end attraverso un relay anonimo",
    )
    ap.add_argument("--pin", help="impronta SHA-256 del certificato dell'hub")
    ap.add_argument("--senza-tls", action="store_true", help="hub in chiaro (solo LAN/prova)")
    ap.add_argument("--leggi-log", metavar="NICK", nargs="?", help="mostra la cronologia cifrata")
    ap.add_argument("--cambia-password", action="store_true", help="cambia la passphrase di questo PC")
    ap.add_argument("--migra-kdf", choices=["argon2id", "pbkdf2"], help="cambia KDF dei file locali")
    sotto = ap.add_subparsers(dest="comando")

    p = sotto.add_parser("nuovo", help="genera le credenziali per un contatto")
    p.add_argument("nick")
    p = sotto.add_parser("aggiungi", help="importa le credenziali di un contatto")
    p.add_argument("nick")
    p.add_argument("invito")
    p = sotto.add_parser("dimentica", help="dimentica l'impronta pinnata di un contatto")
    p.add_argument("nick")
    p = sotto.add_parser("rimuovi", help="cancella un contatto")
    p.add_argument("nick")
    sotto.add_parser("hub", help="mostra l'hub in uso")
    p = sotto.add_parser("imposta-hub", help="imposta l'hub (host o host:porta)")
    p.add_argument("host")
    p = sotto.add_parser("impronta", help="mostra o imposta l'impronta del certificato hub")
    p.add_argument("hex", nargs="?")
    p = sotto.add_parser("stato", help="chiede all'hub come sta")
    p.add_argument("--json", action="store_true")

    args = ap.parse_args()

    cfg = leggi_config()
    if args.pin:
        cfg["pin"] = args.pin.replace(":", "").strip().lower()
        salva_config(cfg)
    if args.senza_tls:
        cfg["tls"] = "off"
        salva_config(cfg)

    if args.comando in ("hub", "imposta-hub", "impronta", "stato"):
        return comandi_senza_segreto(args, cfg)

    if args.cambia_password:
        return cambia_password_dispositivo()

    chiedi_passphrase_dispositivo()
    carica_identita()

    if args.migra_kdf:
        return migra_kdf(args.migra_kdf)

    carica_contatti()

    if args.leggi_log is not None:
        if args.leggi_log:
            if args.leggi_log not in CONTATTI:
                raise SystemExit("Nessun contatto '%s'." % args.leggi_log)
            return leggi_log(args.leggi_log)
        if not CONTATTI:
            print("Nessun contatto.")
            return
        if len(CONTATTI) == 1:
            return leggi_log(next(iter(CONTATTI)))
        print("Contatti: %s" % ", ".join(sorted(CONTATTI)))
        return leggi_log(input("Di chi? ").strip())
    if args.comando == "nuovo":
        return cmd_nuovo(args.nick)
    if args.comando == "aggiungi":
        return cmd_aggiungi(args.nick, args.invito)
    if args.comando == "dimentica":
        return cmd_dimentica(args.nick)
    if args.comando == "rimuovi":
        return cmd_rimuovi(args.nick)
    chat()


def comandi_senza_segreto(args, cfg):
    if args.comando == "hub":
        print("hub:    %s" % (cfg.get("hub") or "(non impostato)"))
        print("tls:    %s" % cfg.get("tls", "on"))
        print("pin:    %s" % (cfg.get("pin") or "(non impostato)"))
        return
    if args.comando == "imposta-hub":
        host = args.host.strip().rstrip("/")
        if "://" in host:
            host = host.split("://", 1)[1]
        cfg["hub"] = host
        salva_config(cfg)
        print("hub impostato: %s" % host)
        grezza, leggibile = None, None
        if cfg.get("tls", "on") != "off":
            try:
                grezza, leggibile = _impronta_remota(*indirizzo_hub(cfg))
            except OSError as errore:
                print("Non riesco a raggiungerlo ora: %s" % errore)
                return
            print("impronta del certificato: %s" % leggibile)
            if not cfg.get("pin"):
                if input("La pinniamo? [s/N]: ").strip().lower() == "s":
                    cfg["pin"] = grezza
                    salva_config(cfg)
                    print("pinnata.")
        return
    if args.comando == "impronta":
        if args.hex:
            cfg["pin"] = args.hex.replace(":", "").strip().lower()
            salva_config(cfg)
            print("impronta impostata: %s" % cfg["pin"])
        else:
            print("pin attuale: %s" % (cfg.get("pin") or "(nessuno)"))
            if cfg.get("hub"):
                try:
                    print("certificato di %s: %s" % (
                        indirizzo_hub(cfg)[0], _impronta_remota(*indirizzo_hub(cfg))[1]))
                except OSError:
                    pass
        return
    if args.comando == "stato":
        try:
            sock, _, _ = apri_hub(cfg)
        except SystemExit:
            raise
        except OSError as errore:
            print("hub non raggiungibile: %s" % errore)
            return
        try:
            sock.sendall(b"%s\nping=1\n\n" % PREDA)
            riga = b""
            while not riga.endswith(b"\n"):
                blocco = sock.recv(4096)
                if not blocco:
                    break
                riga += blocco
            if args.json:
                print(riga.decode(errors="replace").strip())
            else:
                dati = json.loads(riga.decode(errors="replace"))
                for chiave, valore in dati.items():
                    if isinstance(valore, dict):
                        valore = ", ".join("%s=%s" % kv for kv in valore.items())
                    print("%-20s %s" % (chiave, valore))
        except (OSError, json.JSONDecodeError) as errore:
            print("risposta non leggibile: %s" % errore)
        finally:
            sock.close()


def cmd_nuovo(nick):
    contatto = nuovo_contatto(nick)
    testo = invito(nick, contatto)
    CONTATTI[nick] = contatto
    salva_contatti()

    cartella = Path.home() / ".veil2-inviti"
    cartella.mkdir(parents=True, exist_ok=True)
    try:
        cartella.chmod(0o700)
    except OSError:
        pass
    (cartella / ("%s.invito" % nick)).write_text(testo + "\n")
    try:
        (cartella / ("%s.invito" % nick)).chmod(0o600)
    except OSError:
        pass

    print()
    print("Contatto '%s' creato e salvato su questo PC." % nick)
    print()
    print("────────────────────────────────────────────────────────")
    print(" Da portare all'altro PC (in persona, o su un canale fidato):")
    print()
    print("  veil2.py aggiungi %s %s" % (nick, testo))
    print("────────────────────────────────────────────────────────")
    print()
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data("veil2:add:%s:%s" % (nick, testo))
        qr.print_ascii(invert=True)
        print("Scansiona questo QR dall'altro PC: la riga si riempie da sola.")
        print()
    except ImportError:
        pass
    print("Quella riga e' TUTTO il canale: chi la legge puo' leggere i messaggi.")
    print("Se la perdi il contatto e' perso, non c'e' un recupero. Copia anche in")
    print("~/.veil2-inviti/%s.invito" % nick)
    print()
    print("Quando entrambi avete il contatto, avviate veil2.py e confrontate le")
    print("impronte in faccia: e' l'unica verifica che esiste, e va fatta una volta sola.")


def cmd_aggiungi(nick, testo_invito):
    dati = leggi_invito(testo_invito)
    if dati["n"] != nick:
        raise SystemExit("L'invito è per '%s', non per '%s'." % (dati["n"], nick))
    if not RE_NICK.match(nick):
        raise SystemExit("Nickname non valido.")
    if nick in CONTATTI:
        risposta = input("'%s' c'e' gia'. Sovrascrivo? [s/N]: " % nick).strip().lower()
        if risposta != "s":
            return
    CONTATTI[nick] = {
        "passphrase": dati["p"],
        "segreto": dati["s"],
        "peer": None,
        "aggiunto": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    salva_contatti()
    print("Contatto '%s' aggiunto." % nick)
    print("Al primo contatto confrontate le impronte in persona: e' l'unica verifica che esiste.")


def cmd_dimentica(nick):
    percorso = PEER_DIR / (nick + ".key")
    if percorso.exists():
        percorso.unlink()
    if nick in CONTATTI:
        CONTATTI[nick]["peer"] = None
        salva_contatti()
        print("Pin di '%s' dimenticato. Alla prossima connessione vi riverificate le impronte." % nick)
    else:
        print("Nessun pin per '%s'." % nick)


def cmd_rimuovi(nick):
    if nick not in CONTATTI:
        print("Nessun contatto '%s'." % nick)
        return
    del CONTATTI[nick]
    salva_contatti()
    percorso = PEER_DIR / (nick + ".key")
    if percorso.exists():
        percorso.unlink()
    print("Contatto '%s' rimosso. I log cifrati sono rimasti in %s." % (nick, cartella_log(nick)))


def cambia_password_dispositivo():
    """Si decifra con la vecchia passphrase e si ricifra con la nuova. La
    vecchia non viene buttata prima: se qualcosa va storto, i dati sono
    ancora li."""
    global PASSWORD_GLOBALE, CHIAVE_CONTATTI
    prepara_cartella_config()
    PASSWORD_FILE = CONFIG_DIR / "password"
    if not PASSWORD_FILE.exists():
        raise SystemExit("Non c'e' ancora nessuna passphrase da cambiare.")
    vecchia = PASSWORD_FILE.read_text().strip()
    inserita = getpass.getpass("Passphrase attuale di questo PC: ")
    if not hmac.compare_digest(inserita.encode(), vecchia.encode()):
        raise SystemExit("Non coincide.")

    PASSWORD_GLOBALE = inserita
    fernet_vecchio = chiave_dispositivo(b"identita")
    try:
        privata = fernet_vecchio.decrypt(IDENTITY_FILE.read_bytes().strip())
    except InvalidToken:
        raise SystemExit("L'identita' non si apre con questa passphrase. Niente e' stato toccato.")

    while True:
        nuova = getpass.getpass("Nuova passphrase: ")
        if len(nuova) < 12:
            if input("Meno di 12 caratteri. Uso comunque? [s/N]: ").strip().lower() != "s":
                continue
        if not nuova:
            continue
        if nuova == inserita:
            print("Quella e' gia' la passphrase di questo PC.")
            return
        break

    PASSWORD_GLOBALE = nuova
    CHIAVE_CONTATTI = None
    fernet_nuovo = chiave_dispositivo(b"identita")
    scrivi_privato(IDENTITY_FILE, fernet_nuovo.encrypt(privata) + b"\n")

    if CONTATTI_FILE.exists():
        try:
            grezzo = chiave_dispositivo(b"contatti").decrypt(CONTATTI_FILE.read_bytes().strip())
            CONTATTI = json.loads(grezzo)
        except InvalidToken:
            raise SystemExit("Il DB dei contatti non si apre: Niente e' stato toccato.")
        salva_contatti()
    print("Passphrase di questo PC cambiata. Identita' e contatti ricifrati.")
    print("Attenzione: i log delle chat sono cifrati con la passphrase del CONTATTO,")
    print("non con questa, quindi restano leggibili senza fare niente.")


def migra_kdf(nuovo):
    if kdf_attivo() == nuovo:
        print("Sei gia' su %s." % nuovo)
        return
    print("Si convertono i file locali (identita' e DB contatti) a %s." % nuovo)
    print("I log delle chat non cambiano: sono cifrati con una chiave derivata dal")
    print("contatto, quindi il KDF del PC non li tocca.")
    if nuovo == "argon2id" and ctypes.util.find_library("argon2") is None:
        print("\nAttenzione: libargon2 non c'e' su questo PC. Senza di lei il KDF")
        print("ricadrebbe su PBKDF2 e i file NON si aprirebbero più.")
        print("  Debian/Ubuntu:  sudo apt install libargon2-1")
        print("  Void:           sudo xbps-install libargon2")
        if input("Continuo lo stesso? [s/N]: ").strip().lower() != "s":
            return
    if input("Procedo? [s/N]: ").strip().lower() != "s":
        return

    identita_privata = None
    contatti_grezzo = None
    try:
        identita_privata = chiave_dispositivo(b"identita").decrypt(
            IDENTITY_FILE.read_bytes().strip())
    except (InvalidToken, OSError):
        identita_privata = None
    try:
        contatti_grezzo = chiave_dispositivo(b"contatti").decrypt(
            CONTATTI_FILE.read_bytes().strip())
    except (InvalidToken, OSError):
        contatti_grezzo = None

    scrivi_privato(KDF_FILE, (nuovo + "\n").encode())
    global CHIAVE_CONTATTI
    CHIAVE_CONTATTI = None
    if identita_privata is not None:
        scrivi_privato(IDENTITY_FILE, chiave_dispositivo(b"identita").encrypt(identita_privata) + b"\n")
    if contatti_grezzo is not None:
        scrivi_privato(CONTATTI_FILE, chiave_dispositivo(b"contatti").encrypt(contatti_grezzo) + b"\n")
    print("Fatto: il KDF di questo PC ora e' %s." % nuovo)
    print("Ricontrolla che l'altro PC usi lo stesso metodo, altrimenti non vi parlate.")


if __name__ == "__main__":
    try:
        main()
    except EOFError:
        # stdin chiuso o chiuso a metà: qualcuna delle domande non ha
        # ricevuto risposta. Meglio una riga in chiaro che una pila di
        # tracce Python.
        print("\nInterrotto: manca una risposta e l'input e' finito.")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(130)
