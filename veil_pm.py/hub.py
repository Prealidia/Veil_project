#!/usr/bin/env python3
# hub.py - Relay "senza registro" per Veil 2 (protocollo versione 5)
#
# Gira su un server pubblico (qui: Debian). E' solo una casella postale: unisce
# due computer che gia' condividono una passphrase, poi si mette da parte e
# lascia che i due parlino fra loro. NIENTE utenti, niente nickname registrati,
# niente database, niente log di chi sei: se il server si riavvia non sa piu'
# nulla di nessuno.
#
# Il relay NON legge i messaggi: copia byte da una socket all'altra senza
# interpretarli. Non conosce la passphrase e non potrebbe decifrare nulla
# anche se volesse, perche' non vede chiavi ne' contenuti. Non vede nemmeno
# la stanza, che e' uno sha256 di un segreto casuale ad alta entropia e non
# della passphrase.
#
# Perche' un relay e non una connessione diretta fra i due PC: perche' stanno
# dietro router diversi, e uno dei due probabilmente anche dietro CGNAT. Nessun
# trucco di NAT fa funzionare una connessione UDP peer-to-peer li'. Un relay con
# una sola connessione TCP in uscita funziona sempre e non chiede a nessuno di
# aprire porte.
#
# PROTOCOLLO
#   Il client apre TLS e manda un preludio in chiaro dentro il tunnel:
#       VEIL2/1\n
#       stanza=<64 caratteri hex>\n
#       nick=<nome>\n
#       pub=<chiave pubblica in base64>\n
#       \n
#   L'hub risponde "OK accoppiato\n" (l'altro peer e' li', la pipe parte) oppure
#   "OK attesa\n" (resto in coda finche' non arriva) oppure "ERR <motivo>\n".
#   "OK attesa" vuol dire anche: può arrivare un'altra riga "OK accoppiato" piu'
#   tardi, quando l'altro si collega. Il client le legge una alla volta, e solo
#   dopo comincia il proprio scambio di chiavi.
#   Poi la socket diventa una pipe bidirezionale verso l'altro PC della stanza.
#   Niente header, niente framing, niente offset: cio' che il client scrive
#   arriva identico al suo scambio di chiavi, quindi il layer crittografico
#   del client non ha idea che questo programma esista.
#
# Una sola porta, TCP. Nessuna porta UDP.
#
#   hub.py                                 # ascolta su :443 con TLS
#   hub.py --porta 8443
#   hub.py --no-tls                        # dietro un terminatore TLS
#                                          # (nginx stream, Caddy, LAN)
#   hub.py --genera-tls /etc/veil2/tls     # certificato + impronta da pinnare

import argparse
import hashlib
import json
import os
import re
import select
import signal
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

VERSIONE = 5
PREDA = b"VEIL2/1"
PREDA_DECODED = "VEIL2/1"

# Solo forma dell'input: non serve a fidarsi di qualcuno, serve a non far
# lavorare la CPU a casaccio su dati sbagliati.
RE_ROOM = re.compile(r"^[0-9a-f]{64}$")
RE_NICK = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,31}$")
RE_PUB = re.compile(r"^[A-Za-z0-9+/]{43}=$")      # 32 byte base64 standard

# Limiti di risorse. Volutamente stretti: il server e' pubblico e non deve
# poter essere usato per ospitare traffico arbitrario ne' per far esaurire la
# RAM di chi lo ospita.
MAX_STANZE = 512
MAX_SESSIONI = 2            # connessioni per stanza: una coppia
MAX_IN_ATTESA = 4
MAX_COPPIE = 1024           # coppie attive su tutto il server
MAX_PRELUDE = 4096
MAX_STANZA_VUOTA = 900      # stanza senza nessuno: cancellata dopo 15 minuti
MAX_SESSIONE_MUTA = 86400   # coppia muta da un giorno: chiusa
MAX_ATTESA_COMPA = 600      # quanto aspetta chi arriva primo
BUFFER = 65536
TIMEOUT_PRELUDE = 20

TENTATIVI_BAN = 20
DURATA_BAN = 900

# RLock perche' le funzioni di rimozione chiamano altre funzioni che prendono
# lo stesso lock (togli -> togli della compagna).
LOCK_STANZE = threading.RLock()
LOCK_COPPIE = threading.RLock()
LOCK_BAN = threading.RLock()
LOCK_CONTA = threading.RLock()

STANZE = {}
COPPIE = 0
BAN = {}
CONTATORI = {"connessioni": 0, "coppie": 0, "rifiuti": 0, "bannati": 0}
AVVIO = time.time()


def log(frase, *campi):
    if campi:
        frase = frase % campi
    sys.stderr.write("[%s] %s\n" % (datetime.now(timezone.utc).strftime("%H:%M:%S"), frase))
    sys.stderr.flush()


def conta(nome):
    with LOCK_CONTA:
        CONTATORI[nome] = CONTATORI.get(nome, 0) + 1


def stato_globale():
    with LOCK_STANZE:
        stanze = len(STANZE)
        attese = sum(len(s["attesa"]) + len(s["coppie"]) for s in STANZE.values())
    with LOCK_COPPIE:
        coppie = COPPIE
    with LOCK_CONTA:
        cont = dict(CONTATORI)
    return {
        "servizio": "veil2-hub",
        "versione_protocollo": VERSIONE,
        "stanze_vive": stanze,
        "connessioni_vive": attese,
        "coppie_attive": coppie,
        "limiti": {
            "stanze": MAX_STANZE,
            "sessioni_per_stanza": MAX_SESSIONI,
            "coppie_totali": MAX_COPPIE,
        },
        "uptime_s": int(time.time() - AVVIO),
        "totali": cont,
        "memoria": "solo RAM: al riavvio non resta traccia di nessuno",
    }


# --- anti-abuso -------------------------------------------------------------

def bannato(ip):
    with LOCK_BAN:
        scadenza = BAN.get(ip, 0)
        if scadenza <= time.time():
            BAN.pop(ip, None)
            return False
        return True


def nota_rifiuto(ip):
    """Chiamata quando una connessione viene respinta. Tanti rifiuti e l'IP
    viene messo da parte: se qualcuno martella il server, si ferma lui, non
    gli altri."""
    if bannato(ip):
        return True
    with LOCK_BAN:
        chiave = "_t_" + ip
        t = BAN.get(chiave, 0) + 1
        if t >= TENTATIVI_BAN:
            BAN[ip] = time.time() + DURATA_BAN
            BAN.pop(chiave, None)
            conta("bannati")
            return True
        BAN[chiave] = t
    return False


# --- sessione ---------------------------------------------------------------

class Sessione:
    # "dato" = la socket e' passata al relay. Da quel momento e' il thread di
    # inoltro a possederla e nessun altro puo' chiuderla.
    __slots__ = ("sock", "ip", "stanza", "nick", "pub", "entrata", "casa", "dato")

    def __init__(self, sock, ip, stanza, nick, pub):
        self.sock = sock
        self.ip = ip
        self.stanza = stanza
        self.nick = nick
        self.pub = pub
        self.entrata = time.time()
        self.casa = None
        self.dato = False


def chiudi(sess):
    try:
        sess.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sess.sock.close()
    except OSError:
        pass


def rimuovi(sess):
    """Toglie una sessione da ogni lista e libera la compagna. Rientra nei
    lock perche' la compagna va rimossa a sua volta."""
    global COPPIE
    with LOCK_STANZE:
        stanza = STANZE.get(sess.stanza)
        if stanza is None:
            return
        if sess in stanza["attesa"]:
            stanza["attesa"].remove(sess)
        for altra in list(stanza["coppie"]):
            if altra is sess or altra.casa is sess:
                if altra in stanza["coppie"]:
                    stanza["coppie"].remove(altra)
                with LOCK_COPPIE:
                    COPPIE = max(0, COPPIE - 1)
                if altra is not sess and altra.casa is sess:
                    altra.casa = None
                    compagna = altra
                    break
        else:
            compagna = None
        if not stanza["attesa"] and not stanza["coppie"]:
            STANZE.pop(sess.stanza, None)
    if compagna is not None:
        rimuovi(compagna)
        chiudi(compagna)


def accoppia(sess, stanza):
    """Mette in coda la sessione e, se c'e' chi aspetta, la collega.
    Ritorna (compagna, motivo_rifiuto)."""
    global COPPIE
    with LOCK_STANZE:
        # chi si ricollega non deve lasciare il vecchio socket appeso: se
        # dalla stessa stanza arriva lo stesso nickname dallo stesso IP, il
        # vecchio e' un crashed-liberato e va buttato giu'
        for s in list(stanza["attesa"]) + list(stanza["coppie"]):
            if s.sock is sess or s.nick != sess.nick:
                continue
            if s.casa is None and s.ip == sess.ip and s.sock.fileno() >= 0:
                pass          # non e' ancora accoppiato: si lascia in coda
            else:
                rimuovi(s)
                chiudi(s)

        # pulizia: chi ha la socket morta non conta piu'
        for s in [x for x in stanza["attesa"] if x.sock.fileno() < 0]:
            stanza["attesa"].remove(s)
        for s in list(stanza["coppie"]):
            if s.casa is None or s.casa.sock.fileno() < 0:
                stanza["coppie"].remove(s)
                if s.casa is not None and s.casa.sock.fileno() < 0:
                    stanza["attesa"].append(s.casa)
                    s.casa.casa = None
                    s.casa = None
                with LOCK_COPPIE:
                    COPPIE = max(0, COPPIE - 1)

        for altra in stanza["attesa"]:
            if altra.casa is None:
                stanza["attesa"].remove(altra)
                stanza["coppie"].append(altra)
                altra.casa = sess
                sess.casa = altra
                with LOCK_COPPIE:
                    COPPIE += 1
                return altra, None

        if len(stanza["attesa"]) >= MAX_IN_ATTESA:
            return None, "stanza affollata"
        if len(stanza["coppie"]) >= MAX_SESSIONI:
            return None, "stanza piena"
        stanza["attesa"].append(sess)
        return None, None


def inoltra(sess_a, sess_b, a, b):
    """Copia byte fra due socket finche' una delle due non muore. Niente su
    disco, niente interpretato: solo uno spostamento di byte."""
    scaduta = time.time() + MAX_SESSIONE_MUTA
    trasferiti = 0
    while True:
        try:
            pronti, _, guasti = select.select([a, b], [], [], 30)
        except (OSError, ValueError) as errore:
            log("relay interrotto: %s" % errore)
            return
        if not pronti:
            if time.time() > scaduta:
                log("relay chiuso per inattivita': '%s' e '%s'" % (sess_a.nick, sess_b.nick))
                return
            continue
        for sorgente, altro in ((a, b), (b, a)):
            if sorgente not in pronti:
                continue
            nome = sess_a.nick if sorgente is a else sess_b.nick
            altro_nome = sess_b.nick if sorgente is a else sess_a.nick
            try:
                dato = sorgente.recv(BUFFER)
            except OSError as errore:
                log("relay: '%s' non piu' leggibile: %s" % (nome, errore))
                return
            if not dato:
                log("relay chiuso: '%s' ha lasciato la stanza (%d byte scambiati)"
                    % (nome, trasferiti))
                return
            try:
                altro.sendall(dato)
            except OSError as errore:
                log("relay: '%s' non piu' scrivibile: %s" % (altro_nome, errore))
                return
            scaduta = time.time() + MAX_SESSIONE_MUTA
            trasferiti += len(dato)


def servi(sess, compagno):
    try:
        inoltra(sess, compagno, sess.sock, compagno.sock)
    finally:
        rimuovi(sess)
        chiudi(sess)
        chiudi(compagno)
        log("coppia chiusa")


# --- preludo ----------------------------------------------------------------

def leggi_preludo(sock):
    buf = b""
    while b"\n\n" not in buf:
        if len(buf) > MAX_PRELUDE:
            return None
        try:
            pronto, _, _ = select.select([sock], [], [], TIMEOUT_PRELUDE)
        except (OSError, ValueError):
            return None
        if not pronto:
            return None
        try:
            blocco = sock.recv(min(1024, MAX_PRELUDE - len(buf)))
        except OSError:
            return None
        if not blocco:
            return None
        buf += blocco
    testo = buf.split(b"\n\n", 1)[0].decode("ascii", errors="replace")
    righe = testo.split("\n")
    if not righe or righe[0] != PREDA_DECODED:
        return None
    campi = {}
    for riga in righe[1:]:
        k, sep, v = riga.partition("=")
        if sep:
            campi[k.strip().lower()] = v.strip()
    return campi


def rispondi(sock, testo):
    try:
        sock.sendall(testo.encode() + b"\n")
    except OSError:
        pass


def attendi(sess):
    """Il primo arrivato resta appeso finche' l'altro non si fa vivo. Non e'
    lui ad accoppiarsi: se lo facesse, l'ultimo arrivato aprirebbe una seconda
    pipe sulla stessa coppia. Il suo unico compito e' aspettare, e non chiudere
    mai la socket: quando l'hub gli apre la pipe, la proprieta' e' del relay."""
    scadenza = time.time() + MAX_ATTESA_COMPA
    while time.time() < scadenza and not sess.dato:
        if sess.sock.fileno() < 0:
            return False
        time.sleep(0.25)
    return sess.dato


def prendi(sock, stanza_chiave, nick, pub, ip):
    """Accetta la sessione in una stanza, o la rifiuta spiegando perche'.
    Ritorna la Sessione, cosi' il chiamante sa se la socket e' sua o del relay."""
    if not RE_ROOM.match(stanza_chiave):
        conta("rifiuti")
        nota_rifiuto(ip)
        rispondi(sock, "ERR stanza non valida")
        return None
    if not RE_NICK.match(nick):
        conta("rifiuti")
        nota_rifiuto(ip)
        rispondi(sock, "ERR nickname non valido (a-z0-9._- 2-32 caratteri)")
        return None
    if not RE_PUB.match(pub):
        conta("rifiuti")
        nota_rifiuto(ip)
        rispondi(sock, "ERR chiave pubblica non valida")
        return None

    with LOCK_STANZE:
        stanza = STANZE.get(stanza_chiave)
        if stanza is None:
            if len(STANZE) >= MAX_STANZE:
                conta("rifiuti")
                nota_rifiuto(ip)
                rispondi(sock, "ERR server pieno, riprova piu' tardi")
                return None
            stanza = {"attesa": [], "coppie": [], "viva": time.time()}
            STANZE[stanza_chiave] = stanza
        stanza["viva"] = time.time()

    sess = Sessione(sock, ip, stanza_chiave, nick, pub)
    compagno, motivo = accoppia(sess, stanza)

    if motivo is not None:
        conta("rifiuti")
        nota_rifiuto(ip)
        rispondi(sock, "ERR " + motivo)
        return sess

    if compagno is not None:
        conta("coppie")
        # "accoppiato" e non un contatore: il client deve poter distinguere
        # "sono in coda" da "c'e' l'altro peer", e non deve indovinarlo dal
        # silenzio. Le due righe partono prima che la pipe si apra, quindi il
        # client legge la sua riga e solo poi comincia lo scambio di chiavi.
        rispondi(sess.sock, "OK accoppiato")
        rispondi(compagno.sock, "OK accoppiato")
        log("coppia aperta")
        # da qui in poi le due socket sono del thread di inoltro
        sess.dato = True
        compagno.dato = True
        threading.Thread(target=servi, args=(sess, compagno), daemon=True).start()
        return sess

    rispondi(sock, "OK attesa")
    attendi(sess)
    return sess


def gestisci(sock, ip):
    conta("connessioni")
    keepalive(sock)
    sess = None
    try:
        if bannato(ip):
            conta("bannati")
            rispondi(sock, "ERR IP temporaneamente bloccato")
            return
        campi = leggi_preludo(sock)
        if campi is None:
            nota_rifiuto(ip)
            return
        if campi.get("ping") == "1":
            # endpoint di stato: stessa porta, nessun altro server da gestire
            corpo = json.dumps(stato_globale())
            try:
                sock.sendall(corpo.encode() + b"\n")
            except OSError:
                pass
            return
        sess = prendi(
            sock,
            (campi.get("stanza") or "").lower(),
            (campi.get("nick") or "").lower(),
            campi.get("pub") or "",
            ip,
        )
    except Exception as errore:                # una connessione rotta non
        log("errore interno gestito: %r", errore)   # deve mai portare giu' il server
        try:
            rispondi(sock, "ERR errore interno")
        except OSError:
            pass
    finally:
        # Se il relay ha preso la socket, NON la chiudiamo: chiudere qui
        # ucciderebbe la coppia un secondo dopo averla aperta.
        if sess is None or not sess.dato:
            try:
                sock.close()
            except OSError:
                pass


def keepalive(sock, idle=60, intervallo=15, tentativi=4):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for nome, valore in (
            ("TCP_KEEPIDLE", idle),
            ("TCP_KEEPINTVL", intervallo),
            ("TCP_KEEPCNT", tentativi),
        ):
            opzione = getattr(socket, nome, None)
            if opzione is not None:
                sock.setsockopt(socket.IPPROTO_TCP, opzione, valore)
    except OSError:
        pass


def pulizia_loop():
    while True:
        time.sleep(60)
        adesso = time.time()
        with LOCK_STANZE:
            for chiave, stanza in list(STANZE.items()):
                for s in list(stanza["attesa"]) + list(stanza["coppie"]):
                    if adesso - s.entrata > MAX_SESSIONE_MUTA:
                        rimuovi(s)
                        chiudi(s)
                if not stanza["attesa"] and not stanza["coppie"]:
                    if adesso - stanza["viva"] > MAX_STANZA_VUOTA:
                        STANZE.pop(chiave, None)
        with LOCK_BAN:
            for ip, scadenza in list(BAN.items()):
                if not ip.startswith("_t_") and scadenza < adesso - DURATA_BAN:
                    del BAN[ip]


# --- TLS --------------------------------------------------------------------

def genera_tls(direzione, host, giorni=3650):
    """Certificato auto-firmato. Il client non si fida di nessuna autorita':
    pinniamo l'impronta SHA-256 del certificato, quindi puo' essere anche
    auto-firmato. Nessuna terza parte, niente DNS, niente Let's Encrypt."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    try:
        os.makedirs(direzione, mode=0o700, exist_ok=True)
    except PermissionError:
        raise SystemExit(
            "Non posso scrivere in %s.\n"
            "L'hub mette qui certificato e chiave, che devono restare leggibili\n"
            "solo dall'utente che gira il server. Due strade:\n"
            "  - l'hub gira come root o come utente dedicato: rilancia con sudo\n"
            "  - oppure passagli una cartella tua:  --tls-dir ~/.veil2/tls\n"
            "Se giri come servizio systemd, la via giusta e' la seconda con\n"
            "ReadWritePaths= nell'unit, cosi' l'hub non ha bisogno di root."
            % direzione
        )
    cert_path = os.path.join(direzione, "cert.pem")
    key_path = os.path.join(direzione, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    chiave = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "veil2-hub"),
    ])
    adesso = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(chiave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(adesso - timedelta(minutes=5))
        .not_valid_after(adesso + timedelta(days=giorni))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(chiave, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(chiave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)
    return cert_path, key_path


def impronta_cert(path):
    with open(path, "rb") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read().decode())
    grezza = hashlib.sha256(der).hexdigest()
    return grezza, ":".join(grezza[i:i + 2] for i in range(0, len(grezza), 2))


def contesto_server(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def main():
    ap = argparse.ArgumentParser(description="Relay rendezvous e inoltro per Veil 2")
    ap.add_argument("--porta", type=int, default=443, help="porta TCP (default 443)")
    ap.add_argument("--host", default="0.0.0.0", help="indirizzo di ascolto")
    ap.add_argument("--tls", default="on", choices=["on", "off"],
                    help="on: l'hub termina TLS; off: sta dietro un terminatore TLS")
    ap.add_argument("--no-tls", dest="no_tls", action="store_true",
                    help="scorciatoia per --tls off")
    ap.add_argument("--cert", help="certificato PEM")
    ap.add_argument("--chiave", help="chiave privata PEM")
    ap.add_argument("--tls-dir", default="/etc/veil2/tls", help="cartella di cert e chiave")
    ap.add_argument("--genera-tls", metavar="DIR", nargs="?", const="/etc/veil2/tls",
                    help="genera il certificato, stampa l'impronta e esce")
    ap.add_argument("--hostname", default="veil2.example.org",
                    help="nome da mettere nel certificato")
    ap.add_argument("--giorni", type=int, default=3650, help="validita' del certificato")
    args = ap.parse_args()
    if args.no_tls:
        args.tls = "off"

    if args.genera_tls is not None:
        cert, key = genera_tls(args.genera_tls, args.hostname, args.giorni)
        grezza, leggibile = impronta_cert(cert)
        print("certificato: %s" % cert)
        print("chiave:      %s" % key)
        print("impronta SHA-256: %s" % leggibile)
        print()
        print("Sul PC, al primo avvio:  veil2.py --pin %s" % grezza)
        return

    ctx = None
    if args.tls == "on":
        cert = args.cert or os.path.join(args.tls_dir, "cert.pem")
        key = args.chiave or os.path.join(args.tls_dir, "key.pem")
        if not (os.path.exists(cert) and os.path.exists(key)):
            log("certificato assente in %s: ne genero uno", args.tls_dir)
            cert, key = genera_tls(args.tls_dir, args.hostname, args.giorni)
            log("impronta del certificato: %s", impronta_cert(cert)[1])
        ctx = contesto_server(cert, key)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.porta))
    server.listen(128)
    log("hub in ascolto su %s:%d (TLS %s)", args.host, args.porta, args.tls)
    log("stato solo in RAM: al riavvio non resta traccia di nessuno")

    threading.Thread(target=pulizia_loop, daemon=True).start()

    def spegni(_, __):
        log("arresto")
        os._exit(0)

    signal.signal(signal.SIGTERM, spegni)
    signal.signal(signal.SIGINT, spegni)

    while True:
        try:
            grezzo, indirizzo = server.accept()
        except OSError:
            continue
        try:
            grezzo.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if ctx is not None:
            try:
                grezzo.settimeout(TIMEOUT_PRELUDE)
                sock = ctx.wrap_socket(grezzo, server_side=True)
                sock.settimeout(None)
            except (ssl.SSLError, OSError):
                try:
                    grezzo.close()
                except OSError:
                    pass
                continue
        else:
            sock = grezzo
        threading.Thread(target=gestisci, args=(sock, indirizzo[0]), daemon=True).start()


if __name__ == "__main__":
    main()
