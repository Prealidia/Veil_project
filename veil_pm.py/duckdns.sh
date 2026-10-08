#!/bin/sh
# duckdns.sh - dice a DuckDNS qual e' il nostro IP pubblico.
#
# Va tenuto sul server Debian che fa da hub, NON sui PC client: il dominio
# deve puntare all'hub, e l'hub e' l'unica macchina con un IP pubblico.
#
# Con &ip= DuckDNS prende da solo l'IP di chi fa la richiesta: non serve
# scoprire l'IP pubblico, quindi funziona anche dietro NAT.
#
# Uso:
#   sudo install -m 0755 duckdns.sh /usr/local/sbin/duckdns.sh
#   sudo install -m 0600 duckdns.conf.example /etc/veil2/duckdns.conf  # poi edita
#   sudo systemctl enable --now veil2-duckdns.timer
#
# Il token NON va messo qui dentro: sta in /etc/veil2/duckdns.conf, che puo'
# restare leggibile solo da root.

set -u

CONFIG=${DUCKDNS_CONFIG:-/etc/veil2/duckdns.conf}
LOCK=${DUCKDNS_LOCK:-/run/lock/veil2-duckdns.lock}
URL="https://www.duckdns.org/update"

if [ ! -r "$CONFIG" ]; then
    echo "duckdns: non leggo $CONFIG" >&2
    exit 1
fi

# shellcheck source=/dev/null
. "$CONFIG"

if [ -z "${DUCKDNS_TOKEN:-}" ] || [ -z "${DUCKDNS_DOMAIN:-}" ]; then
    echo "duckdns: manca DUCKDNS_TOKEN o DUCKDNS_DOMAIN in $CONFIG" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "duckdns: curl non e' installato (sudo apt install curl)" >&2
    exit 1
fi

# Dopo aver letto la config: il percorso del file "ultimo IP" puo' stare
# li'. Se lo mettessimo qui fuori, la config non farebbe in tempo a
# cambiarlo e ogni giro scriverebbe il log anche con IP immutato.
VEDUTO=${DUCKDNS_VEDUTO:-/var/lib/veil2/duckdns.ultimo}
mkdir -p "$(dirname "$VEDUTO")" 2>/dev/null || true

# Due aggiornamenti sovrapposti non servono a nulla e DuckDNS risponde con
# un errore: meglio aspettare che il primo finisca.
if [ -e "$LOCK" ]; then
    exit 0
fi
: > "$LOCK" 2>/dev/null || true
trap 'rm -f "$LOCK"' EXIT INT TERM

risposta=$(curl --silent --show-error --fail --max-time 20 \
    --retry 2 --retry-delay 3 \
    --user "$DUCKDNS_TOKEN:" \
    "$URL?domains=${DUCKDNS_DOMAIN}&ip=&verbose=true" 2>&1)
codice=$?
if [ $codice -ne 0 ]; then
    echo "duckdns: curl ha fallito (codice $codice): ${risposta:-nessuna risposta}" >&2
    exit $codice
fi

# DuckDNS risponde "OK" seguito dall'IP, oppure "KO" seguito dal motivo.
esito=$(printf '%s' "$risposta" | head -n1 | tr -d '\r')
dettaglio=$(printf '%s' "$risposta" | sed -n '2p' | tr -d '\r')

if [ "$esito" = "OK" ]; then
    if [ -f "$VEDUTO" ] && [ "$(cat "$VEDUTO" 2>/dev/null)" = "$dettaglio" ]; then
        # IP immutato: non rumoriamo il log a ogni giro
        exit 0
    fi
    echo "duckdns: ${DUCKDNS_DOMAIN}.duckdns.org -> ${dettaglio:-IP ignoto}"
    if [ -d "$(dirname "$VEDUTO")" ]; then
        printf '%s\n' "$dettaglio" > "$VEDUTO" 2>/dev/null || true
    fi
    exit 0
fi

echo "duckdns: risposta '${esito:-vuota}' ${dettaglio:-}" >&2
exit 1
