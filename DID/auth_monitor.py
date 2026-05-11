#!/usr/bin/env python3
"""Real-time monitor — DID authentication state of SDN switches."""
import json, os, sys, time

STATUS_FILE = '/tmp/sdn_auth_status.json'

R   = '\033[0m';  B   = '\033[1m'
RED = '\033[91m'; GRN = '\033[92m'; YLW = '\033[93m'
MAG = '\033[95m'; CYN = '\033[96m'
GRY = '\033[90m'; WHT = '\033[97m'


def fmt_dur(s):
    s = max(0, int(s))
    return f"{s//60}m{s%60:02d}s"


def token_col(remaining):
    if remaining <= 0:
        return f"{RED}{B}EXPIRE {R}"
    txt = fmt_dur(remaining).ljust(7)
    if remaining < 30:  return f"{RED}{txt}{R}"
    if remaining < 60:  return f"{YLW}{txt}{R}"
    return                     f"{GRN}{txt}{R}"


def idle_col(idle):
    txt = f"{int(idle)}s".ljust(6)
    if idle > 60:  return f"{RED}{txt}{R}"
    if idle > 30:  return f"{YLW}{txt}{R}"
    return                f"{GRN}{txt}{R}"


def render(status):
    now   = time.time()
    n_ok  = sum(1 for v in status.values() if v.get('state') == 'auth')
    n_wt  = sum(1 for v in status.values() if v.get('state') == 'connected')
    n_off = sum(1 for v in status.values() if v.get('state') == 'unknown')

    sys.stdout.write('\033[2J\033[H')

    W   = 68
    bar = f"{CYN}{B}│{R}"

    print(f"{CYN}{B}┌{'─'*W}┐{R}")
    print(f"{bar}{WHT}{B}{'SDN ZERO TRUST  ·  MONITORING AUTHENTIFICATION':^{W}}{R}{bar}")
    print(f"{bar}{GRY}{time.strftime('%Y-%m-%d  %H:%M:%S'):^{W}}{R}{bar}")
    print(f"{CYN}{B}├{'─'*W}┤{R}")

    # Build summary in two steps to avoid width issues caused by ANSI codes
    summ = (f"  {GRN}{B}Auth OK : {n_ok:<2}{R}   "
            f"{YLW}En attente : {n_wt:<2}{R}   "
            f"{RED}Hors ligne : {n_off:<2}{R}")
    print(f"{bar}{summ}{' '*18}{bar}")

    print(f"{CYN}{B}├────┬──────────┬─────────┬────────┬─────────────────────────┤{R}")
    print(f"{bar}{WHT}{B} ID {R}{bar}"
          f"{WHT}{B} ETAT     {R}{bar}"
          f"{WHT}{B} TOKEN   {R}{bar}"
          f"{WHT}{B} IDLE   {R}{bar}"
          f"{WHT}{B} DID                     {R}{bar}")
    print(f"{CYN}{B}├────┼──────────┼─────────┼────────┼─────────────────────────┤{R}")

    for i in range(1, 23):
        info  = status.get(str(i), {'state': 'unknown'})
        state = info.get('state', 'unknown')
        sid   = f"{MAG}{B}s{str(i):<2}{R}"

        if state == 'auth':
            remaining = info.get('expiry', now) - now
            idle      = now - info.get('last_seen', now)
            did_raw   = info.get('did', '')
            # Afficher la partie lisible : switch_X:abcd1234
            did_parts = did_raw.split(':')
            did_short = ':'.join(did_parts[2:]) if len(did_parts) >= 4 else did_raw
            did_short = did_short[:24].ljust(24)  # Show readable part: switch_X:abcd1234
            s_col  = f"{GRN} OK      {R}"
            tk_col = token_col(remaining)
            id_col = idle_col(idle)
            d_col  = f"{YLW}{did_short}{R}"
        elif state == 'connected':
            s_col  = f"{YLW} ATTENTE  {R}"
            tk_col = f"{GRY}  ---   {R}"
            id_col = f"{GRY}  ---  {R}"
            d_col  = f"{YLW}{'En attente auth...':<24}{R}"
        else:
            s_col  = f"{RED} OFFLINE  {R}"
            tk_col = f"{GRY}  ---   {R}"
            id_col = f"{GRY}  ---  {R}"
            d_col  = f"{GRY}{'Non connecte':<24}{R}"

        print(f"{bar} {sid} {bar}{s_col}{bar} {tk_col} {bar} {id_col}{bar} {d_col} {bar}")

    print(f"{CYN}{B}└────┴──────────┴─────────┴────────┴─────────────────────────┘{R}")
    print(f"\n{GRY}  Actualisation : 1s   |   Ctrl+C pour quitter{R}", flush=True)


def main():
    while True:
        try:
            if os.path.exists(STATUS_FILE):
                with open(STATUS_FILE) as f:
                    status = json.load(f)
                render(status)
            else:
                sys.stdout.write('\033[2J\033[H')
                print(f"\n  {YLW}{B}En attente du controleur Ryu...{R}")
                print(f"  {GRY}(fichier {STATUS_FILE} introuvable){R}\n", flush=True)
        except (json.JSONDecodeError, IOError, ValueError):
            pass
        time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
