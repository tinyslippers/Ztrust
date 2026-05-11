import subprocess
import time
import sys
import os

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def check_status():
    os.system('clear')
    print(f"{BOLD}📡  MONITEUR DE SÉCURITÉ (Crash-Proof){RESET}")
    print("="*45)

    while True:
        try:
            # Query OVS status, redirect stderr to suppress noise
            cmd = "sudo ovs-vsctl show 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            
            if "is_connected: true" in output:
                sys.stdout.write(f"\rStatus: {GREEN}✅ CONTROLEUR EN LIGNE (SECURE){RESET}       ")
                sys.stdout.flush()
            else:
                sys.stdout.write(f"\rStatus: {RED}❌ CONTROLEUR HS / DÉCONNECTÉ{RESET}        ")
                sys.stdout.flush()
                
        except Exception as e:
            # On error (e.g. CPU spike during ping), stay alive and show a warning indicator.
            sys.stdout.write(f"\rStatus: {YELLOW}⚠️  Lecture en cours...{RESET}              ")
            sys.stdout.flush()

        time.sleep(0.5)

if __name__ == "__main__":
    try:
        check_status()
    except KeyboardInterrupt:
        print("\nArrêt manuel.")
    except Exception as e:
        print(f"\nERREUR FATALE : {e}")
        # Keep the window open even on a total crash
        input("Appuie sur Entrée pour quitter...")
