import os
import time
import sys

# Utility script to authenticate the entire fleet at once
def mass_authenticate():
    print("--- 🚀 DÉMARRAGE DE LA FLOTTE IOT (22 Switchs) ---")
    print("Envoi des preuves cryptographiques au contrôleur...")
    
    for i in range(1, 23):
        switch_name = f"switch_{i}"
        
        # Call agent_auth.py for each switch
        # > /dev/null suppresses verbose output
        cmd = f"python3 agent_auth.py {switch_name} > /dev/null 2>&1"
        
        exit_code = os.system(cmd)
        
        if exit_code == 0:
            # Barre de chargement visuelle
            sys.stdout.write(f"\r📡 Authentification {switch_name} : [OK]")
            sys.stdout.flush()
        else:
            print(f"\n❌ Erreur sur {switch_name}")
            
        # Small delay to avoid flooding the controller (simulates network latency)
        time.sleep(0.05)
        
    print("\n\n✅ TOUS LES SWITCHS ONT ENVOYÉ LEUR PREUVE D'IDENTITÉ.")

if __name__ == "__main__":
    mass_authenticate()
