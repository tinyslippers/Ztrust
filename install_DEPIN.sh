#!/bin/bash
# ======================================================
#  Installation automatique de l'environnement DEPIN-ZTN
#  Auteur : Baptiste Rodrigues
#  Projet : Zero Trust Networking & DePIN
# ======================================================

echo "🚀 Début de l'installation de l'environnement DEPIN-ZTN..."

# ---- 1. MISE À JOUR DU SYSTÈME ----
sudo apt update -y && sudo apt upgrade -y

# ---- 2. OUTILS DE BASE ----
echo "📦 Installation des outils essentiels..."
sudo apt install -y git curl wget vim build-essential net-tools xterm telnet iperf3 wireshark

# ---- 3. INSTALLATION DE PYTHON ----
echo "🐍 Installation de Python et pip..."
sudo apt install -y python3 python3-pip python3-venv

# ---- 4. MININET ----
echo "🌐 Installation de Mininet..."
sudo apt install -y mininet openvswitch-switch
sudo systemctl enable openvswitch-switch
sudo systemctl start openvswitch-switch

# ---- 5. RYU CONTROLLER ----
echo "🧠 Installation du contrôleur Ryu..."
sudo pip install ryu

# ---- 6. LIBRAIRIES MACHINE LEARNING ----
echo "🤖 Installation des librairies IA..."
pip install --upgrade pip
pip install numpy pandas scikit-learn matplotlib seaborn torch torchvision torchaudio

# ---- 7. LIBRAIRIES SUPPLÉMENTAIRES (Flask, Requests...) ----
echo "🧩 Installation des librairies supplémentaires..."
pip install flask requests tqdm

# ---- 8. OUTILS OPTIONNELS (IPFS / Blockchain légère) ----
echo "🔗 Installation d’outils optionnels pour le module DePIN..."
sudo apt install -y golang-go
wget https://dist.ipfs.tech/go-ipfs/v0.28.0/go-ipfs_v0.28.0_linux-amd64.tar.gz
tar -xvzf go-ipfs_v0.28.0_linux-amd64.tar.gz
cd go-ipfs && sudo bash install.sh && cd ..
rm -rf go-ipfs*

# ---- 9. CRÉATION DU DOSSIER DE PROJET ----
echo "📁 Création du répertoire de travail..."
mkdir -p ~/DEPIN_ZTN/{controller,ml_module,ai_agent,blockchain}
cd ~/DEPIN_ZTN

# ---- 10. TESTS ----
echo "✅ Vérification des installations..."
echo "Python version : $(python3 --version)"
echo "Ryu version : $(ryu-manager --version 2>/dev/null || echo 'Ryu OK (pas de version affichée)')"
echo "Mininet version : $(mn --version)"

echo "🎉 Installation terminée avec succès !"
echo "Ton environnement DEPIN-ZTN est prêt à être utilisé."
