#!/bin/sh

# Auteur   KMS - Martin Dubois, ing.
# Produit  _DocDev
# Fichier  Scripts/UbuntuDev.sh

echo Executing  Scripts/UbuntuDev.sh

# ===== Execution ===========================================================

sudo apt-get install git
sudo apt-get install git-gui
sudo apt-get install g++
sudo apt-get install make
sudo apt-get install xutils-dev

sudo apt update
sudo apt install software-properties-common apt-transport-https wget

wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -

sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main"

sudo apt install code

# ===== Fin =================================================================

echo OK
