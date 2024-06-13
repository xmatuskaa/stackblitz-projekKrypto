#!/bin/bash

# Kontrola, zda je nainstalovaný Node.js
if ! command -v node &> /dev/null
then
    echo "Node.js není nainstalován. Nainstalujte ho a zkuste to znovu."
    exit 1
fi

# Kontrola, zda jsou nainstalované potřebné moduly
if ! [ -d "node_modules" ]; then
    echo "Instalace potřebných modulů..."
    npm install
fi

# Spuštění skriptu
node KryptoProjekt.js
