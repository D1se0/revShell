#!/bin/bash

# Asegurarse de que el script está siendo ejecutado como root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecute este script como root"
  exit 1
fi

# Instalación de las librerías necesarias para el script Python
echo "Instalando librerías necesarias..."

apt-get update

# Lista de paquetes necesarios
packages=(
  "php"
  "powershell"
  "python3"
  "python3-pip"
  "ruby"
  "socat"
  "sqlite3"
  "nodejs"
  "npm"
  "golang-go"
  "vlang"
  "gawk"
  "lua5.1"
  "dart"
  "crystal"
)

# Instalar cada paquete
for package in "${packages[@]}"; do
  apt-get install -y "$package"
done

# Instalar socat si no está disponible
if ! command -v socat &> /dev/null; then
  apt-get install -y socat
fi

# Copiar el script Python a /usr/bin/ sin la extensión .py
echo "Copiando el script Python a /usr/bin/..."
cp ./revShell.py /usr/bin/revShell
chmod +x /usr/bin/revShell

echo "Instalación completada. Puedes ejecutar el script utilizando 'revShell' desde cualquier zona de la terminal."

