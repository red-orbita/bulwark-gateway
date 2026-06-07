#!/usr/bin/env bash
# Expone un servicio local a internet usando cloudflared (Cloudflare Tunnel)
#
# Uso:
#   ./scripts/expose.sh                  # Expone https://admin.sentinel-gateway.local/
#   ./scripts/expose.sh 8080             # Expone localhost:8080
#   ./scripts/expose.sh https://mi-url/  # Expone una URL personalizada

set -euo pipefail

DEFAULT_URL="https://admin.sentinel-gateway.local/"
TARGET="${1:-$DEFAULT_URL}"

# Verificar que cloudflared está instalado
if ! command -v cloudflared &> /dev/null; then
    echo "cloudflared no está instalado."
    echo ""
    echo "Instálalo con uno de estos métodos:"
    echo ""
    echo "  # Debian/Ubuntu"
    echo "  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg > /dev/null"
    echo "  echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list"
    echo "  sudo apt update && sudo apt install cloudflared"
    echo ""
    echo "  # Arch"
    echo "  yay -S cloudflared"
    echo ""
    echo "  # Con binario directo"
    echo "  curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared"
    echo "  chmod +x /usr/local/bin/cloudflared"
    exit 1
fi

# Determinar si es un puerto o una URL
EXTRA_FLAGS=()
if [[ "$TARGET" =~ ^[0-9]+$ ]]; then
    # Es un puerto numérico
    URL="http://localhost:${TARGET}"
elif [[ "$TARGET" =~ ^https?:// ]]; then
    # Es una URL, extraer el hostname para el header Host
    HOSTNAME=$(echo "$TARGET" | sed -E 's|https?://([^/:]+).*|\1|')
    URL="$TARGET"
    EXTRA_FLAGS=(--no-tls-verify --http-host-header "$HOSTNAME")
else
    URL="$TARGET"
fi

echo "Exponiendo ${URL} a internet..."
echo "Pulsa Ctrl+C para detener el túnel."
echo ""

cloudflared tunnel --url "$URL" "${EXTRA_FLAGS[@]}"
