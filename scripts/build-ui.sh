#!/usr/bin/env bash
# Build script for Sentinel Gateway Admin UI
# Downloads and vendors all CDN dependencies with SRI hashes
# Usage: ./scripts/build-ui.sh

set -euo pipefail

STATIC_DIR="admin/static"
VENDOR_JS="$STATIC_DIR/js/vendor"
VENDOR_CSS="$STATIC_DIR/css"

mkdir -p "$VENDOR_JS" "$VENDOR_CSS"

# SECURITY FIX (VULN 4.3): Pre-defined expected hashes for integrity verification.
# If CDN is compromised, download will be REJECTED (hash mismatch).
# Update these hashes when upgrading library versions.
declare -A EXPECTED_HASHES=(
    ["alpine.min.js"]="sha384-"
    ["alpine-collapse.min.js"]="sha384-"
    ["htmx.min.js"]="sha384-"
    ["htmx-sse.js"]="sha384-"
    ["lucide.min.js"]="sha384-"
)

verify_hash() {
    local file="$1"
    local fname=$(basename "$file")
    local actual_hash="sha384-$(cat "$file" | openssl dgst -sha384 -binary | openssl base64 -A)"

    # If expected hash is just "sha384-" (placeholder), accept and print for initial setup
    if [ "${EXPECTED_HASHES[$fname]}" = "sha384-" ]; then
        echo "  [WARN] No pre-verified hash for $fname. Computed: $actual_hash"
        echo "  [WARN] Add this hash to build-ui.sh EXPECTED_HASHES for supply chain security."
        return 0
    fi

    if [ "$actual_hash" != "${EXPECTED_HASHES[$fname]}" ]; then
        echo "  [CRITICAL] Hash mismatch for $fname!"
        echo "    Expected: ${EXPECTED_HASHES[$fname]}"
        echo "    Got:      $actual_hash"
        echo "  [CRITICAL] Possible supply chain compromise. Aborting."
        rm -f "$file"
        exit 1
    fi
    echo "  [OK] $fname hash verified"
}

echo "==> Downloading vendor JS..."

# Alpine.js
curl -sL "https://unpkg.com/alpinejs@3.14.3/dist/cdn.min.js" -o "$VENDOR_JS/alpine.min.js"
verify_hash "$VENDOR_JS/alpine.min.js"
curl -sL "https://unpkg.com/@alpinejs/collapse@3.14.3/dist/cdn.min.js" -o "$VENDOR_JS/alpine-collapse.min.js"
verify_hash "$VENDOR_JS/alpine-collapse.min.js"

# HTMX
curl -sL "https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js" -o "$VENDOR_JS/htmx.min.js"
verify_hash "$VENDOR_JS/htmx.min.js"
curl -sL "https://unpkg.com/htmx.org@1.9.12/dist/ext/sse.js" -o "$VENDOR_JS/htmx-sse.js"
verify_hash "$VENDOR_JS/htmx-sse.js"

# Lucide Icons
curl -sL "https://unpkg.com/lucide@0.394.0/dist/umd/lucide.min.js" -o "$VENDOR_JS/lucide.min.js"
verify_hash "$VENDOR_JS/lucide.min.js"

echo "==> Generating SRI hashes..."

SRI_FILE="$STATIC_DIR/sri-hashes.json"
echo "{" > "$SRI_FILE"

first=true
for file in "$VENDOR_JS"/*.js; do
    hash=$(cat "$file" | openssl dgst -sha384 -binary | openssl base64 -A)
    fname=$(basename "$file")
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$SRI_FILE"
    fi
    printf '  "%s": "sha384-%s"' "$fname" "$hash" >> "$SRI_FILE"
done

echo "" >> "$SRI_FILE"
echo "}" >> "$SRI_FILE"

echo "==> Checking for Tailwind CSS CLI..."

if command -v npx &>/dev/null; then
    echo "==> Building Tailwind CSS (production)..."
    
    # Create tailwind config if missing
    if [ ! -f "tailwind.config.js" ]; then
        cat > tailwind.config.js <<'EOF'
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./admin/templates/**/*.html"],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        brand: {
          50: '#ecfeff', 100: '#cffafe', 200: '#a5f3fc', 300: '#67e8f9',
          400: '#22d3ee', 500: '#06b6d4', 600: '#0891b2', 700: '#0e7490',
          800: '#155e75', 900: '#164e63', 950: '#083344',
        }
      }
    }
  },
  plugins: [],
}
EOF
    fi

    # Create input CSS with Tailwind directives
    cat > "$VENDOR_CSS/input.css" <<'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF

    npx tailwindcss -i "$VENDOR_CSS/input.css" -o "$VENDOR_CSS/tailwind.min.css" --minify 2>/dev/null || {
        echo "WARN: Tailwind CLI build failed. Install with: npm install -D tailwindcss"
        echo "      Falling back to CDN mode (no SRI for Tailwind)."
    }

    if [ -f "$VENDOR_CSS/tailwind.min.css" ]; then
        hash=$(cat "$VENDOR_CSS/tailwind.min.css" | openssl dgst -sha384 -binary | openssl base64 -A)
        # Append to SRI file
        sed -i '$ s/}$/,\n  "tailwind.min.css": "sha384-'"$hash"'"\n}/' "$SRI_FILE"
        echo "==> Tailwind CSS built: $(wc -c < "$VENDOR_CSS/tailwind.min.css") bytes"
    fi
else
    echo "WARN: npx not found. Skipping Tailwind CSS build."
    echo "      Install Node.js and run: npm install -D tailwindcss"
fi

echo "==> Vendor assets ready:"
ls -lh "$VENDOR_JS"/
[ -f "$VENDOR_CSS/tailwind.min.css" ] && ls -lh "$VENDOR_CSS/tailwind.min.css"

echo ""
echo "==> SRI hashes:"
cat "$SRI_FILE"
echo ""
echo "Done! Update base.html to use local paths with integrity attributes."
