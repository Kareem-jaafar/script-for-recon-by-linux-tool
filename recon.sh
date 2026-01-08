#!/bin/bash

# --- Configuration ---
OUTPUT_DIR="Recon_$(date +%F_%H-%M-%S)"

WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

UAGENTS=(
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
)

pick_ua() {
    echo "${UAGENTS[$RANDOM % ${#UAGENTS[@]}]}"
}

check_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo -e "\n[ERROR] Required tool '$1' is missing. Install it first."
        exit 1
    }
}

# --- Tool Checks ---
check_tool "nmap"
check_tool "subfinder"
check_tool "assetfinder"
check_tool "amass"
check_tool "httpx"
check_tool "ffuf"
check_tool "waybackurls"
check_tool "whatweb"

scan_domain() {
    local domain=$1
    TARGET="$OUTPUT_DIR/$domain"
    mkdir -p "$TARGET"
    REPORT_SUMMARY="$TARGET/report_summary.txt"

    echo -e "\n=======================================================" >> "$REPORT_SUMMARY"
    echo -e "🚀 Starting Advanced Recon for: $domain" >> "$REPORT_SUMMARY"
    echo -e "=======================================================\n" >> "$REPORT_SUMMARY"

    echo -e "\n[INFO] Subdomain Enumeration..."
    subfinder -silent -all -d "$domain" -t 10 > "$TARGET/subs_raw.txt"
    assetfinder --subs-only "$domain" >> "$TARGET/subs_raw.txt"
    amass enum -passive -d "$domain" >> "$TARGET/subs_raw.txt"

    sort -u "$TARGET/subs_raw.txt" -o "$TARGET/01_subdomains.txt"
    rm -f "$TARGET/subs_raw.txt"

    # --- Live Check using httpx ---
    echo -e "\n[INFO] Checking live subdomains (httpx)..."
    cat "$TARGET/01_subdomains.txt" | httpx -silent -timeout 5 -threads 50 -o "$TARGET/02_alive_subdomains.txt"

    echo "--- Live Subdomains ---" >> "$REPORT_SUMMARY"
    cat "$TARGET/02_alive_subdomains.txt" >> "$REPORT_SUMMARY"

    # --- Port Scan ---
    echo -e "\n[INFO] Running Nmap..."
    nmap -sS -Pn -T2 -p- "$domain" --scan-delay 100ms --max-rate 50 -oN "$TARGET/03_ports.txt"

    grep "open" "$TARGET/03_ports.txt" | grep -v "filtered" >> "$REPORT_SUMMARY"

    # --- Directory Bruteforce ---
    echo -e "\n[INFO] Running FFUF..."
    if [ -f "$WORDLIST" ]; then
        cat "$TARGET/02_alive_subdomains.txt" | while read url; do
            ua=$(pick_ua)
            host=$(echo "$url" | sed 's~http[s]*://~~g')
            out="$TARGET/ffuf_${host//\//_}.csv"

            ffuf -w "$WORDLIST" -u "$url/FUZZ" \
                 -H "User-Agent: $ua" \
                 -mc 200,204,301,302,307 \
                 -rate 40 -timeout 5 \
                 -of csv -o "$out" >/dev/null 2>&1

            if [ -f "$out" ]; then
                echo "Domain: $host" >> "$REPORT_SUMMARY"
                awk -F',' '{print $4 " (" $3 ") Size: " $5}' "$out" | grep -v 'url (status' >> "$REPORT_SUMMARY"
            fi
            sleep $((RANDOM % 2 + 1))
        done
    fi

    # --- Wayback URLs ---
    echo -e "\n[INFO] Wayback Collection..."
    ua=$(pick_ua)
    curl -A "$ua" -s "http://web.archive.org/cdx/search/coll?url=*.$domain/*&output=txt&fl=original" > "$TARGET/wayback_temp.txt"

    cat "$TARGET/wayback_temp.txt" | waybackurls > "$TARGET/04_urls_raw.txt"
    sort -u "$TARGET/04_urls_raw.txt" -o "$TARGET/04_all_endpoints.txt"
    grep '=' "$TARGET/04_all_endpoints.txt" > "$TARGET/05_endpoints_with_params.txt"

    # --- WhatWeb ---
    echo -e "\n[INFO] Technology Fingerprinting..."
    WHATWEB_FILE="$TARGET/06_technology_fingerprint.txt"
    whatweb "$domain" > "$WHATWEB_FILE"

    cat "$TARGET/02_alive_subdomains.txt" | while read url; do
        whatweb -a 1 "$url" >> "$WHATWEB_FILE"
    done

    echo -e "\n[SUCCESS] Scan for $domain completed."
}

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 example.com test.com"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

for d in "$@"; do
    scan_domain "$d" &
    sleep 2
done

wait

echo -e "\n✅ All scans finished. Results in: $OUTPUT_DIR"
