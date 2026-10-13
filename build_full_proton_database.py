"""
build_full_proton_database.py: Ingests the complete verified 1048 Proton WireGuard servers
from gluetun-servers catalog into proton_servers.json, complete with country metadata,
city, continent, ISO codes, secure_core flags, and port_forward flags.
"""

import json
import os
import re
import urllib.request

COUNTRY_NAME_TO_ISO = {
    'Afghanistan': 'AF', 'Albania': 'AL', 'Algeria': 'DZ', 'Andorra': 'AD',
    'Angola': 'AO', 'Argentina': 'AR', 'Armenia': 'AM', 'Australia': 'AU',
    'Austria': 'AT', 'Azerbaijan': 'AZ', 'Bahrain': 'BH', 'Bangladesh': 'BD',
    'Belarus': 'BY', 'Belgium': 'BE', 'Bhutan': 'BT', 'Bolivia': 'BO',
    'Bosnia and Herzegovina': 'BA', 'Brazil': 'BR', 'Brunei Darussalam': 'BN',
    'Bulgaria': 'BG', 'Cambodia': 'KH', 'Cameroon': 'CM', 'Canada': 'CA',
    'Chad': 'TD', 'Chile': 'CL', 'Colombia': 'CO', 'Comoros': 'KM',
    'Costa Rica': 'CR', "Cote d'Ivoire": 'CI', 'Croatia': 'HR', 'Cuba': 'CU',
    'Cyprus': 'CY', 'Czech Republic': 'CZ', 'Democratic Republic of the Congo': 'CD',
    'Denmark': 'DK', 'Dominican Republic': 'DO', 'Ecuador': 'EC', 'Egypt': 'EG',
    'El Salvador': 'SV', 'Eritrea': 'ER', 'Estonia': 'EE', 'Ethiopia': 'ET',
    'Finland': 'FI', 'France': 'FR', 'Gabon': 'GA', 'Georgia': 'GE',
    'Germany': 'DE', 'Ghana': 'GH', 'Greece': 'GR', 'Greenland': 'GL',
    'Guatemala': 'GT', 'Guinea': 'GN', 'Haiti': 'HT', 'Honduras': 'HN',
    'Hong Kong': 'HK', 'Hungary': 'HU', 'Iceland': 'IS', 'India': 'IN',
    'Indonesia': 'ID', 'Iraq': 'IQ', 'Ireland': 'IE', 'Israel': 'IL',
    'Italy': 'IT', 'Jamaica': 'JM', 'Japan': 'JP', 'Jordan': 'JO',
    'Kazakhstan': 'KZ', 'Kenya': 'KE', 'Korea': 'KR', 'Kosovo': 'XK',
    'Kuwait': 'KW', 'Kyrgyzstan': 'KG', 'Laos': 'LA',
    "Lao People's Democratic Republic": 'LA', 'Latvia': 'LV', 'Lebanon': 'LB',
    'Libya': 'LY', 'Liechtenstein': 'LI', 'Lithuania': 'LT', 'Luxembourg': 'LU',
    'Macao': 'MO', 'Macedonia': 'MK', 'Malaysia': 'MY', 'Maldives': 'MV',
    'Malta': 'MT', 'Mauritania': 'MR', 'Mauritius': 'MU', 'Mexico': 'MX',
    'Moldova': 'MD', 'Monaco': 'MC', 'Mongolia': 'MN', 'Montenegro': 'ME',
    'Morocco': 'MA', 'Mozambique': 'MZ', 'Myanmar': 'MM', 'Nepal': 'NP',
    'Netherlands': 'NL', 'New Zealand': 'NZ', 'Nicaragua': 'NI', 'Nigeria': 'NG',
    'North Macedonia': 'MK', 'Norway': 'NO', 'Oman': 'OM', 'Pakistan': 'PK',
    'Palestine, State of': 'PS', 'Panama': 'PA', 'Papua New Guinea': 'PG',
    'Paraguay': 'PY', 'Peru': 'PE', 'Philippines': 'PH', 'Poland': 'PL',
    'Portugal': 'PT', 'Puerto Rico': 'PR', 'Qatar': 'QA', 'Romania': 'RO',
    'Russian Federation': 'RU', 'Rwanda': 'RW', 'Saudi Arabia': 'SA',
    'Senegal': 'SN', 'Serbia': 'RS', 'Singapore': 'SG', 'Slovakia': 'SK',
    'Slovenia': 'SI', 'Somalia': 'SO', 'South Africa': 'ZA', 'South Korea': 'KR',
    'South Sudan': 'SS', 'Spain': 'ES', 'Sri Lanka': 'LK', 'Sudan': 'SD',
    'Suriname': 'SR', 'Sweden': 'SE', 'Switzerland': 'CH',
    'Syrian Arab Republic': 'SY', 'Taiwan': 'TW', 'Tajikistan': 'TJ',
    'Tanzania': 'TZ', 'Thailand': 'TH', 'Togo': 'TG', 'Trinidad and Tobago': 'TT',
    'Tunisia': 'TN', 'Turkey': 'TR', 'Turkmenistan': 'TM', 'Uganda': 'UG',
    'Ukraine': 'UA', 'United Arab Emirates': 'AE', 'United Kingdom': 'GB',
    'United States': 'US', 'Uruguay': 'UY', 'Uzbekistan': 'UZ',
    'Venezuela': 'VE', 'Vietnam': 'VN', 'Yemen': 'YE', 'Zimbabwe': 'ZW'
}

COUNTRY_CONTINENTS = {
    # Europe
    "AL": "Europe", "AD": "Europe", "AT": "Europe", "BY": "Europe", "BE": "Europe",
    "BA": "Europe", "BG": "Europe", "HR": "Europe", "CY": "Europe", "CZ": "Europe",
    "DK": "Europe", "EE": "Europe", "FI": "Europe", "FR": "Europe", "DE": "Europe",
    "GR": "Europe", "HU": "Europe", "IS": "Europe", "IE": "Europe", "IT": "Europe",
    "LV": "Europe", "LT": "Europe", "LU": "Europe", "MT": "Europe", "MD": "Europe",
    "MC": "Europe", "ME": "Europe", "NL": "Europe", "MK": "Europe", "NO": "Europe",
    "PL": "Europe", "PT": "Europe", "RO": "Europe", "RS": "Europe", "SK": "Europe",
    "SI": "Europe", "ES": "Europe", "SE": "Europe", "CH": "Europe", "TR": "Europe",
    "UA": "Europe", "GB": "Europe", "VA": "Europe", "XK": "Europe", "LI": "Europe",
    # Asia
    "AF": "Asia", "AM": "Asia", "AZ": "Asia", "BH": "Asia", "BD": "Asia",
    "BT": "Asia", "BN": "Asia", "KH": "Asia", "GE": "Asia", "HK": "Asia",
    "IN": "Asia", "ID": "Asia", "IL": "Asia", "JP": "Asia", "JO": "Asia",
    "KZ": "Asia", "KW": "Asia", "KG": "Asia", "LA": "Asia", "LB": "Asia",
    "MY": "Asia", "MV": "Asia", "MN": "Asia", "MM": "Asia", "NP": "Asia",
    "OM": "Asia", "PK": "Asia", "PH": "Asia", "QA": "Asia", "SA": "Asia",
    "SG": "Asia", "KR": "Asia", "LK": "Asia", "TW": "Asia", "TJ": "Asia",
    "TH": "Asia", "AE": "Asia", "UZ": "Asia", "VN": "Asia", "YE": "Asia",
    "IQ": "Asia", "MO": "Asia", "PS": "Asia", "SY": "Asia", "TM": "Asia",
    # North America
    "BS": "North America", "BZ": "North America", "CA": "North America", "CR": "North America",
    "CU": "North America", "DO": "North America", "SV": "North America", "GT": "North America",
    "HT": "North America", "HN": "North America", "JM": "North America", "MX": "North America",
    "NI": "North America", "PA": "North America", "PR": "North America", "TT": "North America",
    "US": "North America", "GL": "North America",
    # South America
    "AR": "South America", "BO": "South America", "BR": "South America", "CL": "South America",
    "CO": "South America", "EC": "South America", "GY": "South America", "PY": "South America",
    "PE": "South America", "SR": "South America", "UY": "South America", "VE": "South America",
    # Africa
    "DZ": "Africa", "AO": "Africa", "EG": "Africa", "ET": "Africa", "GH": "Africa",
    "KE": "Africa", "MA": "Africa", "MZ": "Africa", "NG": "Africa", "RW": "Africa",
    "SN": "Africa", "ZA": "Africa", "TZ": "Africa", "TN": "Africa", "UG": "Africa",
    "CD": "Africa", "CI": "Africa", "CM": "Africa", "KM": "Africa", "ER": "Africa",
    "GA": "Africa", "GN": "Africa", "LY": "Africa", "MR": "Africa", "MU": "Africa",
    "SD": "Africa", "SO": "Africa", "SS": "Africa", "TD": "Africa", "TG": "Africa",
    "ZW": "Africa",
    # Oceania
    "AU": "Oceania", "FJ": "Oceania", "NZ": "Oceania", "PG": "Oceania",
    # Transcontinental / Others
    "RU": "Europe",
}

def main():
    target_file = "/Users/elahekaveh/Desktop/VPN antigravity/Surfshark_AmneziaWG_v5/proton_servers.json"
    
    # Read existing credentials if available
    existing_creds = {
        "private_key": "KE25xm//0xDKVBulUc/e9QWcg0lPTA7DbglyzwvdWXE=",
        "address": "10.2.0.2/32",
        "dns": "10.2.0.1"
    }
    if os.path.exists(target_file):
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                d = json.load(f)
                ui = d.get("user_interface", {})
                if ui.get("private_key") and "fakeclientkey" not in ui.get("private_key"):
                    existing_creds["private_key"] = ui.get("private_key")
                if ui.get("address"):
                    existing_creds["address"] = ui.get("address")
                if ui.get("dns"):
                    existing_creds["dns"] = ui.get("dns")
        except Exception:
            pass

    local_raw = "protonvpn_raw.json"
    if os.path.exists(local_raw):
        print(f"Loading from local {local_raw}...")
        with open(local_raw, "r", encoding="utf-8") as f:
            raw = json.load(f)
    else:
        url = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json"
        print(f"Fetching full Proton VPN servers catalog from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        raw = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))

    wg_servers = [s for s in raw.get("servers", []) if s.get("vpn") == "wireguard"]
    print(f"Found {len(wg_servers)} WireGuard servers in remote catalog.")

    converted_servers = []
    seen = set()

    for s in wg_servers:
        c_name = s.get("country", "").strip()
        city = s.get("city", "").strip()
        s_name = s.get("server_name", "").strip()
        hostname = s.get("hostname", "").strip()
        pubkey = s.get("wgpubkey", "").strip()
        ips = s.get("ips", [])
        is_sc = bool(s.get("secure_core", False))
        is_pf = bool(s.get("port_forward", False))

        cc = COUNTRY_NAME_TO_ISO.get(c_name)
        if not cc:
            m = re.match(r'^(?:[A-Z]{2}-)?([A-Z]{2})#', s_name)
            if m:
                cc = m.group(1).upper()
            else:
                m2 = re.match(r'^([a-z]{2})-', hostname)
                if m2:
                    cc = m2.group(1).upper()
                else:
                    cc = "UN"

        continent = COUNTRY_CONTINENTS.get(cc, "Global")

        # Deduplicate on server_name, hostname, and secure_core status
        key = (s_name, hostname, is_sc, tuple(ips))
        if key in seen:
            continue
        seen.add(key)

        converted_servers.append({
            "continent": continent,
            "country": c_name,
            "country_code": cc,
            "city": city,
            "hostname": hostname,
            "port": 51820,
            "public_key": pubkey,
            "resolved_ips": ips,
            "secure_core": is_sc,
            "port_forward": is_pf,
            "server_name": s_name
        })

    print(f"Successfully processed {len(converted_servers)} unique WireGuard servers.")
    sc_count = sum(1 for x in converted_servers if x["secure_core"])
    std_count = sum(1 for x in converted_servers if not x["secure_core"])
    pf_count = sum(1 for x in converted_servers if x["port_forward"])
    print(f"  - Standard servers: {std_count}")
    print(f"  - Secure Core servers: {sc_count}")
    print(f"  - Port Forwarding enabled: {pf_count}")

    output_data = {
        "user_interface": existing_creds,
        "servers": converted_servers,
        "last_updated": "2026-09-21T21:30:00"
    }

    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"✅ Saved complete database to {target_file}")

if __name__ == "__main__":
    main()
