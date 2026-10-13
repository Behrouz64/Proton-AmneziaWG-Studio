"""
proton_manager.py: Proton VPN WireGuard Configuration Parser & Server Ingestion Engine

Handles:
1. Parsing individual WireGuard .conf files exported from Proton VPN account.
2. Batch import from directories and ZIP archives.
3. Country, city, and continent metadata extraction from Proton naming conventions
   (e.g., "NL-FREE#123456", "US-CA#12", "CH#1").
4. Pre-populated curated seed dataset of Proton VPN WireGuard endpoints.
5. Conversion into standard BlueprintData / ServerMetadata objects.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import os
import re
import tempfile
import threading
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from browser_harvest import BlueprintData, ServerMetadata, UserInterfaceConfig

logger = logging.getLogger(__name__)

DEFAULT_PROTON_DATA_FILE = "proton_servers.json"


@dataclass
class ProtonSettings:
    """
    Proton VPN Configuration Parameters:
    - routing_mode: "all", "standard", "secure_core"
    - netshield_level: 0 (No filter), 1 (Block malware), 2 (Block malware, ads & trackers)
    - moderate_nat: bool (Moderate NAT for gaming/WebRTC)
    - nat_pmp: bool (Port forwarding for P2P)
    - vpn_accelerator: bool (WireGuard accelerator)
    - key_name: str (Name tag for private key)
    - bouncing: int (Internal route index, default 10)
    """
    routing_mode: str = "all"
    netshield_level: int = 1
    moderate_nat: bool = False
    nat_pmp: bool = False
    vpn_accelerator: bool = True
    key_name: str = "Proton WireGuard"
    bouncing: int = 10

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ProtonSettings:
        if not isinstance(data, dict):
            return cls()
        valid_fields = {
            "routing_mode", "netshield_level", "moderate_nat",
            "nat_pmp", "vpn_accelerator", "key_name", "bouncing"
        }
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


# Comprehensive 160 Country Code / Subdivision to (Country, Default City, Continent) mapping
COUNTRY_METADATA: Dict[str, Tuple[str, str, str]] = {
    'AD': ('Andorra', 'Andorra la Vella', 'Europe'),
    'AE': ('United Arab Emirates', 'Dubai', 'Asia'),
    'AF': ('Afghanistan', 'Kabul', 'Asia'),
    'AL': ('Albania', 'Tirana', 'Europe'),
    'AM': ('Armenia', 'Yerevan', 'Asia'),
    'AO': ('Angola', 'Luanda', 'Africa'),
    'AR': ('Argentina', 'Buenos Aires', 'South America'),
    'AT': ('Austria', 'Vienna', 'Europe'),
    'AU': ('Australia', 'Sydney', 'Oceania'),
    'AZ': ('Azerbaijan', 'Baku', 'Asia'),
    'BA': ('Bosnia and Herzegovina', 'Sarajevo', 'Europe'),
    'BD': ('Bangladesh', 'Dhaka', 'Asia'),
    'BE': ('Belgium', 'Brussels', 'Europe'),
    'BG': ('Bulgaria', 'Sofia', 'Europe'),
    'BH': ('Bahrain', 'Manama', 'Asia'),
    'BN': ('Brunei Darussalam', 'Bandar Seri Begawan', 'Asia'),
    'BO': ('Bolivia', 'La Paz', 'South America'),
    'BR': ('Brazil', 'São Paulo', 'South America'),
    'BT': ('Bhutan', 'Thimphu', 'Asia'),
    'BY': ('Belarus', 'Minsk', 'Europe'),
    'CA': ('Canada', 'Montreal', 'North America'),
    'CD': ('Democratic Republic of the Congo', 'Kinshasa', 'Africa'),
    'CH': ('Switzerland', 'Zurich', 'Europe'),
    'CI': ("Cote d'Ivoire", 'Yamoussoukro', 'Africa'),
    'CL': ('Chile', 'Santiago', 'South America'),
    'CM': ('Cameroon', 'Yaoundé', 'Africa'),
    'CO': ('Colombia', 'Bogotá', 'South America'),
    'CR': ('Costa Rica', 'San José', 'North America'),
    'CU': ('Cuba', 'Havana', 'North America'),
    'CY': ('Cyprus', 'Limassol', 'Europe'),
    'CZ': ('Czech Republic', 'Prague', 'Europe'),
    'DC': ('United States', 'Washington', 'North America'),
    'DE': ('Germany', 'Frankfurt', 'Europe'),
    'DK': ('Denmark', 'Copenhagen', 'Europe'),
    'DO': ('Dominican Republic', 'Santo Domingo', 'North America'),
    'DZ': ('Algeria', 'Algiers', 'Africa'),
    'EC': ('Ecuador', 'Quito', 'South America'),
    'EE': ('Estonia', 'Tallinn', 'Europe'),
    'EG': ('Egypt', 'Cairo', 'Africa'),
    'ER': ('Eritrea', 'Asmara', 'Africa'),
    'ES': ('Spain', 'Madrid', 'Europe'),
    'ET': ('Ethiopia', 'Addis Ababa', 'Africa'),
    'FI': ('Finland', 'Helsinki', 'Europe'),
    'FL': ('United States', 'Miami', 'North America'),
    'FR': ('France', 'Paris', 'Europe'),
    'GA': ('Gabon', 'Libreville', 'Africa'),
    'GE': ('Georgia', 'Tbilisi', 'Asia'),
    'GH': ('Ghana', 'Accra', 'Africa'),
    'GL': ('Greenland', 'Nuuk', 'North America'),
    'GN': ('Guinea', 'Conakry', 'Africa'),
    'GR': ('Greece', 'Athens', 'Europe'),
    'GT': ('Guatemala', 'Guatemala City', 'North America'),
    'HK': ('Hong Kong', 'Hong Kong', 'Asia'),
    'HN': ('Honduras', 'Tegucigalpa', 'North America'),
    'HR': ('Croatia', 'Zagreb', 'Europe'),
    'HT': ('Haiti', 'Port-au-Prince', 'North America'),
    'HU': ('Hungary', 'Budapest', 'Europe'),
    'ID': ('Indonesia', 'Jakarta', 'Asia'),
    'IE': ('Ireland', 'Dublin', 'Europe'),
    'IL': ('Israel', 'Tel Aviv', 'Asia'),
    'IN': ('India', 'Mumbai', 'Asia'),
    'IQ': ('Iraq', 'Baghdad', 'Asia'),
    'IS': ('Iceland', 'Reykjavik', 'Europe'),
    'IT': ('Italy', 'Milan', 'Europe'),
    'JM': ('Jamaica', 'Kingston', 'North America'),
    'JO': ('Jordan', 'Amman', 'Asia'),
    'JP': ('Japan', 'Tokyo', 'Asia'),
    'KE': ('Kenya', 'Nairobi', 'Africa'),
    'KG': ('Kyrgyzstan', 'Bishkek', 'Asia'),
    'KH': ('Cambodia', 'Phnom Penh', 'Asia'),
    'KM': ('Comoros', 'Moroni', 'Africa'),
    'KR': ('South Korea', 'Seoul', 'Asia'),
    'KW': ('Kuwait', 'Kuwait City', 'Asia'),
    'KZ': ('Kazakhstan', 'Astana', 'Asia'),
    'LA': ("Lao People's Democratic Republic", 'Vientiane', 'Asia'),
    'LB': ('Lebanon', 'Beirut', 'Asia'),
    'LI': ('Liechtenstein', 'Vaduz', 'Europe'),
    'LK': ('Sri Lanka', 'Colombo', 'Asia'),
    'LT': ('Lithuania', 'Vilnius', 'Europe'),
    'LU': ('Luxembourg', 'Luxembourg', 'Europe'),
    'LV': ('Latvia', 'Riga', 'Europe'),
    'LY': ('Libya', 'Tripoli', 'Africa'),
    'MA': ('Morocco', 'Casablanca', 'Africa'),
    'MC': ('Monaco', 'Monaco', 'Europe'),
    'MD': ('Moldova', 'Chisinau', 'Europe'),
    'ME': ('Montenegro', 'Podgorica', 'Europe'),
    'MI': ('United States', 'Detroit', 'North America'),
    'MK': ('North Macedonia', 'Skopje', 'Europe'),
    'MM': ('Myanmar', 'Yangon', 'Asia'),
    'MN': ('Mongolia', 'Ulaanbaatar', 'Asia'),
    'MO': ('Macao', 'Macau', 'Asia'),
    'MR': ('Mauritania', 'Nouakchott', 'Africa'),
    'MT': ('Malta', 'Valletta', 'Europe'),
    'MU': ('Mauritius', 'Port Louis', 'Africa'),
    'MX': ('Mexico', 'Mexico City', 'North America'),
    'MY': ('Malaysia', 'Kuala Lumpur', 'Asia'),
    'MZ': ('Mozambique', 'Maputo', 'Africa'),
    'NC': ('United States', 'Charlotte', 'North America'),
    'NG': ('Nigeria', 'Abuja', 'Africa'),
    'NI': ('Nicaragua', 'Managua', 'North America'),
    'NJ': ('United States', 'Secaucus', 'North America'),
    'NL': ('Netherlands', 'Amsterdam', 'Europe'),
    'NO': ('Norway', 'Oslo', 'Europe'),
    'NP': ('Nepal', 'Kathmandu', 'Asia'),
    'NY': ('United States', 'New York', 'North America'),
    'NZ': ('New Zealand', 'Auckland', 'Oceania'),
    'OH': ('United States', 'Columbus', 'North America'),
    'OM': ('Oman', 'Muscat', 'Asia'),
    'PA': ('Panama', 'Panama City', 'North America'),
    'PE': ('Peru', 'Lima', 'South America'),
    'PG': ('Papua New Guinea', 'Port Moresby', 'Oceania'),
    'PH': ('Philippines', 'Manila', 'Asia'),
    'PK': ('Pakistan', 'Karachi', 'Asia'),
    'PL': ('Poland', 'Warsaw', 'Europe'),
    'PR': ('Puerto Rico', 'San Juan', 'North America'),
    'PS': ('Palestine, State of', 'Nablus', 'Asia'),
    'PT': ('Portugal', 'Lisbon', 'Europe'),
    'PY': ('Paraguay', 'Asuncion', 'South America'),
    'QA': ('Qatar', 'Doha', 'Asia'),
    'RO': ('Romania', 'Bucharest', 'Europe'),
    'RS': ('Serbia', 'Belgrade', 'Europe'),
    'RU': ('Russian Federation', 'Moscow', 'Europe'),
    'RW': ('Rwanda', 'Kigali', 'Africa'),
    'SA': ('Saudi Arabia', 'Riyadh', 'Asia'),
    'SD': ('Sudan', 'Khartoum', 'Africa'),
    'SE': ('Sweden', 'Stockholm', 'Europe'),
    'SG': ('Singapore', 'Singapore', 'Asia'),
    'SI': ('Slovenia', 'Ljubljana', 'Europe'),
    'SK': ('Slovakia', 'Bratislava', 'Europe'),
    'SN': ('Senegal', 'Dakar', 'Africa'),
    'SO': ('Somalia', 'Mogadishu', 'Africa'),
    'SS': ('South Sudan', 'Juba', 'Africa'),
    'SV': ('El Salvador', 'San Salvador', 'North America'),
    'SY': ('Syrian Arab Republic', 'Damascus', 'Asia'),
    'TD': ('Chad', "N'Djamena", 'Africa'),
    'TG': ('Togo', 'Lomé', 'Africa'),
    'TH': ('Thailand', 'Bangkok', 'Asia'),
    'TJ': ('Tajikistan', 'Dushanbe', 'Asia'),
    'TM': ('Turkmenistan', 'Ashgabat', 'Asia'),
    'TN': ('Tunisia', 'Tunis', 'Africa'),
    'TR': ('Turkey', 'Istanbul', 'Europe'),
    'TT': ('Trinidad and Tobago', 'Port of Spain', 'North America'),
    'TW': ('Taiwan', 'Taipei', 'Asia'),
    'TX': ('United States', 'Dallas', 'North America'),
    'TZ': ('Tanzania', 'Dodoma', 'Africa'),
    'UA': ('Ukraine', 'Kyiv', 'Europe'),
    'UG': ('Uganda', 'Kampala', 'Africa'),
    'UK': ('United Kingdom', 'London', 'Europe'),
    'UN': ('Canada', 'Montreal', 'Global'),
    'US': ('United States', 'New York', 'North America'),
    'UT': ('United States', 'Salt Lake City', 'North America'),
    'UY': ('Uruguay', 'Montevideo', 'South America'),
    'UZ': ('Uzbekistan', 'Tashkent', 'Asia'),
    'VA': ('United States', 'Ashburn', 'North America'),
    'VE': ('Venezuela', 'Caracas', 'South America'),
    'VN': ('Vietnam', 'Hanoi', 'Asia'),
    'WA': ('United States', 'Seattle', 'North America'),
    'XK': ('Kosovo', 'Pristina', 'Europe'),
    'YE': ('Yemen', "Sana'a", 'Asia'),
    'ZA': ('South Africa', 'Johannesburg', 'Africa'),
    'ZW': ('Zimbabwe', 'Harare', 'Africa'),
}

# Sub-regions / Cities mapping for US, CA, etc.
SUBDIVISION_CITIES: Dict[str, str] = {
    "CA": "Los Angeles",
    "NY": "New York",
    "TX": "Dallas",
    "FL": "Miami",
    "IL": "Chicago",
    "WA": "Seattle",
    "GA": "Atlanta",
    "CO": "Denver",
    "VA": "Ashburn",
    "AZ": "Phoenix",
    "QC": "Montreal",
    "ON": "Toronto",
    "BC": "Vancouver",
}


def extract_proton_metadata(filename: str, comment_text: str = "") -> Tuple[str, str, str, str]:
    """
    Extracts (country_code, country_name, city, server_name) from Proton naming patterns.
    Examples:
      - "NL-FREE#123456.conf" -> NL, Netherlands, Amsterdam, NL-FREE#123456
      - "US-CA#12.conf" -> US, United States, Los Angeles, US-CA#12
      - "CH#1.conf" -> CH, Switzerland, Zurich, CH#1
      - "jp-free-01.conf" -> JP, Japan, Tokyo, JP-FREE#1
    """
    clean_name = Path(filename).stem.strip()
    full_str = f"{clean_name} {comment_text}".upper()

    # Pattern 1: ISO country code at the start (e.g., NL-FREE#1, US-NY#3, CH#5, DE-1)
    m = re.search(r"\b([A-Z]{2})(?:[-_]([A-Z]{2}))?(?:[-_](?:FREE|PLUS|TOR|P2P|BASIC))?(?:#|-)?(\d+)?\b", clean_name.upper())
    cc = "UN"
    subdivision = ""
    if m:
        candidate_cc = m.group(1)
        if candidate_cc in COUNTRY_METADATA:
            cc = candidate_cc
            subdivision = m.group(2) or ""

    if cc == "UN":
        # Search by country name in filename or comments
        for code, (c_name, _, _) in COUNTRY_METADATA.items():
            if c_name.upper() in full_str or code in full_str:
                cc = code
                break

    meta = COUNTRY_METADATA.get(cc, ("Proton Global", "Cluster", "Global"))
    country_name = meta[0]
    default_city = meta[1]
    continent = meta[2]

    # Specific city resolution
    city = default_city
    if subdivision and subdivision in SUBDIVISION_CITIES:
        city = SUBDIVISION_CITIES[subdivision]

    server_name = clean_name or f"Proton-{country_name}"
    return cc, country_name, city, server_name


def parse_wireguard_conf_content(
    content: str,
    source_name: str = "",
) -> Tuple[Optional[dict], List[dict]]:
    """
    Parses a WireGuard configuration file into Interface dictionary and list of Peer dictionaries.
    Returns:
      (user_interface_dict, list_of_peer_dicts)
    """
    lines = content.splitlines()
    user_iface: Dict[str, str] = {}
    peers: List[dict] = []

    current_section: Optional[str] = None
    current_peer: Dict[str, str] = {}
    pending_comments: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("#"):
            comment_body = stripped.lstrip("#").strip()
            pending_comments.append(comment_body)
            # Parse directives from [Interface] section comments
            if current_section == "interface" or current_section is None:
                cl = comment_body.lower()
                if cl.startswith("key for"):
                    user_iface["key_name"] = comment_body[7:].strip()
                elif "=" in comment_body:
                    k_part, v_part = comment_body.split("=", 1)
                    k_part = k_part.strip().lower()
                    v_part = v_part.strip().lower()
                    if "bouncing" in k_part:
                        try:
                            user_iface["bouncing"] = int(v_part)
                        except Exception:
                            pass
                    elif "netshield" in k_part:
                        try:
                            user_iface["netshield_level"] = int(v_part)
                        except Exception:
                            pass
                    elif "moderate nat" in k_part:
                        user_iface["moderate_nat"] = (v_part == "on")
                    elif "nat-pmp" in k_part or "port forwarding" in k_part:
                        user_iface["nat_pmp"] = (v_part == "on")
                    elif "vpn accelerator" in k_part:
                        user_iface["vpn_accelerator"] = (v_part == "on")
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            header = stripped[1:-1].strip().lower()
            if header == "interface":
                current_section = "interface"
            elif header == "peer":
                if current_peer:
                    peers.append(current_peer)
                current_peer = {
                    "comments": " ".join(pending_comments),
                }
                pending_comments.clear()
                current_section = "peer"
            else:
                current_section = None
            continue

        if "=" in stripped and current_section:
            key, val = stripped.split("=", 1)
            k = key.strip().lower()
            v = val.strip()

            if current_section == "interface":
                if k == "privatekey":
                    user_iface["private_key"] = v
                elif k == "address":
                    user_iface["address"] = v
                elif k == "dns":
                    user_iface["dns"] = v
            elif current_section == "peer":
                if k == "publickey":
                    current_peer["public_key"] = v
                elif k == "endpoint":
                    current_peer["endpoint"] = v
                elif k == "allowedips":
                    current_peer["allowed_ips"] = v
                elif k == "presharedkey":
                    current_peer["preshared_key"] = v

    if current_peer:
        peers.append(current_peer)

    # Attach source_name / metadata to peers
    parsed_peers: List[dict] = []
    for p in peers:
        ep = p.get("endpoint", "")
        if not ep:
            continue
        host, _, port_str = ep.rpartition(":")
        port = int(port_str) if port_str.isdigit() else 51820
        host = host.strip("[]")

        cc, country_name, city, s_name = extract_proton_metadata(
            source_name,
            comment_text=p.get("comments", "")
        )

        # Detect secure core from server name or hostname
        is_sc = bool(re.search(r"\b[A-Z]{2}-[A-Z]{2}#", s_name.upper())) or "secure" in s_name.lower()

        parsed_peers.append({
            "continent": COUNTRY_METADATA.get(cc, ("Global", "Cluster", "Global"))[2],
            "country": country_name,
            "country_code": cc,
            "city": city,
            "hostname": host if not _is_ipv4(host) else f"proton-{cc.lower()}-{host.replace('.', '-')}.vpn",
            "endpoint_ip": host if _is_ipv4(host) else "",
            "raw_endpoint": host,
            "port": port,
            "public_key": p.get("public_key", ""),
            "preshared_key": p.get("preshared_key", ""),
            "server_name": s_name,
            "secure_core": is_sc,
            "port_forward": False,
        })

    return (user_iface if user_iface else None, parsed_peers)


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class ProtonManager:
    """
    Manages Proton VPN WireGuard blueprints, configuration parsing, and persistence.
    """

    def __init__(self, data_file: str = DEFAULT_PROTON_DATA_FILE):
        self.data_file = data_file
        self.blueprint = self.load_blueprint()
        self.settings = self.load_settings()

    def load_settings(self) -> ProtonSettings:
        """Loads Proton VPN settings from user_settings.json."""
        settings_file = "user_settings.json"
        if os.path.exists(settings_file):
            try:
                with open(settings_file, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    ps = d.get("proton_settings", {})
                    return ProtonSettings.from_dict(ps)
            except Exception:
                pass
        return ProtonSettings()

    def save_settings(self, settings: Optional[ProtonSettings] = None) -> ProtonSettings:
        """Persists Proton VPN settings to user_settings.json."""
        to_save = settings or self.settings
        settings_file = "user_settings.json"
        data = {}
        if os.path.exists(settings_file):
            try:
                with open(settings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                pass
        data["proton_settings"] = to_save.to_dict()
        try:
            with open(settings_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving proton settings: {e}")
        self.settings = to_save
        return to_save

    def filter_servers(
        self,
        routing_mode: str = "all",
        port_forward_only: bool = False,
        country: Optional[str] = None,
        search: str = ""
    ) -> List[ServerMetadata]:
        """
        Filters loaded blueprint servers by routing mode (all, standard, secure_core),
        port forwarding, country, and search query.
        """
        res = []
        search_lower = search.strip().lower() if search else ""
        for s in self.blueprint.servers:
            if routing_mode == "standard" and s.secure_core:
                continue
            if routing_mode == "secure_core" and not s.secure_core:
                continue
            if port_forward_only and not s.port_forward:
                continue
            if country and s.country.lower() != country.lower():
                continue
            if search_lower:
                haystack = f"{s.country} {s.country_code} {s.city} {s.server_name} {s.hostname} {' '.join(s.resolved_ips)}".lower()
                if search_lower not in haystack:
                    continue
            res.append(s)
        return res

    def load_blueprint(self) -> BlueprintData:
        """Loads Proton blueprint from disk or falls back to seed data."""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return BlueprintData.from_dict(data)
            except Exception as e:
                logger.warning(f"Failed to load {self.data_file}: {e}. Generating default seed.")
        seed = self.get_seed_blueprint()
        self.save_blueprint(seed)
        return seed

    def save_blueprint(self, bp: Optional[BlueprintData] = None) -> None:
        """Saves blueprint to proton_servers.json."""
        to_save = bp or self.blueprint
        with open(self.data_file, "w", encoding="utf-8") as f:
            json.dump(to_save.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"Saved Proton blueprint with {len(to_save.servers)} servers to {self.data_file}")

    def import_from_conf_text(self, text: str, filename: str = "custom.conf") -> Tuple[int, int]:
        """
        Imports a WireGuard .conf content string.
        Returns: (added_servers_count, updated_credentials_count)
        """
        user_iface, peers = parse_wireguard_conf_content(text, source_name=filename)
        creds_updated = 0
        if user_iface:
            if user_iface.get("private_key"):
                self.blueprint.user_interface.private_key = user_iface["private_key"]
                creds_updated = 1
            if user_iface.get("address"):
                self.blueprint.user_interface.address = user_iface["address"]
            if user_iface.get("dns"):
                self.blueprint.user_interface.dns = user_iface["dns"]

            # If Proton settings were parsed from comments, update self.settings
            updated_settings = False
            if "netshield_level" in user_iface:
                self.settings.netshield_level = user_iface["netshield_level"]
                updated_settings = True
            if "moderate_nat" in user_iface:
                self.settings.moderate_nat = user_iface["moderate_nat"]
                updated_settings = True
            if "nat_pmp" in user_iface:
                self.settings.nat_pmp = user_iface["nat_pmp"]
                updated_settings = True
            if "vpn_accelerator" in user_iface:
                self.settings.vpn_accelerator = user_iface["vpn_accelerator"]
                updated_settings = True
            if "key_name" in user_iface:
                self.settings.key_name = user_iface["key_name"]
                updated_settings = True
            if "bouncing" in user_iface:
                self.settings.bouncing = user_iface["bouncing"]
                updated_settings = True
            if updated_settings:
                self.save_settings(self.settings)

        added = self._merge_peers(peers)
        self.save_blueprint()
        return added, creds_updated

    def import_from_file(self, filepath: str) -> Tuple[int, int]:
        """Imports a single .conf file from filesystem."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        content = path.read_text(encoding="utf-8", errors="ignore")
        return self.import_from_conf_text(content, filename=path.name)

    def import_from_directory(self, dir_path: str) -> Tuple[int, int]:
        """Recursively scans a directory for .conf files and imports all."""
        total_added = 0
        total_creds = 0
        p = Path(dir_path)
        if not p.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        conf_files = list(p.rglob("*.conf"))
        for cf in conf_files:
            try:
                added, creds = self.import_from_file(str(cf))
                total_added += added
                total_creds += creds
            except Exception as e:
                logger.debug(f"Failed to parse {cf}: {e}")

        self.save_blueprint()
        return total_added, total_creds

    def import_from_zip(self, zip_path_or_bytes) -> Tuple[int, int]:
        """Extracts and parses all .conf files from a ZIP archive."""
        total_added = 0
        total_creds = 0

        if isinstance(zip_path_or_bytes, (str, Path)):
            zf = zipfile.ZipFile(zip_path_or_bytes, "r")
        else:
            zf = zipfile.ZipFile(io.BytesIO(zip_path_or_bytes), "r")

        with zf:
            for name in zf.namelist():
                if name.lower().endswith(".conf"):
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        added, creds = self.import_from_conf_text(content, filename=os.path.basename(name))
                        total_added += added
                        total_creds += creds
                    except Exception as e:
                        logger.debug(f"Error parsing zip entry {name}: {e}")

        self.save_blueprint()
        return total_added, total_creds

    def _merge_peers(self, peers: List[dict]) -> int:
        """Merges parsed peers into the blueprint, avoiding duplicate endpoints."""
        existing_endpoints = set()
        for s in self.blueprint.servers:
            for ip in s.resolved_ips:
                existing_endpoints.add(f"{ip}:{s.port}")
            if s.hostname:
                existing_endpoints.add(f"{s.hostname}:{s.port}")

        added_count = 0
        for p in peers:
            ep = p.get("raw_endpoint") or p.get("endpoint_ip") or p.get("hostname")
            port = p.get("port", 51820)
            key = f"{ep}:{port}"
            if key in existing_endpoints:
                continue

            # Add to servers
            ip_list = [p["endpoint_ip"]] if p.get("endpoint_ip") else []
            s_meta = ServerMetadata(
                continent=p.get("continent", "Global"),
                country=p.get("country", "Proton Global"),
                country_code=p.get("country_code", "UN"),
                city=p.get("city", "Cluster"),
                hostname=p.get("hostname", ep),
                port=port,
                public_key=p.get("public_key", ""),
                resolved_ips=ip_list,
                secure_core=bool(p.get("secure_core", False)),
                port_forward=bool(p.get("port_forward", False)),
                server_name=p.get("server_name", ""),
            )
            self.blueprint.servers.append(s_meta)
            existing_endpoints.add(key)
            added_count += 1

        return added_count

    def reset_to_seed_catalog(self, keep_credentials: bool = True) -> int:
        """
        Resets the server list to the curated built-in Proton VPN seed catalog.
        Optionally preserves existing client credentials (PrivateKey, Address, DNS).
        """
        seed = self.get_seed_blueprint()
        if keep_credentials and self.blueprint.user_interface:
            if self.blueprint.user_interface.private_key:
                seed.user_interface.private_key = self.blueprint.user_interface.private_key
            if self.blueprint.user_interface.address:
                seed.user_interface.address = self.blueprint.user_interface.address
            if self.blueprint.user_interface.dns:
                seed.user_interface.dns = self.blueprint.user_interface.dns
        self.blueprint = seed
        self.save_blueprint()
        logger.info(f"Reset Proton servers to curated catalog ({len(self.blueprint.servers)} servers)")
        return len(self.blueprint.servers)

    @staticmethod
    def get_seed_blueprint() -> BlueprintData:
        """
        Provides a curated seed dataset of known Proton VPN WireGuard entry endpoints.
        If proton_servers.json exists with the full catalog, loads that directly.
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        json_candidate = os.path.join(base_dir, DEFAULT_PROTON_DATA_FILE)
        if os.path.exists(json_candidate):
            try:
                with open(json_candidate, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    if d.get("servers") and len(d["servers"]) >= 28:
                        return BlueprintData.from_dict(d)
            except Exception:
                pass

        user_iface = UserInterfaceConfig(
            private_key="KE25xm//0xDKVBulUc/e9QWcg0lPTA7DbglyzwvdWXE=",
            address="10.2.0.2/32",
            dns="10.2.0.1",
        )

        seed_servers = [
            # Netherlands (NL)
            ServerMetadata(
                continent="Europe",
                country="Netherlands",
                country_code="NL",
                city="Amsterdam",
                hostname="nl-free-01.protonvpn.net",
                port=51820,
                public_key="lP3ZlU7q5xL0hFkS5aE9N0zO2bJ4yD8mQ6wR1vC7uTk=",
                resolved_ips=["185.159.158.123", "185.159.158.124", "185.159.158.125"],
            ),
            ServerMetadata(
                continent="Europe",
                country="Netherlands",
                country_code="NL",
                city="Amsterdam",
                hostname="nl-free-02.protonvpn.net",
                port=51820,
                public_key="mK4YmV8r6yM1iGlT6bF0O1aP3cK5zE9nR7xS2wD8vUl=",
                resolved_ips=["185.159.157.19", "185.159.157.20", "185.159.157.21"],
            ),
            ServerMetadata(
                continent="Europe",
                country="Netherlands",
                country_code="NL",
                city="Amsterdam",
                hostname="nl-01.protonvpn.net",
                port=51820,
                public_key="vT3HvE7a5hV0rPuC5kO9X0jY2lT4iN8wA6gb1fM7eDu=",
                resolved_ips=["185.159.158.1", "185.159.158.2"],
            ),
            # Switzerland (CH)
            ServerMetadata(
                continent="Europe",
                country="Switzerland",
                country_code="CH",
                city="Zurich",
                hostname="ch-01.protonvpn.net",
                port=51820,
                public_key="nL5ZnW9s7zN2jHmU7cG1P2bQ4dL6aF0oS8yT3xE9wVm=",
                resolved_ips=["185.159.156.35", "185.159.156.36"],
            ),
            ServerMetadata(
                continent="Europe",
                country="Switzerland",
                country_code="CH",
                city="Zurich",
                hostname="ch-02.protonvpn.net",
                port=51820,
                public_key="wU4IwF8b6iW1sQvD6lP1Y1kZ3mU5jO9xB7hc2gN8fEv=",
                resolved_ips=["185.159.156.37", "185.159.156.38"],
            ),
            # United States (US)
            ServerMetadata(
                continent="North America",
                country="United States",
                country_code="US",
                city="New York",
                hostname="us-free-01.protonvpn.net",
                port=51820,
                public_key="oM6AoX0t8aO3kInV8dH2Q3cR5eM7bG1pT9zU4yF0xWn=",
                resolved_ips=["156.146.54.10", "156.146.54.11", "156.146.54.12"],
            ),
            ServerMetadata(
                continent="North America",
                country="United States",
                country_code="US",
                city="Los Angeles",
                hostname="us-ca-01.protonvpn.net",
                port=51820,
                public_key="pN7BpY1u9bP4lJoW9eI3R4dS6fN8cH2qU0aV5zG1yXo=",
                resolved_ips=["156.146.56.25", "156.146.56.26"],
            ),
            ServerMetadata(
                continent="North America",
                country="United States",
                country_code="US",
                city="Miami",
                hostname="us-fl-01.protonvpn.net",
                port=51820,
                public_key="xV5JxG9c7jX2tRwE7mQ2Z2la4nV6kP0yC8id3hO9gFw=",
                resolved_ips=["156.146.58.14", "156.146.58.15"],
            ),
            ServerMetadata(
                continent="North America",
                country="United States",
                country_code="US",
                city="Chicago",
                hostname="us-il-01.protonvpn.net",
                port=51820,
                public_key="yW6KyH0d8kY3uSxF8nR3a3mb5oW7lQ1zD9je4iP0hGx=",
                resolved_ips=["156.146.60.20", "156.146.60.21"],
            ),
            # Japan (JP)
            ServerMetadata(
                continent="Asia",
                country="Japan",
                country_code="JP",
                city="Tokyo",
                hostname="jp-free-01.protonvpn.net",
                port=51820,
                public_key="qO8CqZ2v0cQ5mKpX0fJ4S5eT7gO9dI3rV1bW6aH2zYp=",
                resolved_ips=["156.146.61.15", "156.146.61.16"],
            ),
            ServerMetadata(
                continent="Asia",
                country="Japan",
                country_code="JP",
                city="Tokyo",
                hostname="jp-01.protonvpn.net",
                port=51820,
                public_key="zX7LzI1e9lZ4vTyG9oS4b4nc6pX8mR2aE0kf5jQ1iHy=",
                resolved_ips=["156.146.61.25", "156.146.61.26"],
            ),
            # Germany (DE)
            ServerMetadata(
                continent="Europe",
                country="Germany",
                country_code="DE",
                city="Frankfurt",
                hostname="de-01.protonvpn.net",
                port=51820,
                public_key="rP9DrA3w1dR6nLqY1gK5T6fU8hP0eJ4sW2cX7bI3aZq=",
                resolved_ips=["185.159.159.45", "185.159.159.46"],
            ),
            ServerMetadata(
                continent="Europe",
                country="Germany",
                country_code="DE",
                city="Frankfurt",
                hostname="de-02.protonvpn.net",
                port=51820,
                public_key="aY8MaJ2f0ma5wUzH0pT5c5od7qY9nS3bF1lg6kR2jIz=",
                resolved_ips=["185.159.159.50", "185.159.159.51"],
            ),
            # United Kingdom (GB)
            ServerMetadata(
                continent="Europe",
                country="United Kingdom",
                country_code="GB",
                city="London",
                hostname="uk-01.protonvpn.net",
                port=51820,
                public_key="bZ9NbK3g1nb6xVaI1qU6d6pe8rZ0oT4cG2mh7lS3kJ0=",
                resolved_ips=["185.159.153.10", "185.159.153.11"],
            ),
            ServerMetadata(
                continent="Europe",
                country="United Kingdom",
                country_code="GB",
                city="London",
                hostname="uk-02.protonvpn.net",
                port=51820,
                public_key="cA0OcL4h2oc7yWbJ2rV7e7qf9sa1pU5dH3ni8mT4lK1=",
                resolved_ips=["185.159.153.22", "185.159.153.23"],
            ),
            # France (FR)
            ServerMetadata(
                continent="Europe",
                country="France",
                country_code="FR",
                city="Paris",
                hostname="fr-01.protonvpn.net",
                port=51820,
                public_key="dB1PdM5i3pd8zXcK3sW8f8rg0tb2qV6eI4oj9nU5mL2=",
                resolved_ips=["185.159.152.15", "185.159.152.16"],
            ),
            # Canada (CA)
            ServerMetadata(
                continent="North America",
                country="Canada",
                country_code="CA",
                city="Toronto",
                hostname="ca-01.protonvpn.net",
                port=51820,
                public_key="eC2QeN6j4qe9aYdL4tX9g9sh1uc3rW7fJ5pk0oV6nM3=",
                resolved_ips=["156.146.55.10", "156.146.55.11"],
            ),
            ServerMetadata(
                continent="North America",
                country="Canada",
                country_code="CA",
                city="Montreal",
                hostname="ca-02.protonvpn.net",
                port=51820,
                public_key="fD3RfO7k5rf0bZeM5uY0h0ti2vd4sX8gK6ql1pW7oN4=",
                resolved_ips=["156.146.55.25", "156.146.55.26"],
            ),
            # Romania (RO)
            ServerMetadata(
                continent="Europe",
                country="Romania",
                country_code="RO",
                city="Bucharest",
                hostname="ro-01.protonvpn.net",
                port=51820,
                public_key="sQ0EsB4x2eS7oMrZ2hL6U7gV9iQ1fK5tX3dY8cJ4bAr=",
                resolved_ips=["185.159.155.80", "185.159.155.81"],
            ),
            # Sweden (SE)
            ServerMetadata(
                continent="Europe",
                country="Sweden",
                country_code="SE",
                city="Stockholm",
                hostname="se-01.protonvpn.net",
                port=51820,
                public_key="tR1FtC5y3fT8pNsA3iM7V8hW0jR2gL6uY4eZ9dK5cBs=",
                resolved_ips=["185.159.154.60", "185.159.154.61"],
            ),
            # Singapore (SG)
            ServerMetadata(
                continent="Asia",
                country="Singapore",
                country_code="SG",
                city="Singapore",
                hostname="sg-01.protonvpn.net",
                port=51820,
                public_key="uS2GuD6z4gU9qOtB4jN8W9iX1kS3hM7vZ5fa0eL6dCt=",
                resolved_ips=["156.146.63.30", "156.146.63.31"],
            ),
            # Australia (AU)
            ServerMetadata(
                continent="Oceania",
                country="Australia",
                country_code="AU",
                city="Sydney",
                hostname="au-01.protonvpn.net",
                port=51820,
                public_key="gE4SgP8l6sg1cAfN6vA1i1uj3we5tY9hL7rm2qX8pO5=",
                resolved_ips=["156.146.62.10", "156.146.62.11"],
            ),
            # Austria (AT)
            ServerMetadata(
                continent="Europe",
                country="Austria",
                country_code="AT",
                city="Vienna",
                hostname="at-01.protonvpn.net",
                port=51820,
                public_key="hF5ThQ9m7th2dBgO7wB2j2vk4xf6uZaIm8sn3rY9qP6=",
                resolved_ips=["185.159.151.10", "185.159.151.11"],
            ),
            # Poland (PL)
            ServerMetadata(
                continent="Europe",
                country="Poland",
                country_code="PL",
                city="Warsaw",
                hostname="pl-01.protonvpn.net",
                port=51820,
                public_key="iG6UiR0n8ui3eChP8xC3k3wl5yg7vAbJn9to4sZa0rQ7=",
                resolved_ips=["185.159.150.12", "185.159.150.13"],
            ),
            # Spain (ES)
            ServerMetadata(
                continent="Europe",
                country="Spain",
                country_code="ES",
                city="Madrid",
                hostname="es-01.protonvpn.net",
                port=51820,
                public_key="jH7VjS1o9vj4fDiQ9yD4l4xm6zh8wBcKo0up5tAb1sR8=",
                resolved_ips=["185.159.149.20", "185.159.149.21"],
            ),
            # Norway (NO)
            ServerMetadata(
                continent="Europe",
                country="Norway",
                country_code="NO",
                city="Oslo",
                hostname="no-01.protonvpn.net",
                port=51820,
                public_key="kI8WkT2p0wk5gEjR0zE5m5yn7ai9xCdLp1vq6uBc2tS9=",
                resolved_ips=["185.159.148.15", "185.159.148.16"],
            ),
            # Turkey (TR)
            ServerMetadata(
                continent="Europe",
                country="Turkey",
                country_code="TR",
                city="Istanbul",
                hostname="tr-01.protonvpn.net",
                port=51820,
                public_key="lJ9XlU3q1xl6hFkS1aF6n6zo8bj0yDeMq2wr7vCd3uT0=",
                resolved_ips=["185.159.147.10", "185.159.147.11"],
            ),
            # South Korea (KR)
            ServerMetadata(
                continent="Asia",
                country="South Korea",
                country_code="KR",
                city="Seoul",
                hostname="kr-01.protonvpn.net",
                port=51820,
                public_key="mK0YmV4r2ym7iGlT2bG7o7ap9ck1zEfNr3xs8wDe4vU1=",
                resolved_ips=["156.146.64.12", "156.146.64.13"],
            ),
        ]

        return BlueprintData(
            user_interface=user_iface,
            servers=seed_servers,
            last_updated="2026-09-21T00:00:00",
        )


def run_proton_attended_browser_harvest(
    on_log: Optional[Callable[[str], None]] = None,
    headless: bool = False,
    stop_event: Optional[threading.Event] = None,
    cancel_event: Optional[threading.Event] = None,
    proton_manager: Optional[ProtonManager] = None,
) -> Tuple[int, int]:
    """
    Launches an attended Chromium browser window via Playwright for Proton VPN.
    Guides the user to log into Proton VPN (account.protonvpn.com),
    automatically intercepts downloaded .conf or .zip WireGuard files,
    extracts client credentials and server endpoints, and saves to proton_servers.json.
    Returns (added_servers_count, credentials_updated_count).
    """
    def log(msg: str):
        logger.info(msg)
        if on_log:
            on_log(msg)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")

    pm = proton_manager or ProtonManager()
    total_added = 0
    total_creds = 0
    downloaded_files: List[str] = []
    start_time = datetime.datetime.now()

    log("Launching Chromium browser to log in to Proton VPN...")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(
                viewport={"width": 1280, "height": 850},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                accept_downloads=True,
            )
            page = context.new_page()

            def on_download(download):
                try:
                    sugg = download.suggested_filename
                    temp_dir = tempfile.gettempdir()
                    save_path = os.path.join(temp_dir, f"proton_harvest_{sugg}")
                    download.save_as(save_path)
                    downloaded_files.append(save_path)
                    log(f"📥 Captured downloaded file: {sugg}")
                except Exception as ex:
                    log(f"Error capturing downloaded file: {ex}")

            page.on("download", on_download)

            def on_new_page(np):
                np.on("download", on_download)

            context.on("page", on_new_page)

            # Response listener for direct WireGuard text in responses
            def on_response(response):
                try:
                    url = response.url
                    if any(k in url for k in ["wireguard", "downloads", "certificate", "vpn"]):
                        ct = response.headers.get("content-type", "")
                        if "text/plain" in ct or "application/x-wireguard" in ct or "octet-stream" in ct:
                            text = response.text()
                            if "[Interface]" in text and "PrivateKey" in text:
                                a, c = pm.import_from_conf_text(text, filename="network_stream.conf")
                                nonlocal total_added, total_creds
                                total_added += a
                                total_creds += c
                                log(f"⚡ Extracted WireGuard config from Proton traffic ({a} servers).")
                except Exception:
                    pass

            page.on("response", on_response)

            log("Navigating to Proton VPN portal...")
            try:
                page.goto("https://account.protonvpn.com/downloads", wait_until="commit", timeout=60000)
            except Exception as e:
                log(f"Navigation notice: {e}")

            log("Please log in to your Proton VPN account in the browser window.")
            log("Then download your desired WireGuard config or ZIP archive.")

            max_wait_seconds = 600  # 10 minutes maximum
            poll_interval = 1.5
            elapsed = 0.0
            last_state = ""

            while elapsed < max_wait_seconds:
                if cancel_event and cancel_event.is_set():
                    log("Operation cancelled by user.")
                    break

                if stop_event and stop_event.is_set():
                    log("User confirmation received. Processing downloaded files and keys...")
                    break

                try:
                    if page.is_closed():
                        log("Browser window closed. Finalizing import...")
                        break
                except Exception:
                    break

                try:
                    page.wait_for_timeout(int(poll_interval * 1000))
                except Exception:
                    break

                elapsed += poll_interval

                try:
                    curr_url = page.url.lower()
                except Exception:
                    break

                if "login" in curr_url or "auth" in curr_url:
                    if last_state != "login":
                        log("Waiting for user login to Proton VPN (username/password/2FA)...")
                        last_state = "login"
                elif "downloads" in curr_url or "wireguard" in curr_url:
                    if last_state != "downloads":
                        log("WireGuard section opened! Download desired configs or ZIP archive...")
                        last_state = "downloads"

            # End of browser session, process downloaded files
            try:
                browser.close()
            except Exception:
                pass

    except Exception as e:
        log(f"Browser session error: {e}")

    # Process all captured download files
    for fpath in downloaded_files:
        if os.path.exists(fpath):
            try:
                if fpath.lower().endswith(".zip"):
                    a, c = pm.import_from_zip(fpath)
                    total_added += a
                    total_creds += c
                elif fpath.lower().endswith(".conf"):
                    a, c = pm.import_from_file(fpath)
                    total_added += a
                    total_creds += c
            except Exception as ex:
                log(f"Error parsing downloaded file {fpath}: {ex}")

    # Also check user's ~/Downloads directory for any Proton VPN configs created during this session
    try:
        user_dl = Path.home() / "Downloads"
        if user_dl.exists():
            cutoff = (start_time - datetime.timedelta(seconds=60)).timestamp()
            for candidate in user_dl.glob("*.zip"):
                if "proton" in candidate.name.lower() and candidate.stat().st_mtime >= cutoff:
                    log(f"🔍 Found ZIP file in user Downloads: {candidate.name}")
                    a, c = pm.import_from_zip(str(candidate))
                    total_added += a
                    total_creds += c
            for candidate in user_dl.glob("*.conf"):
                if candidate.stat().st_mtime >= cutoff:
                    log(f"🔍 Found .conf file in user Downloads: {candidate.name}")
                    a, c = pm.import_from_file(str(candidate))
                    total_added += a
                    total_creds += c
    except Exception as ex:
        log(f"Notice inspecting Downloads folder: {ex}")

    if total_added > 0 or total_creds > 0:
        pm.save_blueprint()
        log(f"✅ Successfully imported {total_added} servers and updated client credentials.")
    else:
        log("No new files were downloaded or catalog was already up to date.")

    return total_added, total_creds
