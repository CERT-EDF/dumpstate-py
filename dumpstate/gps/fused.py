import re
from dataclasses import dataclass, field
from datetime import datetime

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class LocationInfo:
    """Holds detailed information about a single location fix."""

    provider: bytes
    latitude: float
    longitude: float
    accuracy: float
    altitude: float
    altitude_accuracy: float
    speed: float
    speed_accuracy: float
    bearing: float
    bearing_accuracy: float
    timestamp: datetime


@dataclass
class FusedLocationData:
    """Holds all data for a single 'Fused Location Provider' block."""

    source: str = ''
    listeners: list[str] = field(default_factory=list)
    last_availability: bool = False
    last_locations: list[LocationInfo] = field(default_factory=list)

    def add_location_line(self, line: bytes):
        """Helper to parse a single complex location line."""
        content_match = re.search(rb'{(.*?)}', line)
        if not content_match:
            return None

        content = content_match.group(1)

        # Provider is everything before the first comma and coordinate
        provider_match = re.match(rb'([^,]+),', content)
        if not provider_match:
            return None
        provider = provider_match.group(1).strip()

        # More robust regex for lat, lon, and optional accuracy
        lat_lon_pattern = re.compile(
            r'(-?[\d.]+)\s*,\s*(-?[\d.]+)(?:±([\d.]+))?'
        )
        lat_lon_match = lat_lon_pattern.search(content.decode('utf-8'))

        if not lat_lon_match:
            return 0.0  # Cannot find lat/lon, cannot proceed

        lat: float = float(lat_lon_match.group(1))
        lon: float = float(lat_lon_match.group(2))
        acc: float = (
            float(lat_lon_match.group(3)) if lat_lon_match.group(3) else 0.0
        )

        # Default other values to 0.0
        kwargs: dict[str, float | datetime] = {
            'alt': 0.0,
            'alt_acc': 0.0,
            'spd': 0.0,
            'spd_acc': 0.0,
            'brg': 0.0,
            'brg_acc': 0.0,
            'ert': None,
        }

        # Regex to find key=value pairs for the rest of the line
        kv_pattern = re.compile(rb'(\w+)=([^,]+)')
        value_pattern = re.compile(r'(-?[\d.]+)(?:±([\d.]+))?')

        for key, val in kv_pattern.findall(content):
            key = key.strip().decode('utf-8')
            val = val.strip()
            val_match = value_pattern.search(val.decode('utf-8'))
            if 'ert' in key:
                kwargs[key] = datetime.strptime(
                    val.decode('utf-8'), "%m-%d %H:%M:%S.%f"
                )
            elif val_match:
                kwargs[key] = float(val_match.group(1))
                if val_match.group(2):
                    kwargs[f"{key}_acc"] = float(val_match.group(2))

        self.last_locations.append(
            LocationInfo(
                provider,
                lat,
                lon,
                acc,
                kwargs['alt'],
                kwargs['alt_acc'],
                kwargs['spd'],
                kwargs['spd_acc'],
                kwargs['brg'],
                kwargs['brg_acc'],
                kwargs['ert'],
            )
        )


def parse_fused_location(
    dumpstate_content: RawData,
) -> list[FusedLocationData] | None:
    """Parses all 'Fused Location Provider' sections of the bug report."""
    LOGGER.info("Parsing \"Fused Location Provider\" section...")

    # Find all blocks of 'Fused Location Provider'
    section_blocks = re.findall(
        rb'Fused Location Provider:\n((?: {2,}.*\n?)*)', dumpstate_content.raw
    )
    if not section_blocks:
        return None

    all_fused_data: list[FusedLocationData] = []
    for block in section_blocks:
        data = FusedLocationData()
        lines = block.strip().split(b'\n')

        # Use a state machine for listeners
        is_listener_section = False
        for line in lines:
            line = line.strip()
            if line.startswith(b"source:"):
                data.source = line.replace(b"source:", b"").strip()
                is_listener_section = False
            elif line.startswith(b"listeners:"):
                is_listener_section = True
            elif line.startswith(b"last availability:"):
                data.last_availability = b"true" in line.lower()
                is_listener_section = False
            elif line.startswith(b"last location"):
                data.add_location_line(line)
                is_listener_section = False
            elif is_listener_section:
                data.listeners.append(line)
        all_fused_data.append(data)
    return all_fused_data
