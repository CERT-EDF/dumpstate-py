import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class UsbEvent:
    """Holds information about a single USB event."""

    timestamp: datetime
    details: dict[str, Any]


@dataclass
class UsbDeviceManager:
    """Holds device manager state and event logs."""

    handler_properties: dict[str, Any] = field(default_factory=dict)
    events: list[UsbEvent] = field(default_factory=list)

    def extract_data(self, parsed_json_data):
        if "handler" in parsed_json_data:
            self.handler_properties = parsed_json_data["handler"]
        if "USB Event" in parsed_json_data:
            self.add_events(parsed_json_data["USB Event"])

    def _parse_event_details(self, details: str) -> dict[str, str]:
        """Parses the details string of a USB event to extract key-value properties."""
        properties = {}

        # Check for UEVENT format like: {SUBSYSTEM=android_usb, SEQNUM=...}
        uevent_match = re.search(r'UEVENT:\s*\{(.*?)\}', details)
        if uevent_match:
            properties['event_type'] = 'uevent'
            content = uevent_match.group(1)
            # Split by comma and then by equals to get key-value pairs
            pairs = content.split(',')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    properties[key.strip()] = value.strip()
            return properties

        # Check for Intent format like: Intent { act=... flg=... }
        intent_match = re.search(r'intent:\s*Intent\s*\{(.*?)\}', details)
        if intent_match:
            properties['event_type'] = 'intent'

            content = intent_match.group(1).strip()
            # Use regex to find all key=value pairs in the intent string
            for match in re.finditer(r'(\w+)=([^\s}]+)', content):
                properties[match.group(1)] = match.group(2)
            # Check for flags like (has extras)
            if '(has extras)' in content:
                properties['extras'] = True

        return properties

    def add_events(self, list_events: list[str]) -> bool:
        if not len(list_events):
            return False

        for usb_event in list_events:
            ts_match = re.match(
                r'(\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}:\d{3})\s(.*?)$', usb_event
            )
            if ts_match:
                ts_str = f"{datetime.now().year}-{ts_match.group(1)}"
                ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S:%f')
                self.events.append(
                    UsbEvent(ts, self._parse_event_details(ts_match.group(2)))
                )

        return True


@dataclass
class UsbConnection:
    """Holds information about a single host connection event."""

    device_address: bytes = b''
    mode: int = 0
    timestamp: datetime = None
    manufacturer: bytes = b''
    product: bytes = b''

    def parse(self, props: dict[str, Any]):
        self.device_address = props.get('device_address')
        self.mode = int(props.get('mode', -1))
        # Timestamp is in milliseconds, convert to seconds for fromtimestamp
        timestamp_ms = int(props.get('timestamp', 0))
        self.timestamp = (
            datetime.fromtimestamp(timestamp_ms / 1000)
            if timestamp_ms
            else None
        )
        self.manufacturer = props.get('manufacturer')
        self.product = props.get('product')


@dataclass
class UsbHostManager:
    """Holds host manager state."""

    num_connects: int = 0
    connections: list[UsbConnection] = field(default_factory=list)

    def extract_data(self, parsed_json_data):
        self.num_connects = parsed_json_data.get('num_connects')
        if 'connections' in parsed_json_data:
            for connection in parsed_json_data['connections']:
                uc = UsbConnection()
                uc.parse(connection)
                self.connections.append(uc)


@dataclass
class UsbManagerData:
    """Holds the entire parsed state of the USB Manager."""

    restrictor_state: dict[str, str] = field(default_factory=dict)
    device_manager: UsbDeviceManager | None = None
    host_manager: UsbHostManager | None = None


def clean_and_load_json(text: str) -> dict[str, Any]:
    """
    Cleans the non-standard key=value format into valid JSON and loads it.
    """

    def quote_values_if_string(match):
        key = match.group(1).strip()
        value = match.group(2).strip()
        # If value is a keyword or a number, don't quote it.
        if value in ('true', 'false', 'null') or re.fullmatch(
            r'-?\d+\.?\d*', value
        ):
            return f'"{key}": {value}'
        # Otherwise, it's a string that needs quoting. Escape existing quotes.
        value = value.replace('"', '\\"')
        return f'"{key}": "{value}"'

    # 1. Add commas between adjacent objects in arrays: '} {' -> '}, {'
    text = re.sub(r'}\s*{', '}, {', text)

    # 2. Add commas between values on separate lines inside arrays
    text = re.sub(
        r'(true|false|null|-?\d+\.?\d*)\s*\n\s*(true|false|null|-?\d+\.?\d*)',
        r'\1,\n\2',
        text,
        flags=re.MULTILINE,
    )

    # 3. Convert all `key=value` pairs. The helper function handles quoting.
    text = re.sub(
        r'^\s*([\w\s-]+)\s*=\s*([^{[]+?)\s*$',
        quote_values_if_string,
        text,
        flags=re.MULTILINE,
    )

    # 4. Handle 'key=value' for numeric/boolean/null values
    text = re.sub(
        r'^\s*([\w\s-]+)\s*=\s*(true|false|null|-?\d+\.?\d*)\s*$',
        r'"\1": \2',
        text,
        flags=re.MULTILINE,
    )

    # 5. Handle assignments for objects and arrays: 'key={' -> '"key": {'
    text = re.sub(
        r'^\s*([\w\s-]+)\s*=\s*({|\[)', r'"\1": \2', text, flags=re.MULTILINE
    )

    # 6. Add commas between elements that are on new lines
    text = re.sub(
        r'(["}\]]|true|false|null|-?\d+\.?\d*)\s*\n\s*"', r'\1,\n"', text
    )

    # 7. Remove trailing commas just before a closing brace or bracket
    text = re.sub(r',\s*([}\]])', r'\1', text)

    # Wrap the text in curly braces to form a valid JSON object string
    json_string = f"{{{text}}}"

    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Could not parse the block as JSON after cleaning: {e}"
        )


def parse_usb_manager_state(
    dumpstate_content: RawData,
) -> UsbManagerData | None:
    LOGGER.info("Parsing \"USB MANAGER STATE\" section...")

    match = re.search(
        rb'USB MANAGER STATE \(dumpsys usb\):\n(.*?)(?=\n\n\n|\Z)',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not match:
        return None

    block = match.group(1).decode('utf-8').strip()
    if not block:
        return None

    data = UsbManagerData()

    # Pre-parse the non-JSON USB Event log, convert it to valid JSON,
    # and substitute it back into the main block.
    event_log_match = re.search(
        r'(USB Event=\[\n(.*?)\n\s+\])', block, re.DOTALL
    )
    if event_log_match:
        full_match_text = event_log_match.group(1)
        event_log_content = event_log_match.group(2).strip()

        # 1. Convert the log into a valid JSON array of strings
        event_lines = event_log_content.split('\n')
        # Use json.dumps to safely escape each line
        json_escaped_lines = [json.dumps(line.strip()) for line in event_lines]
        # Create the final valid JSON string for the array
        valid_json_events = f'"USB Event": [{", ".join(json_escaped_lines)}]'

        # 2. Replace the original malformed block with the valid JSON
        block = block.replace(full_match_text, valid_json_events)

    # Parse the initial key:value block for Restrictor State
    restrictor_match = re.search(
        r'USB Host Restrictor State:\n(.*?)(?=\n[A-Z])', block, re.DOTALL
    )
    if restrictor_match:
        for line in restrictor_match.group(1).strip().split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                data.restrictor_state[key.strip()] = val.strip()

    # Find the main JSON-like block by locating the first '{' on a line
    # and then programmatically finding its matching closing brace '}'.
    # This is more robust than a single regex for nested structures.
    start_match = re.search(r'^\s*{', block, re.MULTILINE)
    if start_match:
        start_index = start_match.start()
        brace_level = 0
        end_index = -1

        # Iterate through the rest of the block to find the matching brace
        for i, char in enumerate(block[start_index:]):
            if char == '{':
                brace_level += 1
            elif char == '}':
                brace_level -= 1

            if brace_level == 0:
                end_index = start_index + i
                break

        if end_index != -1:
            # Extract the content between the outer braces
            json_like_content = block[start_index + 1 : end_index]
            try:
                # And load it like a json string
                parsed_json_data = clean_and_load_json(json_like_content)
                if "device_manager" in parsed_json_data:
                    data.device_manager = UsbDeviceManager()
                    data.device_manager.extract_data(
                        parsed_json_data["device_manager"]
                    )
                if "host_manager" in parsed_json_data:
                    data.host_manager = UsbHostManager()
                    data.host_manager.extract_data(
                        parsed_json_data["host_manager"]
                    )

            except ValueError as e:
                LOGGER.warning(e)

    return data
