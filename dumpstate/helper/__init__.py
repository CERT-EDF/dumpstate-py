"""Raw Data"""


class RawData:

    def __init__(self, raw: bytes):
        self.raw: bytes = raw
        self.lines: list[bytes] = raw.strip().split(b'\n')
