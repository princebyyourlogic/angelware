import socket
import struct
import tempfile
from pathlib import Path
import unittest

from svr_capture import packets


class CaptureTimestampTests(unittest.TestCase):
    def test_micro_and_nanosecond_files_have_identical_timing(self):
        for order, magic, scale in [('<', 'd4c3b2a1', 1000000), ('>', 'a1b2c3d4', 1000000),
                                    ('<', '4d3cb2a1', 1000000000), ('>', 'a1b23c4d', 1000000000)]:
            with self.subTest(magic=magic), tempfile.TemporaryDirectory() as directory:
                data = bytes.fromhex(magic)+struct.pack(order+'HHIIII', 2, 4, 0, 0, 65535, 101)
                for index, fraction in enumerate((.125, .145)):
                    udp = struct.pack('!HHHH', 3074, 20000, 12, 0)+b'test'
                    ip = bytearray(20)
                    ip[0], ip[9] = 0x45, 17
                    struct.pack_into('!HH', ip, 2, 20+len(udp), index)
                    ip[12:16], ip[16:20] = socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2')
                    frame = bytes(ip)+udp
                    data += struct.pack(order+'IIII', 1700000000, round(fraction*scale), len(frame), len(frame))+frame
                # A snapshot can end in a partial record; prior packets still decode.
                data += struct.pack(order+'IIII', 1700000000, 0, 100, 100)+b'partial'
                path = Path(directory)/'test.pcap'
                path.write_bytes(data)
                rows = list(packets(path))
                self.assertEqual(len(rows), 2)
                self.assertAlmostEqual(rows[0][0], 1700000000.125)
                self.assertAlmostEqual(rows[1][0]-rows[0][0], .020, places=5)
                self.assertEqual(rows[1][-1], b'test')


if __name__ == '__main__':
    unittest.main()
