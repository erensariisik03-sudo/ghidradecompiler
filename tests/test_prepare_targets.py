import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_targets', ROOT / 'scripts/prepare_targets.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fake_elf(bits=32):
    data = bytearray(1024)
    data[:6] = b'\x7fELF' + bytes([1 if bits == 32 else 2, 1])
    struct.pack_into('<H', data, 18, 40 if bits == 32 else 183)
    if bits == 32:
        struct.pack_into('<I', data, 28, 64)
        struct.pack_into('<HH', data, 42, 32, 1)
        struct.pack_into('<8I', data, 64, 1, 0, 0, 0, len(data), len(data), 5, 4096)
    else:
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<II6Q', data, 64, 1, 5, 0, 0, 0, len(data), len(data), 4096)
    data[400:412] = b'<size=25>\x00\x00\x00'
    return data


class PreparationTests(unittest.TestCase):
    def test_elf_architecture_and_lfs_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'test.so'
            for bits in (32, 64):
                binary.write_bytes(fake_elf(bits))
                self.assertEqual(module.elf_info(binary)['bits'], bits)
            binary.write_bytes(b'version https://git-lfs.github.com/spec/v1\n' + bytes(100))
            with self.assertRaisesRegex(ValueError, 'LFS pointer'):
                module.elf_info(binary)

    def test_dump_scope_and_rva_association(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / 'dump.cs'
            text = ''
            for cls in sorted(module.REQUIRED_CLASSES):
                text += f'// Namespace: \npublic class {cls} : MonoBehaviour // TypeDefIndex: 1\n{{\n'
                text += '\t// RVA: 0x100 Offset: 0x80 VA: 0x100\n\tpublic void Test(string a) { }\n}\n'
            text += '// Namespace: Other\npublic class fm // TypeDefIndex: 99\n{\n// RVA: 0x900\npublic void Wrong() { }\n}\n'
            dump.write_text(text)
            rows = module.parse_dump(dump)
            self.assertEqual(len(rows), 4)
            self.assertEqual({row['rva'] for row in rows}, {256})
            self.assertNotIn('Wrong', [row['method'] for row in rows])

    def test_arm64_requires_matching_dump_and_bounds_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / 'seed.json'
            seed.write_text(json.dumps({'architecture_bits': 32, 'source': 'test', 'targets': [
                {'rva': 2048, 'class': 'fm', 'method': 'cwv', 'group': 'test'}]}))
            binary = root / 'test.so'
            binary.write_bytes(fake_elf(64))
            (root / 'out64').mkdir()
            (root / 'out64' / 'SUCCESS.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'ARM32'):
                module.prepare(binary, root / 'out64', seed)
            self.assertFalse((root / 'out64' / 'SUCCESS.json').exists())
            binary.write_bytes(fake_elf(32))
            with self.assertRaisesRegex(ValueError, 'outside executable'):
                module.prepare(binary, root / 'out32', seed)

    def test_metadata_literal_index_and_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            literals = [b'unrelated', b'<\\/?size[^>]*>', b'Username must be 3 to 25 characters', b'<color=red>']
            entries, payload = bytearray(), bytearray()
            for literal in literals:
                entries.extend(struct.pack('<II', len(literal), len(payload)))
                payload.extend(literal)
            metadata = root / 'global-metadata.dat'
            metadata.write_bytes(struct.pack('<6I', 0xFAB11BAF, 29, 24, len(entries), 24 + len(entries), len(payload)) + entries + payload)
            output = root / 'literals.jsonl'
            report = module.metadata_literals(metadata, output)
            rows = [json.loads(line) for line in output.read_text().splitlines() if not line.startswith('#')]
            self.assertEqual(report['literal_candidates'], 3)
            self.assertEqual([row['index'] for row in rows], [1, 2, 3])
            self.assertEqual(rows[0]['text'], literals[1].decode())
            metadata.write_bytes(bytes(32))
            with self.assertRaisesRegex(ValueError, 'magic'):
                module.metadata_literals(metadata, output)


if __name__ == '__main__':
    unittest.main()
