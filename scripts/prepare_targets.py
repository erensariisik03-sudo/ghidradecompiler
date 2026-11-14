#!/usr/bin/env python3
"""Prepare bounded IL2CPP diagnostics; no binary patching or external packages."""
import argparse
import hashlib
import json
import mmap
import re
import struct
from pathlib import Path

GAME_CLASSES = {
    'TMPInputFieldTagFilter', 'TMPTextTagFilter', 'ChangeUsernameManager',
    'ChangeUsernameManager.<SubmitChangeUsernameAsync>d__13',
    'fm', 'fm.<RequestAsync>d__2', 'playerNameManager', 'ChatMessage',
}
TMP_METHODS = {
    'get_text', 'set_text', 'SetText', 'SetTextWithoutNotify',
    'get_characterLimit', 'set_characterLimit', 'get_onValueChanged',
    'get_onValidateInput', 'SendOnValueChanged', 'SendOnValueChangedAndUpdateLabel',
    'SendOnEndEdit', 'SendOnSubmit', 'OnSubmit', 'OnDeselect',
    'Append', 'Insert', 'Validate', 'DeactivateInputField',
}
REQUIRED_CLASSES = {'TMPInputFieldTagFilter', 'TMPTextTagFilter', 'ChangeUsernameManager', 'fm'}


def parse_dump(path):
    """Stream dump.cs; only retain selected class/method signatures."""
    rows, cls, namespace, rva = [], '', '', None
    with Path(path).open(encoding='utf-8-sig', errors='replace') as handle:
        for number, line in enumerate(handle, 1):
            if line.startswith('// Namespace:'):
                namespace = line.partition(':')[2].strip()
                cls, rva = '', None
            if '// TypeDefIndex:' in line:
                match = re.search(r'\b(?:class|struct)\s+(.+?)(?:\s+:\s+|\s+// TypeDefIndex:)', line)
                cls = match.group(1).strip() if match else ''
                rva = None
            match = re.search(r'// RVA:\s*(0x[0-9A-Fa-f]+)', line)
            if match:
                rva = int(match.group(1), 16)
                continue
            if rva is None or not line.rstrip().endswith('{ }'):
                continue
            method = re.search(r'([.\w<>]+)\s*\(', line)
            if not method:
                rva = None
                continue
            name = method.group(1)
            game = namespace == '' and cls in GAME_CLASSES
            tmp = namespace == 'TMPro' and cls == 'TMP_InputField' and name in TMP_METHODS
            if rva and (game or tmp):
                rows.append({'rva': rva, 'class': cls, 'method': name,
                             'signature': line.strip(), 'dump_line': number,
                             'group': 'tag_filter' if 'TagFilter' in cls else
                                      ('tmp_input' if tmp else 'username_or_chat')})
            rva = None
    missing = REQUIRED_CLASSES - {row['class'] for row in rows}
    if missing:
        raise ValueError('Required classes absent from dump: ' + ', '.join(sorted(missing)))
    return rows


def elf_info(path):
    with Path(path).open('rb') as handle:
        header = handle.read(64)
        if header.startswith(b'version https://git-lfs'):
            raise ValueError('libil2cpp.so is a Git LFS pointer. Fetch LFS binary content first.')
        if len(header) < 52 or header[:4] != b'\x7fELF' or header[5] != 1:
            raise ValueError('Expected a little-endian ELF .so binary.')
        bits = {1: 32, 2: 64}.get(header[4])
        machine = struct.unpack_from('<H', header, 18)[0]
        if (bits, machine) not in {(32, 40), (64, 183)}:
            raise ValueError(f'Only Android ARM32/ARM64 supported; ELF {bits}, machine {machine}.')
        if bits == 32:
            phoff = struct.unpack_from('<I', header, 28)[0]
            phsize, phnum = struct.unpack_from('<HH', header, 42)
            fmt = '<IIIIIIII'
        else:
            phoff = struct.unpack_from('<Q', header, 32)[0]
            phsize, phnum = struct.unpack_from('<HH', header, 54)
            fmt = '<IIQQQQQQ'
        segments, loads = [], []
        for index in range(phnum):
            handle.seek(phoff + index * phsize)
            values = struct.unpack(fmt, handle.read(struct.calcsize(fmt)))
            if bits == 32:
                kind, offset, va, _, filesz, memsz, flags, _ = values
            else:
                kind, flags, offset, va, _, filesz, memsz, _ = values
            if kind == 1:
                loads.append(va - offset)
                if flags & 1:
                    segments.append((va, va + filesz))
        if not loads or not segments:
            raise ValueError('ELF has no loadable executable segments.')
        return {'bits': bits, 'machine': machine, 'elf_base': min(loads), 'executable': segments}


def metadata_literals(path, output):
    """Read standard IL2CPP string-literal tables; retain index/offset, not guesses at native references."""
    count = 0
    with Path(path).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if len(data) < 24:
            raise ValueError('Metadata header is truncated.')
        magic, version, table, table_bytes, payload, payload_bytes = struct.unpack_from('<6I', data)
        if magic != 0xFAB11BAF:
            raise ValueError('Metadata has no standard IL2CPP magic (encrypted or wrong file).')
        if not (16 <= version <= 40) or table < 24 or table_bytes % 8 or table + table_bytes > len(data) or payload + payload_bytes > len(data):
            raise ValueError('Invalid/unsupported metadata literal table layout.')
        with output.open('w', encoding='utf-8') as out:
            out.write(f'# metadata version={version}; candidate literals, NOT proof of execution\n')
            for index in range(table_bytes // 8):
                length, offset = struct.unpack_from('<II', data, table + index * 8)
                if length > 32768 or offset + length > payload_bytes:
                    continue
                text = data[payload + offset:payload + offset + length].decode('utf-8', errors='replace')
                if re.search(r'size|colou?r|username|user.?name|karakter|character|nickname|\b25\b|\b1024\b|<#[0-9a-f]', text, re.I):
                    record = {'index': index, 'metadata_offset': hex(payload + offset), 'text': text}
                    out.write(json.dumps(record, ensure_ascii=False) + '\n')
                    count += 1
                    if count >= 2500:
                        out.write('# TRUNCATED at 2500 candidates\n')
                        break
    return {'metadata_version': version, 'literal_candidates': count}


def native_strings(path, output):
    count = 0
    with Path(path).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data, output.open('w', encoding='utf-8') as out:
        out.write('# Native file offsets, not RVAs. IL2CPP managed strings may exist ONLY in metadata.\n')
        last_start = -1
        for hit in re.finditer(rb'size|colou?r|username|character.?limit|<#[a-f0-9]', data, re.I):
            start = data.rfind(b'\0', max(0, hit.start() - 256), hit.start()) + 1
            if start == 0:
                start = max(0, hit.start() - 128)
            end = data.find(b'\0', hit.end(), min(len(data), hit.end() + 512))
            if end < 0:
                end = min(len(data), hit.end() + 128)
            raw = data[start:end]
            if start == last_start or not raw or sum(32 <= ch < 127 or ch in (9, 10, 13) for ch in raw) < len(raw) * 0.85:
                continue
            out.write(json.dumps({'file_offset': hex(start), 'text': raw.decode('utf-8', errors='replace')}, ensure_ascii=False) + '\n')
            last_start = start
            count += 1
            if count >= 500:
                out.write('# TRUNCATED at 500 candidates\n')
                break
    return count


def prepare(binary, output, seed, dump=None, metadata=None):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'SUCCESS.json').unlink(missing_ok=True)
    info = elf_info(binary)
    if dump and dump.is_file():
        rows = parse_dump(dump)
        origin = 'input/dump.cs; must match this exact binary and architecture'
    else:
        manifest = json.loads(seed.read_text(encoding='utf-8'))
        if info['bits'] != manifest['architecture_bits']:
            raise ValueError('Bundled addresses are ARM32. For ARM64, include same-version ARM64 input/dump.cs; do not reuse ARM32 RVAs.')
        rows = manifest['targets']
        origin = manifest['source']
    for row in rows:
        va = info['elf_base'] + (row['rva'] & ~1)
        if not any(start <= va < end for start, end in info['executable']):
            raise ValueError(f"Target outside executable ELF segments: {row['class']}.{row['method']} @ {hex(row['rva'])}. Wrong game version/architecture/dump.")
    with (output / 'targets.tsv').open('w', encoding='utf-8') as handle:
        handle.write('# RVA\tlabel\tgroup\n')
        for row in rows:
            label = re.sub(r'[^A-Za-z0-9_]', '_', row['class'] + '__' + row['method']) + f"__{row['rva']:X}"
            handle.write(f"0x{row['rva']:X}\t{label}\t{row['group']}\n")
    (output / 'target_signatures.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    with binary.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    report = dict(info, binary_name=binary.name, binary_sha256=digest, binary_bytes=binary.stat().st_size,
                  target_count=len(rows), target_source=origin, warnings=[
                      'RVA range checks do not prove the game version matches. Use the exact version that produced dump.cs.',
                      'Decompiled output is approximate; inspect disassembly and metadata before changing code.',
                      'No binary modifications are performed.',
                  ])
    report['native_string_candidates'] = native_strings(binary, output / 'native_strings.jsonl')
    if metadata and metadata.is_file():
        try:
            report.update(metadata_literals(metadata, output / 'metadata_literals.jsonl'))
        except ValueError as exc:
            report['warnings'].append(str(exc))
            (output / 'metadata_ERROR.txt').write_text(str(exc), encoding='utf-8')
    else:
        report['warnings'].append('global-metadata.dat missing: the exact Regex pattern may not be recoverable from libil2cpp.so alone.')
    (output / 'input_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"Prepared {len(rows)} targets; ARM{info['bits']}; SHA256={digest}")
    for warning in report['warnings']:
        print('NOTE:', warning)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seed', type=Path, default=Path('targets/arm32-known-dump.json'))
    parser.add_argument('--dump', type=Path, default=Path('input/dump.cs'))
    parser.add_argument('--metadata', type=Path, default=Path('input/global-metadata.dat'))
    args = parser.parse_args()
    try:
        prepare(args.binary, args.output, args.seed, args.dump, args.metadata)
    except (ValueError, OSError, struct.error) as exc:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'PREPARE_ERROR.txt').write_text(str(exc), encoding='utf-8')
        parser.exit(1, f'ERROR: {exc}\n')


if __name__ == '__main__':
    main()
