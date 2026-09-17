"""Prepare and validate portable media packages; standard-library-only CI helper."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import zipfile


ENCODERS = ('libx264', 'libmp3lame', 'aac', 'h264_nvenc', 'h264_qsv', 'h264_amf')
# Windows 10/Server 2022 inbox libraries, never driver or redistributable DLLs.
SYSTEM_DLLS = set('''advapi32 avicap32 avrt bcrypt bcryptprimitives cabinet cfgmgr32
comctl32 comdlg32 crypt32 cryptbase cryptsp d2d1 d3d11 d3d12 d3d9 dbghelp dnsapi
dsound dwmapi dwrite dxgi gdi32 imm32 iphlpapi kernel32 ksuser mf mfplat mfreadwrite
mfuuid mpr msimg32 msvcrt ncrypt netapi32 normaliz ntdll ole32 oleaut32 opengl32
powrprof propsys psapi rpcrt4 secur32 setupapi shcore shell32 shlwapi user32 userenv
usp10 uxtheme version vfw32 winhttp wininet winmm winspool wintrust ws2_32 wtsapi32
wsock32 ucrtbase'''.split())


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def imports(path):
    """Read ordinary and delay-load import descriptors of an AMD64 PE32+ image."""
    data = Path(path).read_bytes()
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('Truncated PE: ' + str(path))
        return struct.unpack_from(fmt, data, offset)
    if data[:2] != b'MZ':
        raise ValueError('Not a PE image: ' + str(path))
    pe, = unpack('<I', 0x3c)
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Missing PE signature')
    machine, count = unpack('<HH', pe + 4)
    optional_size, = unpack('<H', pe + 20)
    optional = pe + 24
    magic, = unpack('<H', optional)
    if machine != 0x8664 or magic != 0x20b or optional_size < 112:
        raise ValueError('Expected AMD64 PE32+')
    base, = unpack('<Q', optional + 24)
    header_size, = unpack('<I', optional + 60)
    directories, = unpack('<I', optional + 108)
    sections = []
    for index in range(count):
        offset = optional + optional_size + index * 40
        virtual_size, rva, size, raw = unpack('<IIII', offset + 8)
        sections.append((rva, max(virtual_size, size), raw, size))
    def file_offset(rva, size):
        if 0 <= rva < header_size and rva + size <= min(header_size, len(data)):
            return rva
        for address, span, raw, available in sections:
            delta = rva - address
            if 0 <= delta < span and delta + size <= available and raw + delta + size <= len(data):
                return raw + delta
        raise ValueError('Unmapped PE RVA: ' + hex(rva))
    result = {'normal': [], 'delay': []}
    for index, kind, width in ((1, 'normal', 20), (13, 'delay', 32)):
        if directories <= index:
            continue
        if 112 + (index + 1) * 8 > optional_size:
            raise ValueError('Invalid PE directory count')
        rva, size = unpack('<II', optional + 112 + index * 8)
        if not rva and not size:
            continue
        if not rva or size < width:
            raise ValueError('Invalid import directory')
        terminated = False
        for delta in range(0, size - width + 1, width):
            descriptor = unpack('<' + 'I' * (width // 4), file_offset(rva + delta, width))
            if not any(descriptor):
                terminated = True
                break
            name_rva = descriptor[3] if kind == 'normal' else descriptor[1]
            if kind == 'delay' and not descriptor[0] & 1:
                name_rva -= base
            chars = []
            for n in range(260):
                char = data[file_offset(name_rva + n, 1)]
                if char == 0:
                    break
                chars.append(char)
            else:
                raise ValueError('Unterminated DLL name')
            name = bytes(chars).decode('ascii').lower()
            if not re.fullmatch(r'[a-z0-9_.+-]+\.dll', name):
                raise ValueError('Invalid imported DLL name: ' + name)
            result[kind].append(name)
        if not terminated:
            raise ValueError('Unterminated import table')
    return result


def system_dll(name):
    return name.removesuffix('.dll') in SYSTEM_DLLS or bool(
        re.fullmatch(r'(api|ext)-ms-win-[a-z0-9-]+-l\d+-\d+-\d+\.dll', name))


def gate(directory):
    """Only application-local DLLs and explicit Windows inbox libraries resolve."""
    directory = Path(directory)
    local = {p.name.lower(): p for p in directory.iterdir() if p.is_file()}
    report, errors = [], []
    for name, path in sorted(local.items()):
        if path.suffix.lower() not in ('.exe', '.dll'):
            continue
        table = imports(path)
        missing = sorted({dll for group in table.values() for dll in group
                          if not system_dll(dll) and dll not in local})
        row = {'file': name, 'bytes': path.stat().st_size, 'sha256': sha(path),
               'imports': table, 'missing': missing}
        report.append(row)
        errors.extend(name + ' -> ' + dll for dll in missing)
    if not report:
        raise ValueError('No PE images found')
    return {'files': report, 'errors': errors, 'passed': not errors}


def prepare(root):
    path = root / 'recipes/packages/ffmpeg.cmake'
    text = path.read_text(encoding='utf-8')
    assert text.count('--disable-ffprobe') == 1
    assert '--enable-nonfree' not in text and '--disable-programs' not in text
    assert '--enable-gpl' in text and '--enable-version3' in text
    text = text.replace('--disable-ffprobe', '--enable-ffprobe\n        --enable-static\n        --disable-shared')
    path.write_text(text, encoding='utf-8', newline='\n')


def package(root):
    prefix = root / 'build/install/x86_64-w64-mingw32/bin'
    mpv = root / 'build/mpv-0.41.0-x86_64'
    ffmpeg = root / 'build/ffmpeg-windows-x64'
    ffmpeg.mkdir()
    for name in ('ffmpeg.exe', 'ffprobe.exe'):
        shutil.copyfile(prefix / name, ffmpeg / name)
    license_path = root / 'src_packages/vulkan/LICENSE.txt'
    assert 'Apache License' in license_path.read_text(encoding='utf-8')
    # Bundle the built loader, never a DLL taken from the developer's machine.
    for destination in (mpv, ffmpeg):
        needs_loader = destination == mpv or any('vulkan-1.dll' in group
            for exe in destination.glob('*.exe') for group in imports(exe).values())
        if needs_loader:
            shutil.copyfile(prefix / 'vulkan-1.dll', destination / 'vulkan-1.dll')
            shutil.copyfile(license_path, destination / 'LICENSE.Vulkan-Loader.txt')
            for notice in ('NOTICE', 'NOTICE.txt'):
                source = license_path.parent / notice
                if source.is_file():
                    shutil.copyfile(source, destination / ('Vulkan-Loader.' + notice))
    shutil.copyfile(root / 'src_packages/ffmpeg/COPYING.GPLv3', ffmpeg / 'GPL-3.0.txt')
    config = list((root / 'build').glob('**/ffmpeg-build/config.h'))
    assert len(config) == 1, config
    flags = config[0].read_text(encoding='utf-8') + (config[0].parent / 'config_components.h').read_text(encoding='utf-8')
    for encoder in ENCODERS:
        assert f'#define CONFIG_{encoder.upper()}_ENCODER 1' in flags, encoder
    log = config[0].parent / 'ffbuild/config.log'
    assert '--enable-nonfree' not in log.read_text(encoding='utf-8')
    for source in (config[0], config[0].parent / 'config_components.h', log):
        shutil.copyfile(source, root / 'provenance' / ('ffmpeg-' + source.name))
    reports = {directory.name: gate(directory) for directory in (mpv, ffmpeg)}
    write_json(root / 'provenance/portable-imports.json', reports)
    forbidden = ('avcodec', 'avformat', 'avutil', 'avfilter', 'swresample', 'swscale', 'libgcc', 'libstdc++', 'libwinpthread')
    assert not any(dll.startswith(forbidden) for row in reports[ffmpeg.name]['files']
                   for group in row['imports'].values() for dll in group), 'FFmpeg must link its libraries statically'
    assert all(report['passed'] for report in reports.values()), reports


def finish(root, output):
    mpv = root / 'build/mpv-0.41.0-x86_64'
    ffmpeg = root / 'build/ffmpeg-windows-x64'
    note = ('Bundled vulkan-1.dll: Vulkan-Loader, Apache-2.0; see LICENSE.Vulkan-Loader.txt.\n'
            'Its exact source and license are in work/src_packages/vulkan in the shared source archive.\n')
    with (mpv / 'SOURCE.txt').open('a', encoding='utf-8') as stream:
        stream.write(note)
    url = ('https://github.com/' + os.environ['GITHUB_REPOSITORY'] + '/releases/tag/lingomaster-mpv-0.41.0-' + os.environ['GITHUB_RUN_ID'])
    (ffmpeg / 'SOURCE.txt').write_text('FFmpeg and linked components: GPL-3.0-or-later.\n'
        'Complete corresponding source, patches and workflow (same build as mpv): ' + url + '\n'
        'Use mpv-0.41.0-corresponding-source.tar.zst and SOURCE_RESTORE.txt at that release.\n'
        + (note if (ffmpeg / 'vulkan-1.dll').exists() else ''), encoding='utf-8')
    shutil.copyfile(root / 'provenance/portable-imports.json', output / 'portable-imports.json')
    with zipfile.ZipFile(output / 'ffmpeg-windows-x64.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(ffmpeg.iterdir()):
            archive.write(path, path.name)


def smoke(artifacts, output):
    assert os.name == 'nt', 'Run on a fresh windows-2022 hosted runner'
    output.mkdir(parents=True, exist_ok=True)
    system = Path(os.environ['SystemRoot']) / 'System32'
    loader = system / 'vulkan-1.dll'
    report = {'system32_vulkan_present': loader.is_file(), 'system32_vulkan_sha256': sha(loader) if loader.is_file() else None,
              'runner_image': os.environ.get('ImageOS'), 'runner_image_version': os.environ.get('ImageVersion'),
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'workflow_commit': os.environ.get('GITHUB_SHA'),
              'commands': [], 'passed': False}
    env = os.environ.copy()
    env['PATH'] = str(system) + os.pathsep + str(system.parent)
    for key in list(env):
        if key.startswith(('VK_', 'VULKAN_', 'FFMPEG_', 'MPV_')):
            del env[key]
    env['VK_LOADER_DEBUG'] = 'all'
    def run(name, args):
        try:
            process = subprocess.run([str(a) for a in args], cwd=output, env=env,
                capture_output=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            (output / (name + '.stdout.log')).write_bytes(exc.stdout or b'')
            (output / (name + '.stderr.log')).write_bytes(exc.stderr or b'')
            report['commands'].append({'name': name, 'argv': [str(a) for a in args], 'timeout_seconds': 120})
            raise
        (output / (name + '.stdout.log')).write_bytes(process.stdout)
        (output / (name + '.stderr.log')).write_bytes(process.stderr)
        report['commands'].append({'name': name, 'argv': [str(a) for a in args], 'returncode': process.returncode})
        assert process.returncode == 0, (name, process.returncode, process.stderr[-3000:])
        return process.stdout.decode('utf-8', errors='replace')
    try:
        for archive_name, folder in (('mpv-0.41.0-x86_64.zip', 'mpv'), ('ffmpeg-windows-x64.zip', 'ffmpeg')):
            with zipfile.ZipFile(artifacts / archive_name) as archive:
                for name in archive.namelist():
                    assert '\\' not in name and not name.startswith('/') and '..' not in Path(name).parts
                archive.extractall(output / folder)
            result = gate(output / folder)
            report[folder] = result
            assert result['passed'], result
        mpv = output / 'mpv/mpv.exe'
        ffmpeg = output / 'ffmpeg/ffmpeg.exe'
        ffprobe = output / 'ffmpeg/ffprobe.exe'
        assert (mpv.parent / 'vulkan-1.dll').is_file()
        run('mpv-version', [mpv, '--no-config', '--version'])
        version = run('ffmpeg-version', [ffmpeg, '-version'])
        assert '--enable-nonfree' not in version
        run('ffmpeg-hwaccels', [ffmpeg, '-hide_banner', '-hwaccels'])
        encoders = run('ffmpeg-encoders', [ffmpeg, '-hide_banner', '-encoders'])
        for encoder in ENCODERS:
            assert re.search(r'^\s*[A-Z.]{6}\s+' + re.escape(encoder) + r'\s', encoders, re.M), encoder
        fixture = output / 'fixture.mp4'
        run('encode-fixture', [ffmpeg, '-hide_banner', '-nostdin', '-y', '-f', 'lavfi', '-i', 'testsrc2=size=160x90:rate=10',
            '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=48000', '-t', '2', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', fixture])
        probe = json.loads(run('ffprobe', [ffprobe, '-v', 'error', '-show_streams', '-show_format', '-of', 'json', fixture]))
        assert {row['codec_name'] for row in probe['streams']} == {'h264', 'aac'}
        run('mp3-encode', [ffmpeg, '-hide_banner', '-nostdin', '-y', '-i', fixture, '-vn', '-c:a', 'libmp3lame', output / 'fixture.mp3'])
        run('mpv-null-decode', [mpv, '--no-config', '--vo=null', '--ao=null', '--hwdec=no', '--untimed', '--no-terminal', fixture])
        report['passed'] = True
    finally:
        write_json(output / 'smoke.json', report)
        files = sorted(p for p in output.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
        (output / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in files), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'package', 'finish', 'smoke'))
    parser.add_argument('--root', type=Path, default=Path('work'))
    parser.add_argument('--output', type=Path, default=Path('output'))
    args = parser.parse_args()
    if args.action == 'smoke':
        smoke(args.root.resolve(), args.output.resolve())
    elif args.action == 'finish':
        finish(args.root, args.output)
    else:
        globals()[args.action](args.root)
