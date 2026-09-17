"""Build ffmpeg from the already published mpv source closure; no Git refresh."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

BASE_URL = "https://download.lingomaster.io/tools/mpv-ipc/0.41.0-35124922360/"
SOURCE_NAME = "mpv-0.41.0-corresponding-source.tar.zst"
SOURCE_SHA = "1945ba456cac3c813637f119ed5356a8217d407974567f0811777852f3104f9c"
MANIFEST_SHA = "73233935328e7c2243210427d96d53cc1ec3e9169fb80a166ae09296cf7c31bf"
RECIPE = "cd1edc11dc6887a50f705717619d879f5a93a488"
FFMPEG_COMMIT = "9cf34b031f489dcecad5c579d0a22a956918cf36"
ENCODERS = ("libx264", "libmp3lame", "aac", "h264_nvenc", "h264_qsv", "h264_amf")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def verify(root, files=True):
    assert sha(root / "versions.json") == MANIFEST_SHA
    manifest = json.loads((root / "versions.json").read_text(encoding="utf-8"))
    assert manifest["recipe_commit"] == RECIPE
    for row in manifest["git"]:
        assert git(root / row["path"], "rev-parse", "HEAD") == row["commit"], row["path"]
    assert git(root / "src_packages/ffmpeg", "rev-parse", "HEAD") == FFMPEG_COMMIT
    if files:
        for row in manifest["files"]:
            assert sha(root / row["path"]) == row["sha256"], row["path"]
    return manifest


def patch_external_project(text, guard):
    marker = "  _ep_add_download_command(${name})"
    assert text.count(marker) == 1
    return text.replace(marker, '''  # Restored Git trees already contain the exact reviewed patches.
  get_property(lm_git TARGET ${name} PROPERTY _EP_GIT_REPOSITORY)
  if(lm_git)
    get_property(lm_source TARGET ${name} PROPERTY _EP_SOURCE_DIR)
    set_property(TARGET ${name} PROPERTY _EP_DOWNLOAD_COMMAND
      "${CMAKE_COMMAND}" "-DSOURCE_DIR=${lm_source}" "-P" "''' + str(guard).replace("\\", "/") + '''")
    set_property(TARGET ${name} PROPERTY _EP_UPDATE_COMMAND "")
    set_property(TARGET ${name} PROPERTY _EP_PATCH_COMMAND "")
    # CMake 3.31's shared step generators read caller variables.
    get_property(_EP_DOWNLOAD_COMMAND TARGET ${name} PROPERTY _EP_DOWNLOAD_COMMAND)
    set(_EP_UPDATE_COMMAND "")
    set(_EP_PATCH_COMMAND "")
  endif()
''' + marker)


def prepare(root, module):
    manifest = verify(root)
    recipes = root / "recipes"
    path = recipes / "packages/ffmpeg.cmake"
    text = path.read_text(encoding="utf-8")
    assert text.count("--disable-ffprobe") == 1
    assert "--enable-nonfree" not in text
    text = text.replace("--disable-ffprobe", "--enable-ffprobe\n        --enable-static\n        --disable-shared")
    path.write_text(text, encoding="utf-8", newline="\n")
    guard = recipes / "cmake/require_restored_source.cmake"
    guard.write_text('if(NOT EXISTS "${SOURCE_DIR}/.git")\n'
        '  message(FATAL_ERROR "Missing restored Git source: ${SOURCE_DIR}")\n'
        'endif()\n', encoding="utf-8", newline="\n")
    module.write_text(patch_external_project(module.read_text(encoding="utf-8"), guard.resolve()),
                      encoding="utf-8", newline="\n")
    provenance = root / "ffmpeg-provenance"
    provenance.mkdir(exist_ok=True)
    write_json(provenance / "source-input.json", {
        "source_url": BASE_URL + SOURCE_NAME, "source_sha256": SOURCE_SHA,
        "versions_sha256": MANIFEST_SHA, "recipe_commit": RECIPE,
        "ffmpeg_commit": FFMPEG_COMMIT, "git_trees_verified": len(manifest["git"]),
        "source_files_verified": len(manifest["files"]), "git_refresh_disabled": True})


def package(root, output):
    manifest = verify(root, files=False)
    output.mkdir(exist_ok=True)
    bundle_dir = output / "ffmpeg-windows-x64"
    bundle_dir.mkdir(exist_ok=True)
    prefix = root / "build/install/x86_64-w64-mingw32/bin"
    objdump = root / "build/install/bin/x86_64-w64-mingw32-objdump"
    binaries = []
    for name in ("ffmpeg.exe", "ffprobe.exe"):
        source = prefix / name
        assert source.is_file(), source
        imports = subprocess.check_output([str(objdump), "-p", str(source)], text=True)
        dlls = [line.split(":", 1)[1].strip() for line in imports.splitlines() if "DLL Name:" in line]
        forbidden = ("avcodec", "avformat", "avutil", "avfilter", "swresample", "swscale", "libgcc", "libstdc++", "libwinpthread")
        assert not any(dll.lower().startswith(forbidden) for dll in dlls), dlls
        shutil.copyfile(source, bundle_dir / name)
        binaries.append({"name": name, "bytes": source.stat().st_size, "sha256": sha(source), "imports": dlls})
    candidates = list((root / "build").glob("**/ffmpeg-build/config.h"))
    assert len(candidates) == 1, candidates
    flags = candidates[0].read_text(encoding="utf-8") + (candidates[0].parent / "config_components.h").read_text(encoding="utf-8")
    for encoder in ENCODERS:
        assert f"#define CONFIG_{encoder.upper()}_ENCODER 1" in flags, encoder
    configure = candidates[0].parent / "ffbuild/config.log"
    assert "--enable-nonfree" not in configure.read_text(encoding="utf-8")
    license_path = root / "src_packages/ffmpeg/COPYING.GPLv3"
    shutil.copyfile(license_path, bundle_dir / "GPL-3.0.txt")
    provenance = root / "ffmpeg-provenance"
    shutil.copyfile(configure, provenance / "ffmpeg-config.log")
    shutil.copyfile(candidates[0], provenance / "ffmpeg-config.h")
    shutil.copyfile(candidates[0].parent / "config_components.h", provenance / "ffmpeg-config_components.h")
    write_json(provenance / "binaries.json", binaries)
    (provenance / "recipe.patch").write_text(git(root / "recipes", "diff", "--binary", "HEAD") + "\n", encoding="utf-8")
    # The small supplement contains the changed recipe and actual source deltas.
    # The original 1 GB closure stays at its existing immutable public URL.
    supplement = output / "ffmpeg-source-supplement.tar.gz"
    changed = []
    with tarfile.open(supplement, "w:gz") as archive:
        archive.add(root / "recipes", arcname="work/recipes", filter=lambda row: None if ".git" in Path(row.name).parts else row)
        archive.add(provenance, arcname="work/ffmpeg-provenance")
        for row in manifest["files"]:
            path = root / row["path"]
            if row["path"].startswith("src_packages/") and path.is_file() and not path.is_symlink() and sha(path) != row["sha256"]:
                archive.add(path, arcname="work/" + row["path"])
                changed.append({"path": row["path"], "sha256": sha(path)})
    source = json.loads((provenance / "source-input.json").read_text(encoding="utf-8"))
    source.update({"source_supplement": supplement.name, "supplement_sha256": sha(supplement),
                   "supplement_url": "https://github.com/" + os.environ["GITHUB_REPOSITORY"]
                       + "/releases/download/lingomaster-ffmpeg-" + os.environ["GITHUB_RUN_ID"] + "/" + supplement.name,
                   "changed_source_files": changed, "binaries": binaries,
                   "run_id": os.environ["GITHUB_RUN_ID"], "workflow_commit": os.environ["GITHUB_SHA"]})
    write_json(output / "SOURCE.json", source)
    shutil.copyfile(output / "SOURCE.json", bundle_dir / "SOURCE.json")
    instructions = ("FFmpeg and linked components: GPL-3.0-or-later. Independent subprocess only.\n"
        "Download and verify the shared complete source archive:\n" + BASE_URL + SOURCE_NAME + "\nSHA256: " + SOURCE_SHA + "\n"
        "Then extract ffmpeg-source-supplement.tar.gz over it on Linux (preserve symlinks).\n"
        "Build instructions and preparation script: work/ffmpeg-provenance/.\n"
        "The supplement includes changed recipes, source deltas, configuration and binary hashes.\n")
    (output / "SOURCE_RESTORE.txt").write_text(instructions, encoding="utf-8")
    shutil.copyfile(output / "SOURCE_RESTORE.txt", bundle_dir / "SOURCE.txt")
    shutil.copyfile(license_path, output / "GPL-3.0.txt")
    zip_path = output / "ffmpeg-windows-x64.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(bundle_dir.iterdir()):
            archive.write(path, path.name)
    files = [p for p in sorted(output.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (output / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n" for p in files), encoding="utf-8")
    print(json.dumps({"binaries": binaries, "changed_source_files": len(changed)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "package"))
    parser.add_argument("--root", type=Path, default=Path("work"))
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", type=Path, default=Path("output"))
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.root, args.module)
    else:
        package(args.root, args.output)
