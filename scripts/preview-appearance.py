#!/usr/bin/env python3
"""Capture actual SwiftUI windows using inert providers and private storage.

Requires an existing unsigned or signed Release build in build/ParityDerivedData.
The production entry point is excluded. No production GUI, daemon, subscription
transport, autostart service or network provider is started.
"""

import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    products = root / "build/ParityDerivedData/Build/Products/Release"
    output = root / "build/appearance-preview"
    output.mkdir(parents=True, exist_ok=True)
    objects = [products / f"{name}.o" for name in ("ZarpCore", "ZarpdIPC", "ZarpSubscriptions")]
    if not all(path.exists() for path in objects):
        raise SystemExit("Build the Release scheme with -derivedDataPath build/ParityDerivedData first.")
    sources = sorted(path for path in (root / "App/Sources/Zarp").rglob("*.swift") if path.name != "ZarpApp.swift")
    bundle = output / "AppearancePreview.app/Contents"
    (bundle / "MacOS").mkdir(parents=True, exist_ok=True)
    executable = bundle / "MacOS/AppearancePreview"
    with (bundle / "Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleName": "Zarp Appearance Preview", "CFBundleExecutable": "AppearancePreview",
                      "CFBundleIdentifier": "io.github.zarp.appearance-preview", "CFBundlePackageType": "APPL",
                      "CFBundleVersion": "1", "LSMinimumSystemVersion": "14.0",
                      "NSPrincipalClass": "NSApplication", "NSHighResolutionCapable": True}, stream)
    command = ["xcrun", "swiftc", "-swift-version", "5", "-target", "arm64-apple-macos14.0",
               "-D", "ZARP_APPEARANCE_PREVIEW", "-I", str(products),
               "-module-cache-path", str(output / "ModuleCache"), "-o", str(executable)]
    command.extend(str(path) for path in sources)
    command.append(str(root / "scripts/appearance-preview/PreviewApp.swift"))
    command.extend(str(path) for path in objects)
    subprocess.run(command, cwd=root, check=True, timeout=120)
    # A new GUI bundle has its own Documents privacy permissions. Keep all runtime
    # inputs and outputs in temporary storage to avoid a macOS access prompt.
    with tempfile.TemporaryDirectory(prefix="zarp-appearance-") as temporary:
        runtime = pathlib.Path(temporary)
        shutil.copytree(root / "Resources/Lang", runtime / "Lang")
        subprocess.run(["open", "-W", "-n", str(bundle.parent), "--args", str(runtime), str(runtime / "Lang")],
                       cwd=root, check=True, timeout=30)
        for path in runtime.iterdir():
            if path.is_file():
                shutil.copy2(path, output / path.name)
        if not (runtime / "report.json").exists():
            failure = runtime / "preview-failure.txt"
            raise SystemExit(failure.read_text() if failure.exists() else "Preview exited before producing a report.")
    print(f"Preview screenshots and report: {output}")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.SubprocessError, OSError) as error:
        print(f"Appearance preview failed: {error}", file=sys.stderr)
        sys.exit(1)
