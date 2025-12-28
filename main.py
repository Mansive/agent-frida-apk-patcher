import os
import shutil
import subprocess
import lief
import json
import xml.etree.ElementTree as ET
from pathlib import Path

# ================= SYSTEM CONFIGURATION =================
# Anchor all paths to the directory where this script is located
BASE_DIR = Path(__file__).resolve().parent

# ================= USER CONFIGURATION =================
# Use BASE_DIR to ensure these are always absolute
APK_FILE = BASE_DIR / "assets" / "Eden-28116-Android-Legacy.apk"
GADGET_FILE = BASE_DIR / "assets" / "frida-gadget-16.7.11-less-signals.so"
UNPACKED_DIR = BASE_DIR / "unpacked"
REPACKED_DIR = BASE_DIR / "repacked"
KEYSTORE_FILE = BASE_DIR / "assets" / "debug.keystore"

KEYSTORE_ALIAS = "mykey"
KEYSTORE_PASS = "password"

# Naming the gadget inside the APK (Clean name is better for linking)
INTERNAL_GADGET_NAME = "libfrida-gadget.so"
INTERNAL_CONFIG_NAME = "libfrida-gadget.config.so"

FRIDA_CONFIG = {
    "interaction": {
        "type": "listen",
        "address": "0.0.0.0",
        "port": 27042,
        "on_load": "resume",
    }
}
# =================================================


def run_command(cmd_list, shell=True):
    """
    Helper to run subprocess commands with proper path stringification.
    We convert all Path objects to strings before passing them.
    """
    # Convert all Path objects to strings
    cmd_str_list = [str(x) for x in cmd_list]

    # Print command for debugging (optional)
    # print(f"Running: {' '.join(cmd_str_list)}")

    subprocess.run(
        cmd_str_list,
        check=True,
        shell=shell,
        cwd=BASE_DIR,  # Force the working directory to be the script folder
    )


def check_tools():
    # On Windows via Scoop, these are often .cmd or .bat files.
    # We allow shell=True in run_command to handle the shim execution.
    required = ["apktool", "zipalign", "apksigner", "keytool"]
    for tool in required:
        if shutil.which(tool) is None:
            print(f"❌ Error: '{tool}' not found in PATH.")
            exit(1)

    if not APK_FILE.exists():
        print(f"❌ Error: APK not found at {APK_FILE}")
        exit(1)

    if not GADGET_FILE.exists():
        print(f"❌ Error: Gadget not found at {GADGET_FILE}")
        exit(1)

    # Ensure output dirs exist
    REPACKED_DIR.mkdir(exist_ok=True, parents=True)
    UNPACKED_DIR.mkdir(exist_ok=True, parents=True)

    print("✅ All tools and files found.")


def unpack_apk():
    print(f"📦 Unpacking {APK_FILE.name}...")
    if UNPACKED_DIR.exists():
        shutil.rmtree(UNPACKED_DIR)

    # We pass absolute paths converted to strings
    run_command(["apktool", "d", APK_FILE, "-o", UNPACKED_DIR, "-f", "-m"])


def inject_lief_and_files():
    lib_dir = UNPACKED_DIR / "lib"

    if not lib_dir.exists():
        print("❌ Error: No 'lib' folder found in unpacked APK.")
        exit(1)

    for arch_path in lib_dir.iterdir():
        if not arch_path.is_dir():
            continue

        print(f"🔧 Processing architecture: {arch_path.name}")

        # 1. Find target library
        so_files = list(arch_path.glob("*.so"))
        if not so_files:
            continue

        target_lib_path = None
        # Check for specific names first
        for candidate in ["libmain.so", "libnative-lib.so"]:
            if (arch_path / candidate).exists():
                target_lib_path = arch_path / candidate
                break

        # Fallback to largest file
        if not target_lib_path:
            target_lib_path = max(so_files, key=lambda p: p.stat().st_size)

        print(f"   -> Injecting into: {target_lib_path.name}")

        # 2. LIEF Injection
        # Note: LIEF expects a string path, not a Path object
        lib = lief.parse(str(target_lib_path))
        lib.add_library(INTERNAL_GADGET_NAME)
        lib.write(str(target_lib_path))

        # 3. Copy Frida Gadget
        # We rename it to the clean name defined in INTERNAL_GADGET_NAME
        dest_gadget = arch_path / INTERNAL_GADGET_NAME
        shutil.copy(GADGET_FILE, dest_gadget)
        print(f"   -> Gadget copied as {INTERNAL_GADGET_NAME}")

        # 4. Create Config
        config_path = arch_path / INTERNAL_CONFIG_NAME
        with open(config_path, "w") as f:
            json.dump(FRIDA_CONFIG, f, indent=2)
        print(f"   -> Config created as {INTERNAL_CONFIG_NAME}")


def fix_manifest():
    print("📝 Updating AndroidManifest.xml...")
    manifest_path = UNPACKED_DIR / "AndroidManifest.xml"

    ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    application = root.find("application")
    if application is None:
        print("❌ Error: <application> tag not found in Manifest.")
        return

    ns = "{http://schemas.android.com/apk/res/android}"
    attr_name = f"{ns}extractNativeLibs"
    curr_val = application.get(attr_name)

    if curr_val != "true":
        print(f"   -> Changing extractNativeLibs from '{curr_val}' to 'true'")
        application.set(attr_name, "true")
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
    else:
        print("   -> extractNativeLibs is already true.")


def repack_sign_align():
    repacked_apk = REPACKED_DIR / "repacked.apk"
    repacked_aligned_apk = REPACKED_DIR / "repacked-aligned.apk"

    print("🏗️ Repacking APK...")
    run_command(["apktool", "b", UNPACKED_DIR, "-o", repacked_apk, "-f"])

    print("📐 Zipaligning...")
    if repacked_aligned_apk.exists():
        os.remove(repacked_aligned_apk)

    run_command(["zipalign", "-p", "-v", "4", repacked_apk, repacked_aligned_apk])

    if not KEYSTORE_FILE.exists():
        print("🔑 Generating debug keystore...")
        # Ensure the parent directory for keystore exists
        KEYSTORE_FILE.parent.mkdir(parents=True, exist_ok=True)
        run_command(
            [
                "keytool",
                "-genkey",
                "-v",
                "-keystore",
                KEYSTORE_FILE,
                "-alias",
                KEYSTORE_ALIAS,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-storepass",
                KEYSTORE_PASS,
                "-keypass",
                KEYSTORE_PASS,
                "-dname",
                "CN=Frida, OU=Debug, O=Hack, L=Nowhere, ST=NA, C=US",
            ]
        )

    print("✍️ Signing APK...")
    run_command(
        [
            "apksigner",
            "sign",
            "--ks",
            KEYSTORE_FILE,
            "--ks-pass",
            f"pass:{KEYSTORE_PASS}",
            repacked_aligned_apk,
        ]
    )

    print(f"\n✅ SUCCESS! Output file: {repacked_aligned_apk}")


if __name__ == "__main__":
    check_tools()
    unpack_apk()
    inject_lief_and_files()
    fix_manifest()
    repack_sign_align()
