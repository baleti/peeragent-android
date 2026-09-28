#!/usr/bin/env bash
# No Gradle: aapt2 -> kotlinc -> d8 -> apksigner, invoked directly. Works
# from Termux (where these ship as plain packages) or a normal Linux shell
# with the Android SDK command-line build-tools installed - override the
# paths below via environment variables for your own layout, e.g.:
#   ANDROID_JAR=/opt/android-sdk/platforms/android-34/android.jar \
#   KOTLIN_STDLIB=/usr/share/kotlin/lib/kotlin-stdlib.jar \
#   bash build.sh
set -e
cd "$(dirname "$0")"

ANDROID_JAR="${ANDROID_JAR:-$HOME/mediabridge/sdk/platform37/android-37.1/android.jar}"
# Must be the base kotlin-stdlib.jar (~750KB, holds kotlin.jvm.internal.Intrinsics
# and friends) - NOT kotlin-stdlib-jdk7.jar/-jdk8.jar, which are ~1KB extension
# wrappers that silently dexed fine but omitted Intrinsics, crash-looping
# every Kotlin method's auto-injected null-check with NoClassDefFoundError.
# See docs/design.md for how much time that cost to track down.
KOTLIN_STDLIB="${KOTLIN_STDLIB:-$PREFIX/opt/kotlin/lib/kotlin-stdlib.jar}"
AAPT2="${AAPT2:-aapt2}"
KOTLINC="${KOTLINC:-kotlinc}"
D8="${D8:-d8}"
APKSIGNER="${APKSIGNER:-apksigner}"

echo "android.jar: $ANDROID_JAR"
echo "kotlin-stdlib: $KOTLIN_STDLIB"

rm -rf build
mkdir -p build/classes build/dex

RES_ARGS=()
if [ -d res ]; then
  echo "=== aapt2 compile (res/) ==="
  "$AAPT2" compile -o build/compiled-res.zip --dir res
  RES_ARGS=(-R build/compiled-res.zip)
fi

echo "=== aapt2 link ==="
# --auto-add-overlay: aapt2 treats -R inputs as overlays onto an (empty,
# there being no separate base here) resource table, and without this
# flag rejects any *value* resource (colors.xml etc, as opposed to a
# file-based one like a mipmap PNG/XML) that isn't already present in an
# earlier -R input as "does not override an existing resource" -- broke
# the very first build after res/values/colors.xml was added for the
# adaptive launcher icon.
"$AAPT2" link -o build/base.apk \
  -I "$ANDROID_JAR" \
  --manifest AndroidManifest.xml \
  --min-sdk-version 29 --target-sdk-version 34 \
  --auto-add-overlay \
  "${RES_ARGS[@]}"

echo "=== kotlinc ==="
"$KOTLINC" -cp "$ANDROID_JAR" -d build/classes $(find src -name "*.kt")

echo "=== d8 (app classes + kotlin-stdlib) ==="
cd build
"$D8" --output dex --min-api 29 $(find classes -name "*.class") "$KOTLIN_STDLIB"

echo "=== assemble signed apk ==="
cp base.apk peeragent-unsigned.apk
cd dex
zip -qr ../peeragent-unsigned.apk classes.dex
cd ..

if [ ! -f ../debug.keystore ]; then
  keytool -genkeypair -v -keystore ../debug.keystore \
    -storepass android -keypass android -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=PeerAgent Companion Debug,O=local,C=US"
fi

"$APKSIGNER" sign --ks ../debug.keystore --ks-pass pass:android \
  --key-pass pass:android \
  --out peeragent-signed.apk peeragent-unsigned.apk

echo "=== BUILD_OK ==="
ls -la peeragent-signed.apk
