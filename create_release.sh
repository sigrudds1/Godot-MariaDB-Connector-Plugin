#!/bin/bash

# Check if a version argument is provided
if [[ -z "$1" ]]; then
    echo "❌ Error: No version number provided."
    echo "Usage: $0 <version>"
    exit 1
fi

VERSION="$1"

# Step 1: Define expected tags
PLATFORMS=("linux" "windows")
ARCHS=("x86_64" "arm64")
TARGETS=("debug" "release")

# Define output folder
OUTPUT_DIR="release_zips"
LIBS_DIR="demo/libs"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Step 2: Check if any ZIP file already exists, exit immediately if true
for PLATFORM in "${PLATFORMS[@]}"; do
    for ARCH in "${ARCHS[@]}"; do
        ZIP_NAME="${OUTPUT_DIR}/MariaDBConnector-${PLATFORM}-${ARCH}-v${VERSION}.zip"
        if [[ -f "$ZIP_NAME" ]]; then
            echo "❌ ERROR: ZIP file $ZIP_NAME already exists! Exiting to prevent overwrites."
            exit 1
        fi
    done
done

echo "✅ No existing ZIPs found. Proceeding with packaging..."

# Step 3: Iterate through libs folder and detect platform/arch/target from filenames
for FILE in "$LIBS_DIR"/lib_mariadb_connector.*; do
    [[ -e "$FILE" ]] || continue  # Skip if no matching files

    # Extract filename
    FILENAME=$(basename "$FILE")

    DETECTED_PLATFORM=""
    DETECTED_ARCH=""
    DETECTED_TARGET=""

    # Match platform, arch, and target based on filename
    for PLATFORM in "${PLATFORMS[@]}"; do
        [[ "$FILENAME" == *"$PLATFORM"* ]] && DETECTED_PLATFORM="$PLATFORM"
    done

    for ARCH in "${ARCHS[@]}"; do
        [[ "$FILENAME" == *"$ARCH"* ]] && DETECTED_ARCH="$ARCH"
    done

    for TARGET in "${TARGETS[@]}"; do
        [[ "$FILENAME" == *"$TARGET"* ]] && DETECTED_TARGET="$TARGET"
    done

    # Ensure all three components were detected
    if [[ -z "$DETECTED_PLATFORM" || -z "$DETECTED_ARCH" || -z "$DETECTED_TARGET" ]]; then
        echo "⚠️  Skipping unknown file: $FILENAME"
        continue
    fi

    # Step 4: We have all 3 matches (Platform, Arch, Target)

    # Step 5: Check if ZIP already exists
    ZIP_NAME="${OUTPUT_DIR}/MariaDBConnector-${DETECTED_PLATFORM}-${DETECTED_ARCH}-v${VERSION}.zip"

    if [[ ! -f "$ZIP_NAME" ]]; then
        # If ZIP does not exist, create it while excluding all `libs/` files **except `.gdextension`**
        echo "📦 Creating new ZIP: $ZIP_NAME"
        zip -r "$ZIP_NAME" "demo/" -x "demo/libs/lib_mariadb_connector.*"
    fi

	zip -u "$ZIP_NAME" "$FILE" "$LIBS_DIR/$(basename "$FILE")"

done

echo "🎉 Release ZIPs successfully created in $OUTPUT_DIR/ for version v${VERSION}."
