find .github/workflows -type f -name "*.yml" -exec sed -i '' 's|export DYLD_LIBRARY_PATH="$IDADIR:$DYLD_LIBRARY_PATH"|export DYLD_LIBRARY_PATH="$IDADIR/Contents/MacOS:$DYLD_LIBRARY_PATH"|g' {} +
find .github/workflows -type f -name "*.yml" -exec sed -i '' 's|-- /bin/ls|-- /tmp/test_ls|g' {} +
find .github/workflows -type f -name "*.yml" -exec sed -i '' 's|echo "Running idalib_dump_port..."|cp /bin/ls /tmp/test_ls \&\& echo "Running idalib_dump_port..."|g' {} +
find .github/workflows -type f -name "*.yml" -exec sed -i '' 's|-- "C:\\Windows\\System32\\notepad.exe"|-- "C:\\test_notepad.exe"|g' {} +
find .github/workflows -type f -name "*.yml" -exec sed -i '' 's|echo "Running idalib_dump_port..."|cp "C:\\Windows\\System32\\notepad.exe" "C:\\test_notepad.exe" \&\& echo "Running idalib_dump_port..."|g' {} +
