#!/bin/bash
rm -f build/updates.txt
./gradlew dependencyUpdate -Drevision=release
find . -name report.txt | xargs cat > build/updates.txt
echo "Updates...."
cat build/updates.txt | fgrep ' ->' | sort | uniq
