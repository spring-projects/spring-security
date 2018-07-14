#!/bin/bash

./gradlew jar
mkdir -p build/s101 && cd $_
rm *.jar
find ../../ -name '*-SNAPSHOT.jar' | grep -v samples | grep -v itest | xargs -I{} cp {} .
