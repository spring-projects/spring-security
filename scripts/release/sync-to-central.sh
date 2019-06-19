#!/bin/bash

RELEASE_VERSION=$1
BINTRAY_API_KEY=$2
SONATYPE_USER_TOKEN=$3
SONATYPE_USER_TOKEN_PWD=$4
curl -i -u spring-operator:$BINTRAY_API_KEY -XPOST "https://api.bintray.com/maven_central_sync/spring/jars/org.springframework.security/versions/$RELEASE_VERSION" -H "Content-Type: application/json" -d "{\"username\": \"$SONATYPE_USER_TOKEN\", \"password\": \"$SONATYPE_USER_TOKEN_PWD\"}"
