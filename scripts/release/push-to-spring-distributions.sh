#!/bin/bash

BUILD_NUMBER=$1
ENCRYPTED_ARTIFACTORY_PWD=$2
export ARTIFACTORY_BUILD_API_URL=https://repo.spring.io/api/build/distribute/Spring%20Security%20-%204.2.x%20-%20Default%20Job/$BUILD_NUMBER
curl -i -u buildmaster:$ENCRYPTED_ARTIFACTORY_PWD -XPOST $ARTIFACTORY_BUILD_API_URL -H "Content-Type: application/json" -d '{"sourceRepos": ["libs-release-local"], "targetRepo": "spring-distributions"}'
