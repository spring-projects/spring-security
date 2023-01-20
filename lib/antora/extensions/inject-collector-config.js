'use strict'

const BASE_COMMAND = 'gradlew -PbuildSrc.skipTests=true --scan --stacktrace'
const JVM_ARGS='-Xmx3g -XX:+HeapDumpOnOutOfMemoryError'
const REPO_URL = 'https://github.com/spring-projects/spring-security'
const TASK_NAME=':spring-security-docs:generateAntora'

module.exports.register = function () {
  this.once('contentAggregated', ({ contentAggregate }) => {
    for (const { origins } of contentAggregate) {
      for (const origin of origins) {
        if (origin.url === REPO_URL && origin.descriptor.ext?.collector === undefined) {
          origin.descriptor.ext = {
            collector: {
              run: {
                command: `${BASE_COMMAND} "-Dorg.gradle.jvmargs=${JVM_ARGS}" ${TASK_NAME}`,
                local: true,
              },
              scan: {
                dir: './build/generateAntora',
              },
            }
          }
        }
      }
    }
  })
}
