'use strict'

const BASE_COMMAND = 'gradlew -q -PbuildSrc.skipTests=true'
const JVM_ARGS='-Xmx3g -XX:+HeapDumpOnOutOfMemoryError'
const REPO_URL = 'https://github.com/spring-projects/spring-security'
const TASK_NAME=':spring-security-docs:generateAntora'

/**
 * The purpose of this extension is to inject the Antora Collector configuration into the parsed component version
 * descriptor in tags created before Antora Collector was introduced. Antora Collector runs a command to generate a
 * replacement antora.yml that a) sets the version from the value of the version property in gradle.properties and b)
 * populates AsciiDoc attributes with information from the Gradle build, such as software versions and resource URLs.
 */
module.exports.register = function () {
  this.once('contentAggregated', ({ contentAggregate }) => {
    for (const { origins } of contentAggregate) {
      for (const origin of origins) {
        if (!(origin.url === REPO_URL && origin.descriptor.ext?.collector === undefined)) continue
        origin.descriptor.ext = {
          collector: {
            run: { command: `${BASE_COMMAND} "-Dorg.gradle.jvmargs=${JVM_ARGS}" ${TASK_NAME}`, local: true },
            scan: { dir: './build/generateAntora' },
          }
        }
      }
    }
  })
}
