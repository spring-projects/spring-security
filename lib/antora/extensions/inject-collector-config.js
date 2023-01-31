'use strict'

const BASE_COMMAND = 'gradlew -PbuildSrc.skipTests=true -Porg.gradle.java.installations.auto-detect=false --scan --stacktrace'
const JVM_ARGS='-Xmx3g -XX:+HeapDumpOnOutOfMemoryError'
const REPO_URL = 'https://github.com/spring-projects/spring-security'
const TASK_NAME=':spring-security-docs:generateAntora'

/**
 * Set of tags that contain a collector config, but the antora command fails on GitHub Actions.
 */
const VERSIONS_TO_OVERRIDE = [
  '6.0.0-RC1'
]

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
        if (origin.url !== REPO_URL) {
          continue
        }
        // Ignore tags with their own collector config unless the antora command fails on GitHub Actions
        if (!(origin.descriptor.ext?.collector === undefined || VERSIONS_TO_OVERRIDE.includes(origin.tag))) {
          continue
        }
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
