'use strict'

const GRADLE_ARGS = '-q -PbuildSrc.skipTests=true'
const JVM_ARGS='-Xmx3g -XX:+HeapDumpOnOutOfMemoryError'
const TASK_NAME=':spring-security-docs:generateAntora'

module.exports.register = function () {
  this.once('contentAggregated', ({ playbook, contentAggregate }) => {
    const gradle = playbook.env.GRADLE || 'gradle'
    const repositoryUrl = playbook.env.BUILD_REPOSITORY
      ? playbook.env.BUILD_REPOSITORY
      : playbook.env.GITHUB_REPOSITORY
        ? `${playbook.env.GITHUB_SERVER_URL}/${playbook.env.GITHUB_REPOSITORY}`
        : require('child_process').execSync('git remote get-url origin').toString().trimEnd()
    for (const { origins } of contentAggregate) {
      for (const origin of origins) {
        if (origin.url !== repositoryUrl) continue
        let collector, run
        if ((collector = origin.descriptor.ext?.collector) === undefined) {
          origin.descriptor.ext = {
            collector: {
              run: { command: `${gradle} ${GRADLE_ARGS} "-Dorg.gradle.jvmargs=${JVM_ARGS}" ${TASK_NAME}` },
              scan: { dir: './build/generateAntora' },
            }
          }
        } else if ((run = collector.run) && run.command?.startsWith('gradlew ')) {
          Object.assign(run, { command: `${gradle} ${run.command.slice(8)}`, local: false })
        }
      }
    }
  })
}
