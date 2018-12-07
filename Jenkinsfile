def projectProperties = [
	[$class: 'BuildDiscarderProperty',
		strategy: [$class: 'LogRotator', numToKeepStr: '5']],
	pipelineTriggers([cron('@daily')])
]
properties(projectProperties)

def SUCCESS = hudson.model.Result.SUCCESS.toString()
currentBuild.result = SUCCESS

try {
	parallel check: {
		stage('Check') {
			node {
				checkout scm
				try {
					sh "./gradlew clean check  --refresh-dependencies --no-daemon --stacktrace"
				} catch(Exception e) {
					currentBuild.result = 'FAILED: check'
					throw e
				} finally {
					junit '**/build/test-results/*/*.xml'
				}
			}
		}
	},
	sonar: {
		stage('Sonar') {
			node {
				checkout scm
				withCredentials([string(credentialsId: 'spring-sonar.login', variable: 'SONAR_LOGIN')]) {
					try {
						if ("master" == env.BRANCH_NAME) {
							sh "./gradlew sonarqube -PexcludeProjects='**/samples/**' -Dsonar.host.url=$SPRING_SONAR_HOST_URL -Dsonar.login=$SONAR_LOGIN --refresh-dependencies --no-daemon --stacktrace"
						} else {
							sh "./gradlew sonarqube -PexcludeProjects='**/samples/**' -Dsonar.projectKey='spring-security-${env.BRANCH_NAME}' -Dsonar.projectName='spring-security-${env.BRANCH_NAME}' -Dsonar.host.url=$SPRING_SONAR_HOST_URL -Dsonar.login=$SONAR_LOGIN --refresh-dependencies --no-daemon --stacktrace"
						}
					} catch(Exception e) {
						currentBuild.result = 'FAILED: sonar'
						throw e
					}
				}
			}
		}
	},
	snapshots: {
		stage('Snapshot Tests') {
			node {
				checkout scm
				try {
					sh "./gradlew clean test -PforceMavenRepositories=snapshot -PspringVersion='5.+' -PreactorVersion=Californium-BUILD-SNAPSHOT -PspringDataVersion=Lovelace-BUILD-SNAPSHOT --refresh-dependencies --no-daemon --stacktrace"
				} catch(Exception e) {
					currentBuild.result = 'FAILED: snapshots'
					throw e
				}
			}
		}
	},
	jdk9: {
		stage('JDK 9') {
			node {
				checkout scm
				try {
					withEnv(["JAVA_HOME=${ tool 'jdk9' }"]) {
						sh "./gradlew clean test --refresh-dependencies --no-daemon --stacktrace"
					}
				} catch(Exception e) {
					currentBuild.result = 'FAILED: jdk9'
					throw e
				}
			}
		}
	},
	jdk10: {
		stage('JDK 10') {
			node {
				checkout scm
				try {
					withEnv(["JAVA_HOME=${ tool 'jdk10' }"]) {
						sh "./gradlew clean test --refresh-dependencies --no-daemon --stacktrace"
					}
				} catch(Exception e) {
					currentBuild.result = 'FAILED: jdk10'
					throw e
				}
			}
		}
	},
	jdk11: {
		stage('JDK 11') {
			node {
				checkout scm
				try {
					withEnv(["JAVA_HOME=${ tool 'jdk11' }"]) {
						sh "./gradlew clean test --refresh-dependencies --no-daemon --stacktrace"
					}
				} catch(Exception e) {
					currentBuild.result = 'FAILED: jdk11'
					throw e
				}
			}
		}
	}

	if(currentBuild.result == 'SUCCESS') {
		parallel artifacts: {
			stage('Deploy Artifacts') {
				node {
					checkout scm
					withCredentials([file(credentialsId: 'spring-signing-secring.gpg', variable: 'SIGNING_KEYRING_FILE')]) {
						withCredentials([string(credentialsId: 'spring-gpg-passphrase', variable: 'SIGNING_PASSWORD')]) {
							withCredentials([usernamePassword(credentialsId: 'oss-token', passwordVariable: 'OSSRH_PASSWORD', usernameVariable: 'OSSRH_USERNAME')]) {
								withCredentials([usernamePassword(credentialsId: '02bd1690-b54f-4c9f-819d-a77cb7a9822c', usernameVariable: 'ARTIFACTORY_USERNAME', passwordVariable: 'ARTIFACTORY_PASSWORD')]) {
									sh "./gradlew deployArtifacts finalizeDeployArtifacts -Psigning.secretKeyRingFile=$SIGNING_KEYRING_FILE -Psigning.keyId=$SPRING_SIGNING_KEYID -Psigning.password='$SIGNING_PASSWORD' -PossrhUsername=$OSSRH_USERNAME -PossrhPassword=$OSSRH_PASSWORD -PartifactoryUsername=$ARTIFACTORY_USERNAME -PartifactoryPassword=$ARTIFACTORY_PASSWORD --refresh-dependencies --no-daemon --stacktrace"
								}
							}
						}
					}
				}
			}
		},
		docs: {
			stage('Deploy Docs') {
				node {
					checkout scm
					withCredentials([file(credentialsId: 'docs.spring.io-jenkins_private_ssh_key', variable: 'DEPLOY_SSH_KEY')]) {
						sh "./gradlew deployDocs -PdeployDocsSshKeyPath=$DEPLOY_SSH_KEY -PdeployDocsSshUsername=$SPRING_DOCS_USERNAME --refresh-dependencies --no-daemon --stacktrace"
					}
				}
			}
		},
		schema: {
			stage('Deploy Schema') {
				node {
					checkout scm
					withCredentials([file(credentialsId: 'docs.spring.io-jenkins_private_ssh_key', variable: 'DEPLOY_SSH_KEY')]) {
						sh "./gradlew deploySchema -PdeployDocsSshKeyPath=$DEPLOY_SSH_KEY -PdeployDocsSshUsername=$SPRING_DOCS_USERNAME --refresh-dependencies --no-daemon --stacktrace"
					}
				}
			}
		}
	}
} catch(Exception e) {
	currentBuild.result = 'FAILED: deploys'
	throw e
} finally {
	def buildStatus = currentBuild.result
	def buildNotSuccess =  !SUCCESS.equals(buildStatus)
	def lastBuildNotSuccess = !SUCCESS.equals(currentBuild.previousBuild?.result)

	if(buildNotSuccess || lastBuildNotSuccess) {

		stage('Notifiy') {
			node {
				final def RECIPIENTS = [[$class: 'DevelopersRecipientProvider'], [$class: 'RequesterRecipientProvider']]

				def subject = "${buildStatus}: Build ${env.JOB_NAME} ${env.BUILD_NUMBER} status is now ${buildStatus}"
				def details = """The build status changed to ${buildStatus}. For details see ${env.BUILD_URL}"""

				emailext (
					subject: subject,
					body: details,
					recipientProviders: RECIPIENTS,
					to: "$SPRING_SECURITY_TEAM_EMAILS"
				)
			}
		}
	}
}
