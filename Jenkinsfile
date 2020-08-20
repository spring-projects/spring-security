def projectProperties = [
	[$class: 'BuildDiscarderProperty',
		strategy: [$class: 'LogRotator', numToKeepStr: '5']],
	pipelineTriggers([cron('@daily')])
]
properties(projectProperties)

def SUCCESS = hudson.model.Result.SUCCESS.toString()
currentBuild.result = SUCCESS

def GRADLE_ENTERPRISE_CACHE_USER = usernamePassword(credentialsId: 'gradle_enterprise_cache_user',
		passwordVariable: 'GRADLE_ENTERPRISE_CACHE_PASSWORD',
		usernameVariable: 'GRADLE_ENTERPRISE_CACHE_USERNAME')
def GRADLE_ENTERPRISE_SECRET_ACCESS_KEY = string(credentialsId: 'gradle_enterprise_secret_access_key',
		variable: 'GRADLE_ENTERPRISE_ACCESS_KEY')
def SPRING_SIGNING_SECRING = file(credentialsId: 'spring-signing-secring.gpg', variable: 'SIGNING_KEYRING_FILE')
def SPRING_GPG_PASSPHRASE = string(credentialsId: 'spring-gpg-passphrase', variable: 'SIGNING_PASSWORD')
def OSSRH_CREDENTIALS = usernamePassword(credentialsId: 'oss-token', passwordVariable: 'OSSRH_PASSWORD', usernameVariable: 'OSSRH_USERNAME')
def ARTIFACTORY_CREDENTIALS = usernamePassword(credentialsId: '02bd1690-b54f-4c9f-819d-a77cb7a9822c', usernameVariable: 'ARTIFACTORY_USERNAME', passwordVariable: 'ARTIFACTORY_PASSWORD')
def JENKINS_PRIVATE_SSH_KEY = file(credentialsId: 'docs.spring.io-jenkins_private_ssh_key', variable: 'DEPLOY_SSH_KEY')
def SONAR_LOGIN_CREDENTIALS = string(credentialsId: 'spring-sonar.login', variable: 'SONAR_LOGIN')

def jdkEnv(String jdk = 'jdk8') {
	def jdkTool = tool(jdk)
	return "JAVA_HOME=${ jdkTool }"
}

try {
	parallel check: {
		stage('Check') {
			node {
				checkout scm
				sh "git clean -dfx"
				try {
					withCredentials([GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv(),
							 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
							 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
							 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew check --stacktrace"
						}
					}
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
				sh "git clean -dfx"
				withCredentials([SONAR_LOGIN_CREDENTIALS,
					GRADLE_ENTERPRISE_CACHE_USER,
					GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
					try {
						withEnv([jdkEnv(),
							 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
							 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
							 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							if ("master" == env.BRANCH_NAME) {
								sh "./gradlew sonarqube -PexcludeProjects='**/samples/**' -Dsonar.host.url=$SPRING_SONAR_HOST_URL -Dsonar.login=$SONAR_LOGIN --stacktrace"
							} else {
								sh "./gradlew sonarqube -PexcludeProjects='**/samples/**' -Dsonar.projectKey='spring-security-${env.BRANCH_NAME}' -Dsonar.projectName='spring-security-${env.BRANCH_NAME}' -Dsonar.host.url=$SPRING_SONAR_HOST_URL -Dsonar.login=$SONAR_LOGIN --stacktrace"
							}
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
				sh "git clean -dfx"
				try {
					withCredentials([GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv(),
							 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
							 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
							 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew test --refresh-dependencies -PforceMavenRepositories=snapshot -PspringVersion='5.+' -PreactorVersion='20+' -PspringDataVersion='Lovelace-BUILD-SNAPSHOT' -PrsocketVersion=1.1.0-SNAPSHOT -PspringBootVersion=2.4.0-SNAPSHOT -PkotlinVersion=1.4.0 -PlocksDisabled --stacktrace"
						}
					}
				} catch(Exception e) {
					currentBuild.result = 'FAILED: snapshots'
					throw e
				}
			}
		}
	},
	jdk11: {
		stage('JDK 11') {
			node {
				checkout scm
				sh "git clean -dfx"
				try {

					withCredentials([GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv("jdk11"),
						 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
						 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
						 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew test --stacktrace"
						}
					}
				} catch(Exception e) {
					currentBuild.result = 'FAILED: jdk11'
					throw e
				}
			}
		}
	},
	jdk12: {
		stage('JDK 12') {
			node {
				checkout scm
				sh "git clean -dfx"
				try {
					withCredentials([GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv("openjdk12"),
						 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
						 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
						 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew test --stacktrace"
						}
					}
				} catch(Exception e) {
					currentBuild.result = 'FAILED: jdk12'
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
					sh "git clean -dfx"
					withCredentials([SPRING_SIGNING_SECRING,
						 SPRING_GPG_PASSPHRASE,
						 OSSRH_CREDENTIALS,
						 ARTIFACTORY_CREDENTIALS,
						 GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv(),
							 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
							 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
							 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew deployArtifacts finalizeDeployArtifacts -Psigning.secretKeyRingFile=$SIGNING_KEYRING_FILE -Psigning.keyId=$SPRING_SIGNING_KEYID -Psigning.password='$SIGNING_PASSWORD' -PossrhUsername=$OSSRH_USERNAME -PossrhPassword=$OSSRH_PASSWORD -PartifactoryUsername=$ARTIFACTORY_USERNAME -PartifactoryPassword=$ARTIFACTORY_PASSWORD --stacktrace"
						}
					}
				}
			}
		},
		docs: {
			stage('Deploy Docs') {
				node {
					checkout scm
					sh "git clean -dfx"
					withCredentials([JENKINS_PRIVATE_SSH_KEY,
						 SPRING_GPG_PASSPHRASE,
						 OSSRH_CREDENTIALS,
						 ARTIFACTORY_CREDENTIALS,
						 GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv(),
							 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
							 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
							 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew deployDocs -PdeployDocsSshKeyPath=$DEPLOY_SSH_KEY -PdeployDocsSshUsername=$SPRING_DOCS_USERNAME --stacktrace"
						}
					}
				}
			}
		},
		schema: {
			stage('Deploy Schema') {
				node {
					checkout scm
					sh "git clean -dfx"
					withCredentials([JENKINS_PRIVATE_SSH_KEY,
						 SPRING_GPG_PASSPHRASE,
						 OSSRH_CREDENTIALS,
						 ARTIFACTORY_CREDENTIALS,
						 GRADLE_ENTERPRISE_CACHE_USER,
						 GRADLE_ENTERPRISE_SECRET_ACCESS_KEY]) {
						withEnv([jdkEnv(),
							 "GRADLE_ENTERPRISE_CACHE_USERNAME=${GRADLE_ENTERPRISE_CACHE_USERNAME}",
							 "GRADLE_ENTERPRISE_CACHE_PASSWORD=${GRADLE_ENTERPRISE_CACHE_PASSWORD}",
							 "GRADLE_ENTERPRISE_ACCESS_KEY=${GRADLE_ENTERPRISE_ACCESS_KEY}"]) {
							sh "./gradlew deploySchema -PdeployDocsSshKeyPath=$DEPLOY_SSH_KEY -PdeployDocsSshUsername=$SPRING_DOCS_USERNAME --stacktrace"
						}
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
