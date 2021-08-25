parallel check: {
	stage('Check') {
		node {
			checkout scm
			sh "./gradlew check  --refresh-dependencies --no-daemon"
		}
	}
},
sonar: {
	stage('Sonar') {
		node {
			checkout scm
			withCredentials([string(credentialsId: 'spring-sonar.login', variable: 'SONAR_LOGIN')]) {
				sh "./gradlew sonarqube -Dsonar.host.url=$SPRING_SONAR_HOST_URL -Dsonar.login=$SONAR_LOGIN --refresh-dependencies --no-daemon"
			}
		}
	}
},
ossrh: {
	stage('OSSRH Deploy') {
		node {
			checkout scm
			withCredentials([file(credentialsId: 'spring-signing-secring.gpg', variable: 'SIGNING_KEYRING_FILE')]) {
				withCredentials([string(credentialsId: 'spring-gpg-passphrase', variable: 'SIGNING_PASSWORD')]) {
					withCredentials([usernamePassword(credentialsId: 'oss-token', passwordVariable: 'OSSRH_PASSWORD', usernameVariable: 'OSSRH_USERNAME')]) {
						sh "./gradlew uploadArchives -Psigning.secretKeyRingFile=$SIGNING_KEYRING_FILE -Psigning.keyId=$SPRING_SIGNING_KEYID -Psigning.password=$SIGNING_PASSWORD -PossrhUsername=$OSSRH_USERNAME -PossrhPassword=$OSSRH_PASSWORD  --refresh-dependencies --no-daemon"
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