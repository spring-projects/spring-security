package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project

public class OssrhPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		if(project.hasProperty('ossrhUsername')) {
			project.uploadArchives {
				repositories {
					mavenDeployer {
						repository(url: "https://oss.sonatype.org/service/local/staging/deploy/maven2/") {
							authentication(userName: project.ossrhUsername, password: project.ossrhPassword)
						}

						snapshotRepository(url: "https://oss.sonatype.org/content/repositories/snapshots/") {
							authentication(userName: project.ossrhUsername, password: project.ossrhPassword)
						}
					}
				}
			}
		}
	}
}
