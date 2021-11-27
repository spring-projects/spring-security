/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.spring.gradle.convention

import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.tasks.bundling.Zip
import org.gradle.api.Plugin
import org.gradle.api.Project

public class DeployDocsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		project.getPluginManager().apply('org.hidetake.ssh')

		project.ssh.settings {
			knownHosts = allowAnyHosts
		}
		project.remotes {
			docs {
				role 'docs'
				if (project.hasProperty('deployDocsHost')) {
					host = project.findProperty('deployDocsHost')
				} else {
					host = 'docs.af.pivotal.io'
				}
				retryCount = 5 // retry 5 times (default is 0)
				retryWaitSec = 10 // wait 10 seconds between retries (default is 0)
				user = project.findProperty('deployDocsSshUsername')
				if (project.hasProperty('deployDocsSshKeyPath')) {
					identity = project.file(project.findProperty('deployDocsSshKeyPath'))
				} else if (project.hasProperty('deployDocsSshKey')) {
					identity = project.findProperty('deployDocsSshKey')
				}
				if(project.hasProperty('deployDocsSshPassphrase')) {
					passphrase = project.findProperty('deployDocsSshPassphrase')
				}
			}
		}

		project.task('deployDocs') {
			dependsOn 'docsZip'
			doFirst {
				project.ssh.run {
					session(project.remotes.docs) {
						def now = System.currentTimeMillis()
						def name = project.rootProject.name
						def version = project.rootProject.version
						def tempPath = "/tmp/${name}-${now}-docs/".replaceAll(' ', '_')
						execute "mkdir -p $tempPath"

						project.tasks.docsZip.outputs.each { o ->
							put from: o.files, into: tempPath
						}

						execute "unzip $tempPath*.zip -d $tempPath"

						def extractPath = "/var/www/domains/spring.io/docs/htdocs/autorepo/docs/${name}/${version}/"

						execute "rm -rf $extractPath"
						execute "mkdir -p $extractPath"
						execute "mv $tempPath/docs/* $extractPath"
						execute "chmod -R g+w $extractPath"
					}
				}
			}
		}
	}
}