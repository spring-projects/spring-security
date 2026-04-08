package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.plugins.BasePlugin
import org.gradle.api.plugins.PluginManager
import org.gradle.api.tasks.Sync
import org.gradle.api.tasks.bundling.Zip

/**
 * Aggregates asciidoc, javadoc, and deploying of the docs into a single plugin
 */
public class DocsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {

		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(BasePlugin);
		pluginManager.apply(JavadocApiPlugin);
		pluginManager.apply("org.jetbrains.dokka");

		project.rootProject.subprojects { subproject ->
			subproject.pluginManager.withPlugin("security-kotlin") {
				subproject.pluginManager.apply("org.jetbrains.dokka")
				configureDokka(subproject)
				project.dependencies.add("dokka", subproject)
			}
		}

		project.extensions.configure("dokka") { dokka ->
			dokka.moduleName.set(Utils.getProjectName(project) + " Kotlin API")
		}

		project.tasks.named("dokkaGeneratePublicationHtml").configure { it.dependsOn("api") }

		project.tasks.register("syncAntoraAttachments", Sync) { sync ->
			sync.group = 'Documentation'
			sync.description = 'Syncs the Antora attachments'
			sync.into(project.layout.buildDirectory.dir('generated-antora-resources/modules/ROOT/assets/attachments/api'))
			sync.from(project.provider({ project.tasks.api.outputs })) { copy ->
				copy.into('java')
			}
			sync.from(project.tasks.named("dokkaGeneratePublicationHtml")) { copy ->
				copy.into('kotlin')
			}
		}

		project.tasks.register("generateAntoraResources") {
			it.dependsOn 'generateAntoraYml', 'syncAntoraAttachments'
		}

		Task docsZip = project.tasks.create('docsZip', Zip) {
			dependsOn 'api'
			group = 'Distribution'
			archiveBaseName = project.rootProject.name
			archiveClassifier = 'docs'
			description = "Builds -${archiveClassifier.get()} archive containing all " +
				"Docs for deployment at docs.spring.io"

			from(project.tasks.api.outputs) {
				into 'api'
			}
			into 'docs'
			duplicatesStrategy = 'exclude'
		}

		Task docs = project.tasks.create("docs") {
			group = 'Documentation'
			description = 'An aggregator task to generate all the documentation'
			dependsOn docsZip
		}
		project.tasks.assemble.dependsOn docs
	}

	void configureDokka(Project project) {
		project.extensions.configure("dokka") { dokka ->
			dokka.dokkaSourceSets.configureEach { spec ->
				spec.suppressedFiles.from(project.fileTree("src/main/java"))
				spec.externalDocumentationLinks.register("javadoc") {
					it.url.set(new URI("https://docs.spring.io/${Utils.getProjectName(project)}/reference/${project.rootProject.version}/api/java/"))
					it.packageListUrl.set(project.layout.buildDirectory.file("api/element-list").get().asFile.toURI())
				}
			}
		}
	}
}
