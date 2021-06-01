package io.spring.gradle.convention

import org.aim42.htmlsanitycheck.HtmlSanityCheckPlugin
import org.aim42.htmlsanitycheck.HtmlSanityCheckTask
import org.aim42.htmlsanitycheck.check.BrokenHttpLinksChecker
import org.asciidoctor.gradle.jvm.AbstractAsciidoctorTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.plugins.PluginManager
import org.gradle.api.tasks.bundling.Zip

/**
 * Aggregates asciidoc, javadoc, and deploying of the docs into a single plugin
 */
public class DocsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {

		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply("org.asciidoctor.jvm.convert");
		pluginManager.apply("org.asciidoctor.jvm.pdf");
		pluginManager.apply(AsciidoctorConventionPlugin);
		pluginManager.apply(DeployDocsPlugin);
		pluginManager.apply(JavadocApiPlugin);
		pluginManager.apply(HtmlSanityCheckPlugin)

		String projectName = Utils.getProjectName(project);
		String pdfFilename = projectName + "-reference.pdf";

		project.tasks.withType(AbstractAsciidoctorTask) { t ->
			project.configure(t) {
				sources {
					include "**/*.adoc"
					exclude '_*/**'
				}
			}
		}

		project.tasks.withType(HtmlSanityCheckTask) { HtmlSanityCheckTask t ->
			project.configure(t) {
				t.dependsOn 'asciidoctor'
				t.checkerClasses = [BrokenHttpLinksChecker]
				t.checkingResultsDir = new File(project.getBuildDir(), "/report/htmlchecks")
				t.failOnErrors = false
				t.httpConnectionTimeout = 3000
				t.sourceDir = new File(project.getBuildDir(), "/docs/asciidoc/")
				t.sourceDocuments = project.files(new File(project.getBuildDir(), "/docs/asciidoc/index.html"))
			}
		}

		Task docsZip = project.tasks.create('docsZip', Zip) {
			dependsOn 'api', 'asciidoctor'
			group = 'Distribution'
			archiveBaseName = project.rootProject.name
			archiveClassifier = 'docs'
			description = "Builds -${classifier} archive containing all " +
				"Docs for deployment at docs.spring.io"

			from(project.tasks.asciidoctor.outputs) {
				into 'reference/html5'
				include '**'
			}
			from(project.tasks.asciidoctorPdf.outputs) {
				into 'reference/pdf'
				include '**'
				rename "index.pdf", pdfFilename
			}
			from(project.tasks.api.outputs) {
				into 'api'
			}
			into 'docs'
			duplicatesStrategy 'exclude'
		}

		Task docs = project.tasks.create("docs") {
			group = 'Documentation'
			description 'An aggregator task to generate all the documentation'
			dependsOn docsZip
		}
		project.tasks.assemble.dependsOn docs
	}
}
