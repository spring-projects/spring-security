package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.tasks.bundling.Zip
import org.springframework.gradle.xsd.CreateVersionlessXsdTask

public class SchemaZipPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		Zip schemaZip = project.tasks.create('schemaZip', Zip)
		schemaZip.group = 'Distribution'
		schemaZip.archiveBaseName = project.rootProject.name
		schemaZip.archiveClassifier = 'schema'
		schemaZip.description = "Builds -${schemaZip.archiveClassifier} archive containing all " +
			"XSDs for deployment at static.springframework.org/schema."
		def versionlessXsd = project.tasks.create("versionlessXsd", CreateVersionlessXsdTask) {
			description = "Generates spring-security.xsd"
			versionlessXsdFile = project.layout.buildDirectory.file("versionlessXsd/spring-security.xsd")
		}
		project.rootProject.subprojects.each { module ->

			module.getPlugins().withType(JavaPlugin.class).all {
				def Properties schemas = new Properties();

				module.sourceSets.main.resources.find {
					it.path.endsWith('META-INF/spring.schemas')
				}?.withInputStream { schemas.load(it) }

				for (def key : schemas.keySet()) {
					def shortName = key.replaceAll(/http.*schema.(.*).spring-.*/, '$1')
					assert shortName != key
					File xsdFile = module.sourceSets.main.resources.find {
						it.path.endsWith(schemas.get(key))
					}
					assert xsdFile != null
					schemaZip.into (shortName) {
						duplicatesStrategy 'exclude'
						from xsdFile.path
					}
					versionlessXsd.getInputFiles().from(xsdFile.path)
				}
			}
		}

        schemaZip.into("security") {
            from(versionlessXsd.getOutputs())
        }

	}
}
