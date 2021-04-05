package io.spring.gradle.convention

import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.tasks.bundling.Zip
import org.gradle.api.Plugin
import org.gradle.api.Project

public class SchemaZipPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		Zip schemaZip = project.tasks.create('schemaZip', Zip)
		schemaZip.group = 'Distribution'
		schemaZip.archiveBaseName = project.rootProject.name
		schemaZip.archiveClassifier = 'schema'
		schemaZip.description = "Builds -${schemaZip.archiveClassifier} archive containing all " +
			"XSDs for deployment at static.springframework.org/schema."

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
				}
			}
		}
	}
}
