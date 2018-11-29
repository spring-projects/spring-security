package aspectj

import org.gradle.api.Project
import org.gradle.api.Plugin
import org.gradle.api.tasks.TaskAction
import org.gradle.api.logging.LogLevel
import org.gradle.api.file.*
import org.gradle.api.tasks.SourceSet
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException

import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.plugins.ide.eclipse.GenerateEclipseProject
import org.gradle.plugins.ide.eclipse.GenerateEclipseClasspath
import org.gradle.plugins.ide.eclipse.EclipsePlugin
import org.gradle.plugins.ide.eclipse.model.BuildCommand
import org.gradle.plugins.ide.eclipse.model.ProjectDependency

/**
 *
 * @author Luke Taylor
 */
class AspectJPlugin implements Plugin<Project> {

	void apply(Project project) {
		project.plugins.apply(JavaPlugin)

		if (project.configurations.findByName('ajtools') == null) {
			project.configurations.create('ajtools')
			project.dependencies {
				ajtools "org.aspectj:aspectjtools"
				optional "org.aspectj:aspectjrt"
			}
		}

		if (project.configurations.findByName('aspectpath') == null) {
			project.configurations.create('aspectpath')
		}

		project.afterEvaluate {
			setupAspectJ(project)
		}
	}

	void setupAspectJ(Project project) {
		project.tasks.withType(JavaCompile) { javaCompileTask ->
			def javaCompileTaskName = javaCompileTask.name
			def ajCompileTask = project.tasks.create(name: javaCompileTaskName + 'Aspect', overwrite: true, description: 'Compiles AspectJ Source', type: Ajc) {
				inputs.files(javaCompileTask.inputs.files)
				inputs.properties(javaCompileTask.inputs.properties.findAll {it.value != null})

				sourceRoots.addAll(project.sourceSets.main.java.srcDirs)
				if(javaCompileTaskName.contains("Test")) {
					sourceRoots.addAll(project.sourceSets.test.java.srcDirs)
				}
				compileClasspath = javaCompileTask.classpath
				destinationDir = javaCompileTask.destinationDir
				aspectPath = project.configurations.aspectpath
			}

			javaCompileTask.setActions Arrays.asList()
			javaCompileTask.dependsOn ajCompileTask

		}

		project.tasks.withType(GenerateEclipseProject) {
			project.eclipse.project.file.whenMerged { p ->
				p.natures.add(0, 'org.eclipse.ajdt.ui.ajnature')
				p.buildCommands = [new BuildCommand('org.eclipse.ajdt.core.ajbuilder')]
			}
		}

		project.tasks.withType(GenerateEclipseClasspath) {
			project.eclipse.classpath.file.whenMerged { classpath ->
				def entries = classpath.entries.findAll { it instanceof ProjectDependency}.findAll { entry ->
					def projectPath = entry.path.replaceAll('/','')
					project.rootProject.allprojects.find{ p->
						if(p.plugins.findPlugin(EclipsePlugin)) {
							return p.eclipse.project.name == projectPath && p.plugins.findPlugin(AspectJPlugin)
						}
						false
					}
				}
				entries.each { entry->
					entry.entryAttributes.put('org.eclipse.ajdt.aspectpath','org.eclipse.ajdt.aspectpath')
				}
			}
		}
	}
}

class Ajc extends DefaultTask {
	Set<File> sourceRoots = []
	FileCollection compileClasspath
	File destinationDir
	FileCollection aspectPath

	Ajc() {
		logging.captureStandardOutput(LogLevel.INFO)
	}

	@TaskAction
	def compile() {
		logger.info("="*30)
		logger.info("="*30)
		logger.info("Running ajc ...")
		logger.info("classpath: ${compileClasspath?.files}")
		logger.info("srcDirs ${sourceRoots}")
		ant.taskdef(resource: "org/aspectj/tools/ant/taskdefs/aspectjTaskdefs.properties", classpath: project.configurations.ajtools.asPath)
		if(sourceRoots.empty) {
			return
		}
		ant.iajc(classpath: compileClasspath.asPath, fork: 'true', destDir: destinationDir.absolutePath,
				source: project.convention.plugins.java.sourceCompatibility,
				target: project.convention.plugins.java.targetCompatibility,
				aspectPath: aspectPath.asPath, sourceRootCopyFilter: '**/*.java', showWeaveInfo: 'true') {
			sourceroots {
				sourceRoots.each {
					logger.info("	sourceRoot $it")
					pathelement(location: it.absolutePath)
				}
			}
		}
	}
}
