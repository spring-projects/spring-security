package emma;

import org.gradle.api.*
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Input
import com.vladium.emma.instr.InstrProcessor
import com.vladium.emma.report.ReportProcessor
import org.gradle.api.tasks.InputFiles
import com.vladium.util.XProperties;

/**
 *
 * @author Luke Taylor
 */
class EmmaPlugin implements Plugin<Project> {

    void apply(Project project) {
        Project rootProject = project.rootProject
        def emmaMetaDataFile = "${rootProject.buildDir}/emma/emma.em"
        def emmaCoverageFile = "${rootProject.buildDir}/emma/emma.ec"

        if (project.configurations.findByName('emma_rt') == null) {
            project.configurations.add('emma_rt')
            project.dependencies {
                emma_rt 'emma:emma:2.0.5312'
            }
        }

        project.task('emmaInstrument') {
            dependsOn project.classes

            doFirst {
                InstrProcessor processor = InstrProcessor.create ();
                String[] classesDirPath = [project.sourceSets.main.classesDir.absolutePath]

                processor.setInstrPath(classesDirPath, false);
                processor.setOutMode(InstrProcessor.OutMode.OUT_MODE_COPY);
                processor.setInstrOutDir("${project.buildDir}/emma/classes");
                processor.setMetaOutFile(emmaMetaDataFile);
                processor.setMetaOutMerge(true);
                //processor.setInclExclFilter (null);
                processor.run();
            }
        }

        // Modify test tasks in the project to generate coverage data
        project.afterEvaluate {
            if (project.hasProperty('coverage') && ['on','true'].contains(project.properties.coverage)) {
                project.tasks.withType(Test.class).each { task ->
                    task.dependsOn project.emmaInstrument
                    task.configure() {
                        jvmArgs '-Dsec.log.level=DEBUG', "-Demma.coverage.out.file=$emmaCoverageFile"
                        jvmArgs '-Demma.verbosity.level=quiet'
                    }
                    task.doFirst {
                        classpath = project.files("${project.buildDir}/emma/classes") + project.configurations.emma_rt + classpath
                    }
                }
            }
        }

        List<Task> reportTasks = rootProject.getTasksByName('coverageReport', false) as List;
        CoverageReport task;

        if (reportTasks.isEmpty()) {
            task = rootProject.tasks.add('coverageReport', CoverageReport.class);
            task.dataPath = [emmaMetaDataFile, emmaCoverageFile];
        } else {
            task = reportTasks[0];
        }

        task.modules.add(project);
    }
}

class CoverageReport extends DefaultTask {
    @Input
    List<Project> modules = [];

    @Input
    String[] dataPath;

    @TaskAction
    void generateReport() {
        def buildDir = project.rootProject.buildDir

        if (!buildDir.exists()) {
            throw new GradleException("No coverage data. Run gradle with -Pcoverage=on if using coverageReport");
        }

        ReportProcessor processor = ReportProcessor.create ();
        processor.setDataPath(dataPath)

        def srcPath = []
        modules.each {module->
            module.sourceSets.main.java.srcDirs.each {
                srcPath.add(it.absolutePath)
            }
        }

        processor.setSourcePath(srcPath as String[]);


        def types = ['txt', 'html']
        processor.setReportTypes(types as String[]);
        XProperties properties = new XProperties();
        properties.setProperty('report.html.out.file', "$buildDir/emma/coverage.html");
        properties.setProperty('report.txt.out.file', "$buildDir/emma/coverage.txt");
        processor.setPropertyOverrides(properties)

        processor.run()
    }
}
