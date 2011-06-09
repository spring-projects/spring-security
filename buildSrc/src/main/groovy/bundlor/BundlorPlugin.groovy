package bundlor

import com.springsource.bundlor.ClassPath
import com.springsource.bundlor.ManifestGenerator
import com.springsource.bundlor.ManifestWriter
import com.springsource.bundlor.blint.ManifestValidator
import com.springsource.bundlor.blint.support.DefaultManifestValidatorContributorsFactory
import com.springsource.bundlor.blint.support.StandardManifestValidator
import com.springsource.bundlor.support.DefaultManifestGeneratorContributorsFactory
import com.springsource.bundlor.support.StandardManifestGenerator
import com.springsource.bundlor.support.classpath.FileSystemClassPath
import com.springsource.bundlor.support.manifestwriter.FileSystemManifestWriter
import com.springsource.bundlor.support.properties.EmptyPropertiesSource
import com.springsource.bundlor.support.properties.FileSystemPropertiesSource
import com.springsource.bundlor.support.properties.PropertiesPropertiesSource
import com.springsource.bundlor.support.properties.PropertiesSource
import com.springsource.bundlor.util.BundleManifestUtils
import com.springsource.util.parser.manifest.ManifestContents
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.file.FileCollection
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

/**
 * @author Luke Taylor
 */
class BundlorPlugin implements Plugin<Project> {
    void apply(Project project) {
        Task bundlor = project.tasks.add('bundlor', Bundlor.class)
        bundlor.setDescription('Generates OSGi manifest using bundlor tool')
        bundlor.dependsOn(project.classes)
        project.jar.dependsOn bundlor
    }
}

public class Bundlor extends DefaultTask {
    @InputFile
    @Optional
    File manifestTemplate

    @OutputDirectory
    File bundlorDir = new File("${project.buildDir}/bundlor")

    @OutputFile
    File manifest = project.file("${bundlorDir}/META-INF/MANIFEST.MF")

    @Input
    Map<String,String> expansions = [:]

    @InputFile
    @Optional
    File osgiProfile

    @InputFiles
    @Optional
    FileCollection inputPaths

    @Input
    boolean failOnWarnings = false

    Bundlor() {
        manifestTemplate = new File(project.projectDir, 'template.mf')

        if (!manifestTemplate.exists()) {
            logger.info("No bundlor template for project " + project.name)
            manifestTemplate = null
        }

        inputPaths = project.files(project.sourceSets.main.classesDir)

        if (manifestTemplate != null) {
            project.jar.manifest.from manifest
            project.jar.inputs.files manifest
        }
    }

    @TaskAction
    void createManifest() {
        if (manifestTemplate == null) {
            return;
        }

        logging.captureStandardOutput(LogLevel.INFO)

        project.mkdir(bundlorDir)

        //String inputPath = project.sourceSets.main.classesDir

        List<ClassPath> inputClassPath = [] as List;

        ManifestWriter manifestWriter = new FileSystemManifestWriter(project.file(bundlorDir.absolutePath));
        ManifestContents mfTemplate = BundleManifestUtils.getManifest(manifestTemplate);

        inputPaths.each {f ->
            inputClassPath.add(new FileSystemClassPath(f))
        }

        // Must be a better way of doing this...
        Properties p = new Properties()
        expansions.each {entry ->
            p.setProperty(entry.key, entry.value as String)
        }

        PropertiesSource expansionProps = new PropertiesPropertiesSource(p)
        PropertiesSource osgiProfileProps = osgiProfile == null ? new EmptyPropertiesSource() :
            new FileSystemPropertiesSource(osgiProfile);

        ManifestGenerator manifestGenerator = new StandardManifestGenerator(
                DefaultManifestGeneratorContributorsFactory.create(expansionProps, osgiProfileProps));

        ManifestContents mf = manifestGenerator.generate(mfTemplate, inputClassPath.toArray(new ClassPath[inputClassPath.size()]));

        try {
            manifestWriter.write(mf);
        } finally {
            manifestWriter.close();
        }

        ManifestValidator manifestValidator = new StandardManifestValidator(DefaultManifestValidatorContributorsFactory.create());

        List<String> warnings = manifestValidator.validate(mf);

        if (warnings.isEmpty()) {
            return
        }

        logger.warn("Bundlor Warnings:");
        for (String warning : warnings) {
            logger.warn("    " + warning);
        }

        if (failOnWarnings) {
            throw new GradleException("Bundlor returned warnings. Please fix manifest template at " + manifestTemplate.absolutePath + " and try again.")
        }
    }

    def inputPath(FileCollection paths) {
        inputPaths = project.files(inputPaths, paths)
    }
}
