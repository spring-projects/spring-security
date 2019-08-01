package versions;

import org.codehaus.groovy.runtime.ResourceGroovyMethods;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.MapProperty;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.util.Properties;

public class VersionsResourceTasks extends DefaultTask {

	private final RegularFileProperty versionsFile = getProject().getObjects().fileProperty();

	private final MapProperty<String, String> versions = getProject().getObjects().mapProperty(String.class, String.class);

	@OutputFile
	public RegularFileProperty getVersionsFile() {
		return versionsFile;
	}

	@Input
	public MapProperty<String, String> getVersions() {
		return versions;
	}

	@TaskAction
	void generateVersions() throws IOException {

		File file = versionsFile.getAsFile().get();
		File parentFile = versionsFile.getAsFile().get().getParentFile();

		if (parentFile.isDirectory() || parentFile.mkdirs()) {
			Properties properties = new Properties();
			properties.putAll(getVersions().get());
			try (Writer writer = ResourceGroovyMethods.newWriter(file)) {
				properties.store(writer, null);
			}
		}
		else {
			throw new IOException(parentFile + " does not exist and cannot be created");
		}
	}
}
