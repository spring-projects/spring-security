package trang;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;

/**
 * Used for converting .rnc files to .xsd files.
 * @author Rob Winch
 */
public class TrangPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		Task rncToXsd = project.getTasks().create("rncToXsd", RncToXsd.class);
		rncToXsd.setDescription("Converts .rnc to .xsd");
		rncToXsd.setGroup("Build");
	}
}
