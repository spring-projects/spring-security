package trang;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

/**
 * Used for converting .rnc files to .xsd files.
 * @author Rob Winch
 */
public class TrangPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getTasks().register("rncToXsd", RncToXsd.class, rncToXsd -> {
			rncToXsd.setDescription("Converts .rnc to .xsd");
			rncToXsd.setGroup("Build");
		});
	}
}
