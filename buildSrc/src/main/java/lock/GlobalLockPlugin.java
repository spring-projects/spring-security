package lock;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

/**
 * @author Rob Winch
 */
public class GlobalLockPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getTasks().register("writeLocks", GlobalLockTask.class, (writeAll) -> {
			writeAll.setDescription("Writes the locks for all projects");
		});
	}
}
