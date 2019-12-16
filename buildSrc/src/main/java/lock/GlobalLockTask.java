package lock;

import org.gradle.api.Action;
import org.gradle.api.DefaultTask;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.tasks.TaskAction;

import java.util.function.Consumer;

/**
 * @author Rob Winch
 */
public class GlobalLockTask extends DefaultTask {
	@TaskAction
	public void lock() {
		Project taskProject = getProject();
		if (!taskProject.getGradle().getStartParameter().isWriteDependencyLocks()) {
			throw new IllegalStateException("You just specify --write-locks argument");
		}
		writeLocksFor(taskProject);
		taskProject.getSubprojects().forEach(new Consumer<Project>() {
			@Override
			public void accept(Project subproject) {
				writeLocksFor(subproject);
			}
		});
	}

	private void writeLocksFor(Project project) {
		project.getConfigurations().configureEach(new Action<Configuration>() {
			@Override
			public void execute(Configuration configuration) {
				if (configuration.isCanBeResolved()) {
					configuration.resolve();
				}
			}
		});
	}
}
