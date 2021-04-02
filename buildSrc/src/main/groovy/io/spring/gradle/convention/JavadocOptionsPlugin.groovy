package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.javadoc.Javadoc

public class JavadocOptionsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		project.getTasks().withType(Javadoc).all { t->
			t.options.addStringOption('Xdoclint:none', '-quiet')
		}
	}
}
