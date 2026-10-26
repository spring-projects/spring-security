/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */


package io.spring.gradle.convention;

import java.util.List;
import java.util.stream.StreamSupport;

import org.gradle.api.Project;
import org.gradle.api.artifacts.repositories.ArtifactRepository;
import org.gradle.api.artifacts.repositories.MavenArtifactRepository;
import org.gradle.api.internal.project.ProjectInternal;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link RepositoryConventionPlugin}. The general repository rules are tested
 * with {@code SpringRepositoryPlugin}; this covers what is added on top of it.
 */
public class RepositoryConventionPluginTests {

	private Project project = ProjectBuilder.builder().build();

	@BeforeEach
	public void setUp() {
		this.project.setVersion("1.0.0");
		this.project.getPluginManager().apply(RepositoryConventionPlugin.class);
		((ProjectInternal) this.project).evaluate();
	}

	@Test
	public void applyThenIncludesSpringRepositories() {
		assertThat(names()).containsSubsequence("MavenRepo", "spring-oss-release");
	}

	@Test
	public void applyThenIncludesShibbolethRepository() {
		MavenArtifactRepository shibboleth = (MavenArtifactRepository) this.project.getRepositories()
			.getByName("shibboleth");
		assertThat(shibboleth.getUrl().toString())
			.isEqualTo("https://build.shibboleth.net/nexus/content/repositories/releases/");
	}

	private List<String> names() {
		return StreamSupport.stream(this.project.getRepositories().spliterator(), false)
			.map(ArtifactRepository::getName)
			.toList();
	}

}
