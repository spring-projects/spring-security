/*
 * Copyright 2019-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.convention.versions;

import com.github.benmanes.gradle.versions.updates.resolutionstrategy.ComponentSelectionWithCurrent;
import org.gradle.api.Action;
import org.gradle.api.artifacts.ComponentSelection;
import org.gradle.api.artifacts.component.ModuleComponentIdentifier;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

public class DependencyExcludesTests {

	@Test
	public void createExcludeMinorVersionBumpWhenMajorVersionBumpThenReject() {
		ComponentSelection componentSelection = executeCreateExcludeMinorVersionBump("1.0.0", "2.0.0");
		verify(componentSelection).reject(any());
	}

	@Test
	public void createExcludeMinorVersionBumpWhenMajorCalVersionBumpThenReject() {
		ComponentSelection componentSelection = executeCreateExcludeMinorVersionBump("2000.0.0", "2001.0.0");
		verify(componentSelection).reject(any());
	}

	@Test
	public void createExcludeMinorVersionBumpWhenMinorVersionBumpThenReject() {
		ComponentSelection componentSelection = executeCreateExcludeMinorVersionBump("1.0.0", "1.1.0");
		verify(componentSelection).reject(any());
	}

	@Test
	public void createExcludeMinorVersionBumpWhenMinorCalVersionBumpThenReject() {
		ComponentSelection componentSelection = executeCreateExcludeMinorVersionBump("2000.0.0", "2000.1.0");
		verify(componentSelection).reject(any());
	}

	@Test
	public void createExcludeMinorVersionBumpWhenMinorAndPatchVersionBumpThenReject() {
		ComponentSelection componentSelection = executeCreateExcludeMinorVersionBump("1.0.0", "1.1.1");
		verify(componentSelection).reject(any());
	}

	@Test
	public void createExcludeMinorVersionBumpWhenPatchVersionBumpThenDoesNotReject() {
		ComponentSelection componentSelection = executeCreateExcludeMinorVersionBump("1.0.0", "1.0.1");
		verify(componentSelection, times(0)).reject(any());
	}

	private ComponentSelection executeCreateExcludeMinorVersionBump(String currentVersion, String candidateVersion) {
		ComponentSelection componentSelection = mock(ComponentSelection.class);
		UpdateDependenciesExtension.DependencyExcludes excludes = new UpdateDependenciesExtension(() -> Collections.emptyList()).new DependencyExcludes();
		Action<ComponentSelectionWithCurrent> excludeMinorVersionBump = excludes.createExcludeMinorVersionBump();
		ComponentSelectionWithCurrent selection = currentVersionAndCandidateVersion(componentSelection, currentVersion, candidateVersion);
		excludeMinorVersionBump.execute(selection);
		return componentSelection;
	}

	private ComponentSelectionWithCurrent currentVersionAndCandidateVersion(ComponentSelection componentSelection, String currentVersion, String candidateVersion) {
		ModuleComponentIdentifier candidate = mock(ModuleComponentIdentifier.class);
		given(componentSelection.getCandidate()).willReturn(candidate);
		ComponentSelectionWithCurrent selection = new ComponentSelectionWithCurrent(currentVersion, componentSelection);
		given(candidate.getVersion()).willReturn(candidateVersion);
		given(componentSelection.getCandidate()).willReturn(candidate);
		return selection;
	}
}
