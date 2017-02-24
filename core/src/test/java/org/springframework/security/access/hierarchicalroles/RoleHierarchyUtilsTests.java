/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.hierarchicalroles;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests for {@link RoleHierarchyUtils}.
 *
 * @author Joe Grandja
 */
@RunWith(Parameterized.class)
public class RoleHierarchyUtilsTests {

	/**
	 * Provide the data to be injected into {@link RoleHierarchyUtilsTests} to be used by
	 * {@link RoleHierarchyUtilsTests#roleHierarchyFromMapWhenMapValidThenConvertsCorrectly()}
	 * in order to test a number of different role hierarchies.
	 * @return the data for {@link RoleHierarchyUtilsTests#roleHierarchyFromMapWhenMapValidThenConvertsCorrectly()}
	 */
	@Parameters
	public static Collection<Object[]> data() {
		return Arrays.asList(new Object[][] {
			{
				new TreeMap<String, List<String>>() {
					{ put("ROLE_A", asList("ROLE_B", "ROLE_C")); }
					{ put("ROLE_B", asList("ROLE_D")); }
					{ put("ROLE_C", asList("ROLE_D")); }
				}
			},
			{
				new TreeMap<String, List<String>>() {
					{ put("ROLE_A", asList("ROLE_B")); }
					{ put("ROLE_B", asList("ROLE_C")); }
					{ put("ROLE_C", asList("ROLE_D", "ROLE_E")); }
				}
			},
		});
	}

	@Parameter
	public Map<String, List<String>> roleHierarchyMap;

	@Test
	public void roleHierarchyFromMapWhenMapValidThenConvertsCorrectly() throws Exception {
		StringWriter roleHierarchyBuffer = new StringWriter();
		PrintWriter roleHierarchyWriter = new PrintWriter(roleHierarchyBuffer);

		for (Map.Entry<String, List<String>> entry: this.roleHierarchyMap.entrySet()) {
			String role = entry.getKey();
			for (String impliedRole: entry.getValue()) {
				String roleMapping = String.format("%s > %s", role, impliedRole);
				roleHierarchyWriter.println(roleMapping);
			}
		}

		String expectedRoleHierarchy = roleHierarchyBuffer.toString();

		String roleHierarchy = RoleHierarchyUtils.roleHierarchyFromMap(this.roleHierarchyMap);

		assertThat(roleHierarchy).isEqualTo(expectedRoleHierarchy);
	}

	@Test(expected = IllegalArgumentException.class)
	public void roleHierarchyFromMapWhenMapNullThenThrowsIllegalArgumentException() throws Exception {
		RoleHierarchyUtils.roleHierarchyFromMap(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void roleHierarchyFromMapWhenMapEmptyThenThrowsIllegalArgumentException() throws Exception {
		RoleHierarchyUtils.roleHierarchyFromMap(Collections.<String, List<String>>emptyMap());
	}

	@Test(expected = IllegalArgumentException.class)
	public void roleHierarchyFromMapWhenRoleNullThenThrowsIllegalArgumentException() throws Exception {
		Map<String, List<String>> roleHierarchyMap = new HashMap<String, List<String>>();
		roleHierarchyMap.put(null, asList("ROLE_B", "ROLE_C"));

		RoleHierarchyUtils.roleHierarchyFromMap(roleHierarchyMap);
	}

	@Test(expected = IllegalArgumentException.class)
	public void roleHierarchyFromMapWhenRoleEmptyThenThrowsIllegalArgumentException() throws Exception {
		Map<String, List<String>> roleHierarchyMap = new HashMap<String, List<String>>();
		roleHierarchyMap.put("", asList("ROLE_B", "ROLE_C"));

		RoleHierarchyUtils.roleHierarchyFromMap(roleHierarchyMap);
	}

	@Test(expected = IllegalArgumentException.class)
	public void roleHierarchyFromMapWhenImpliedRolesNullThenThrowsIllegalArgumentException() throws Exception {
		Map<String, List<String>> roleHierarchyMap = new HashMap<String, List<String>>();
		roleHierarchyMap.put("ROLE_A", null);

		RoleHierarchyUtils.roleHierarchyFromMap(roleHierarchyMap);
	}

	@Test(expected = IllegalArgumentException.class)
	public void roleHierarchyFromMapWhenImpliedRolesEmptyThenThrowsIllegalArgumentException() throws Exception {
		Map<String, List<String>> roleHierarchyMap = new HashMap<String, List<String>>();
		roleHierarchyMap.put("ROLE_A", Collections.<String>emptyList());

		RoleHierarchyUtils.roleHierarchyFromMap(roleHierarchyMap);
	}
}
