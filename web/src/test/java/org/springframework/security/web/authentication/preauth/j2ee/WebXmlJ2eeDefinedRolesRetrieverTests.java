/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.web.authentication.preauth.j2ee;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import static org.assertj.core.api.Assertions.assertThat;

public class WebXmlJ2eeDefinedRolesRetrieverTests {

	@Test
	public void testRole1To4Roles() throws Exception {
		List<String> ROLE1TO4_EXPECTED_ROLES = Arrays.asList("Role1", "Role2", "Role3", "Role4");
		final Resource webXml = new ClassPathResource("webxml/Role1-4.web.xml");
		WebXmlMappableAttributesRetriever rolesRetriever = new WebXmlMappableAttributesRetriever();

		rolesRetriever.setResourceLoader(new ResourceLoader() {
			@Override
			public ClassLoader getClassLoader() {
				return Thread.currentThread().getContextClassLoader();
			}

			@Override
			public Resource getResource(String location) {
				return webXml;
			}
		});

		rolesRetriever.afterPropertiesSet();
		Set<String> j2eeRoles = rolesRetriever.getMappableAttributes();
		assertThat(j2eeRoles).containsAll(ROLE1TO4_EXPECTED_ROLES);
	}

	@Test
	public void testGetZeroJ2eeRoles() throws Exception {
		final Resource webXml = new ClassPathResource("webxml/NoRoles.web.xml");
		WebXmlMappableAttributesRetriever rolesRetriever = new WebXmlMappableAttributesRetriever();
		rolesRetriever.setResourceLoader(new ResourceLoader() {
			@Override
			public ClassLoader getClassLoader() {
				return Thread.currentThread().getContextClassLoader();
			}

			@Override
			public Resource getResource(String location) {
				return webXml;
			}
		});
		rolesRetriever.afterPropertiesSet();
		Set<String> j2eeRoles = rolesRetriever.getMappableAttributes();
		assertThat(j2eeRoles).isEmpty();
	}

}
