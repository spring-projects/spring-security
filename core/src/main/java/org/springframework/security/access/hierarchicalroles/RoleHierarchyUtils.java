/*
 * Copyright 2002-2016 the original author or authors.
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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

/**
 * Utility method for working with {@link RoleHierarchy}.
 *
 * @author Thomas Darimont
 * @since
 */
public class RoleHierarchyUtils {

	/**
	 * Builds a {@link RoleHierarchy} representation from the given {@link Map} of role name to implied roles.
	 * The map key is the role name and the map value is a {@link List} of implied role names.
	 *
	 * <p>
	 *     Here is an example configuration of a role hierarchy configured via yaml.
	 *     wich follows the pattern:
	 *     {@code ROLE_NAME: List of implied role names}
	 * </p>
	 * <pre>
	 * <code>
	 *
	 * security:
	 *   roles:
	 *     hierarchy:
	 *       ROLE_ALL: ROLE_A, ROLE_C
	 *       ROLE_A: ROLE_B
	 *       ROLE_B: ROLE_AUTHENTICATED
	 *       ROLE_C: ROLE_AUTHENTICATED
	 *       ROLE_AUTHENTICATED: ROLE_UNAUTHENTICATED
	 * </code>
	 * </pre>
	 * <p>This yaml configuration could then be mapped by the following {@literal ConfigurationProperties}</p>
	 * <pre>
	 * <code>
	 *   {@literal @}ConfigurationProperties("security.roles")
	 *   class SecurityPropertiesExtension {
	 *     Map<String, List<String>> hierarchy = new LinkedHashMap<>();
	 *
	 *     //getter | setter
	 *   }
	 * </code>
	 * </pre>
	 * <p>To define the role hierarchy just declare a {@link org.springframework.context.annotation.Bean} of
	 * type {@link RoleHierarchy} as follows:</p>
	 * <pre>
	 * <code>
	 *   {@literal @}Bean
	 *   RoleHierarchy roleHierarchy(SecurityPropertiesExtension spe) {
	 *     return RoleHierarchyUtils.roleHierarchyFromMap(spe.getHierarchy());
	 *   }
	 * </code>
	 * </pre>
	 *
	 * @param roleHierarchyMapping the role name to implied role names mapping
	 * @return
	 */
	public static RoleHierarchy roleHierarchyFromMap(Map<String, List<String>> roleHierarchyMapping) {

		StringWriter roleHierachyDescriptionBuffer = new StringWriter();
		PrintWriter roleHierarchyDescriptionWriter = new PrintWriter(roleHierachyDescriptionBuffer);

		for (Map.Entry<String, List<String>> entry : roleHierarchyMapping.entrySet()) {

			String currentRole = entry.getKey();
			List<String> impliedRoles = entry.getValue();

			for (String impliedRole : impliedRoles) {
				String roleMapping = currentRole + " > " + impliedRole;
				roleHierarchyDescriptionWriter.println(roleMapping);
			}
		}

		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy(roleHierachyDescriptionBuffer.toString());
		return roleHierarchy;
	}
}
