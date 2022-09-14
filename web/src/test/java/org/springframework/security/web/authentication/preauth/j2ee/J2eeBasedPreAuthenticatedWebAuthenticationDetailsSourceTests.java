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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.MappableAttributesRetriever;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author TSARDD
 */
public class J2eeBasedPreAuthenticatedWebAuthenticationDetailsSourceTests {

	@Test
	public final void testAfterPropertiesSetException() {
		J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource t = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
		assertThatIllegalArgumentException().isThrownBy(t::afterPropertiesSet);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestNoMappedNoUserRoles() {
		String[] mappedRoles = new String[] {};
		String[] roles = new String[] {};
		String[] expectedRoles = new String[] {};
		testDetails(mappedRoles, roles, expectedRoles);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestNoMappedUnmappedUserRoles() {
		String[] mappedRoles = new String[] {};
		String[] roles = new String[] { "Role1", "Role2" };
		String[] expectedRoles = new String[] {};
		testDetails(mappedRoles, roles, expectedRoles);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestNoUserRoles() {
		String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		String[] roles = new String[] {};
		String[] expectedRoles = new String[] {};
		testDetails(mappedRoles, roles, expectedRoles);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestAllUserRoles() {
		String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		String[] roles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		String[] expectedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		testDetails(mappedRoles, roles, expectedRoles);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestUnmappedUserRoles() {
		String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		String[] roles = new String[] { "Role1", "Role2", "Role3", "Role4", "Role5" };
		String[] expectedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		testDetails(mappedRoles, roles, expectedRoles);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestPartialUserRoles() {
		String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		String[] roles = new String[] { "Role2", "Role3" };
		String[] expectedRoles = new String[] { "Role2", "Role3" };
		testDetails(mappedRoles, roles, expectedRoles);
	}

	@Test
	public final void testBuildDetailsHttpServletRequestPartialAndUnmappedUserRoles() {
		String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
		String[] roles = new String[] { "Role2", "Role3", "Role5" };
		String[] expectedRoles = new String[] { "Role2", "Role3" };
		testDetails(mappedRoles, roles, expectedRoles);
	}

	private void testDetails(String[] mappedRoles, String[] userRoles, String[] expectedRoles) {
		J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource src = getJ2eeBasedPreAuthenticatedWebAuthenticationDetailsSource(
				mappedRoles);
		Object o = src.buildDetails(getRequest("testUser", userRoles));
		assertThat(o).isNotNull();
		assertThat(o instanceof PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails).withFailMessage(
				"Returned object not of type PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails, actual type: "
						+ o.getClass())
				.isTrue();
		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = (PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails) o;
		List<GrantedAuthority> gas = details.getGrantedAuthorities();
		assertThat(gas).as("Granted authorities should not be null").isNotNull();
		assertThat(gas).hasSize(expectedRoles.length);
		Collection<String> expectedRolesColl = Arrays.asList(expectedRoles);
		Collection<String> gasRolesSet = new HashSet<>();
		for (GrantedAuthority grantedAuthority : gas) {
			gasRolesSet.add(grantedAuthority.getAuthority());
		}
		assertThat(expectedRolesColl.containsAll(gasRolesSet) && gasRolesSet.containsAll(expectedRolesColl))
				.withFailMessage("Granted Authorities do not match expected roles").isTrue();
	}

	private J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource getJ2eeBasedPreAuthenticatedWebAuthenticationDetailsSource(
			String[] mappedRoles) {
		J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource result = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
		result.setMappableRolesRetriever(getMappableRolesRetriever(mappedRoles));
		result.setUserRoles2GrantedAuthoritiesMapper(getJ2eeUserRoles2GrantedAuthoritiesMapper());
		result.afterPropertiesSet();
		return result;
	}

	private MappableAttributesRetriever getMappableRolesRetriever(String[] mappedRoles) {
		SimpleMappableAttributesRetriever result = new SimpleMappableAttributesRetriever();
		result.setMappableAttributes(new HashSet<>(Arrays.asList(mappedRoles)));
		return result;
	}

	private Attributes2GrantedAuthoritiesMapper getJ2eeUserRoles2GrantedAuthoritiesMapper() {
		SimpleAttributes2GrantedAuthoritiesMapper result = new SimpleAttributes2GrantedAuthoritiesMapper();
		result.setAddPrefixIfAlreadyExisting(false);
		result.setConvertAttributeToLowerCase(false);
		result.setConvertAttributeToUpperCase(false);
		result.setAttributePrefix("");
		return result;
	}

	private HttpServletRequest getRequest(final String userName, final String[] aRoles) {
		MockHttpServletRequest req = new MockHttpServletRequest() {
			private Set<String> roles = new HashSet<>(Arrays.asList(aRoles));

			@Override
			public boolean isUserInRole(String arg0) {
				return this.roles.contains(arg0);
			}
		};
		req.setRemoteUser(userName);
		return req;
	}

}
