/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.preauth;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author TSARDD
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetailsTests {

	List<GrantedAuthority> gas = AuthorityUtils.createAuthorityList("Role1", "Role2");

	@Test
	public void testToString() {
		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
				getRequest("testUser", new String[] {}), this.gas);
		String toString = details.toString();
		assertThat(toString.contains("Role1")).as("toString should contain Role1").isTrue();
		assertThat(toString.contains("Role2")).as("toString should contain Role2").isTrue();
	}

	@Test
	public void testGetSetPreAuthenticatedGrantedAuthorities() {
		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
				getRequest("testUser", new String[] {}), this.gas);
		List<GrantedAuthority> returnedGas = details.getGrantedAuthorities();
		assertThat(this.gas.containsAll(returnedGas) && returnedGas.containsAll(this.gas)).withFailMessage(
				"Collections do not contain same elements; expected: " + this.gas + ", returned: " + returnedGas)
				.isTrue();
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
