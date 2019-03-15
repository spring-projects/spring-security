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
package org.springframework.security.cas.userdetails;

import static org.assertj.core.api.Assertions.*;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.junit.Test;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author Luke Taylor
 */
public class GrantedAuthorityFromAssertionAttributesUserDetailsServiceTests {

	@Test
	public void correctlyExtractsNamedAttributesFromAssertionAndConvertsThemToAuthorities() {
		GrantedAuthorityFromAssertionAttributesUserDetailsService uds = new GrantedAuthorityFromAssertionAttributesUserDetailsService(
				new String[] { "a", "b", "c", "d" });
		uds.setConvertToUpperCase(false);
		Assertion assertion = mock(Assertion.class);
		AttributePrincipal principal = mock(AttributePrincipal.class);
		Map<String, Object> attributes = new HashMap<String, Object>();
		attributes.put("a", Arrays.asList("role_a1", "role_a2"));
		attributes.put("b", "role_b");
		attributes.put("c", "role_c");
		attributes.put("d", null);
		attributes.put("someother", "unused");
		when(assertion.getPrincipal()).thenReturn(principal);
		when(principal.getAttributes()).thenReturn(attributes);
		when(principal.getName()).thenReturn("somebody");
		CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(
				assertion, "ticket");
		UserDetails user = uds.loadUserDetails(token);
		Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities());
		assertThat(roles).containsOnly(
				"role_a1", "role_a2", "role_b", "role_c");
	}
}
