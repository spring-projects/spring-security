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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationTokenTests {

	@Test
	public void testPreAuthenticatedAuthenticationTokenRequestWithDetails() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		Object details = "dummyDetails";
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
				principal, credentials);
		token.setDetails(details);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isEqualTo(details);
		assertThat(token.getAuthorities().isEmpty()).isTrue();
	}

	@Test
	public void testPreAuthenticatedAuthenticationTokenRequestWithoutDetails() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
				principal, credentials);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isNull();
		assertThat(token.getAuthorities().isEmpty()).isTrue();
	}

	@Test
	public void testPreAuthenticatedAuthenticationTokenResponse() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		List<GrantedAuthority> gas = AuthorityUtils.createAuthorityList("Role1");
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
				principal, credentials, gas);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isNull();
		assertThat(token.getAuthorities()).isNotNull();
		Collection<GrantedAuthority> resultColl = token.getAuthorities();
		assertThat(

		gas.containsAll(resultColl) && resultColl.containsAll(gas)).withFailMessage(
				"GrantedAuthority collections do not match; result: " + resultColl
						+ ", expected: " + gas).isTrue();

	}

}
