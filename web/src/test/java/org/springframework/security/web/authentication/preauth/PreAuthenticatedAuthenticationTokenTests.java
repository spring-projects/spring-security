/*
 * Copyright 2004-present the original author or authors.
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

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationTokenTests {

	@Test
	public void testPreAuthenticatedAuthenticationTokenRequestWithDetails() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		Object details = "dummyDetails";
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials);
		token.setDetails(details);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isEqualTo(details);
		assertThat(token.getAuthorities()).isEmpty();
	}

	@Test
	public void testPreAuthenticatedAuthenticationTokenRequestWithoutDetails() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isNull();
		assertThat(token.getAuthorities()).isEmpty();
	}

	@Test
	public void testPreAuthenticatedAuthenticationTokenResponse() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		List<GrantedAuthority> gas = AuthorityUtils.createAuthorityList("Role1");
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials,
				gas);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isNull();
		assertThat(token.getAuthorities()).isNotNull();
		Collection<GrantedAuthority> resultColl = token.getAuthorities();
		assertThat(gas.containsAll(resultColl) && resultColl.containsAll(gas))
			.withFailMessage("GrantedAuthority collections do not match; result: " + resultColl + ", expected: " + gas)
			.isTrue();
	}

	@Test
	public void toBuilderWhenApplyThenCopies() {
		PreAuthenticatedAuthenticationToken factorOne = new PreAuthenticatedAuthenticationToken("alice", "pass",
				AuthorityUtils.createAuthorityList("FACTOR_ONE"));
		PreAuthenticatedAuthenticationToken factorTwo = new PreAuthenticatedAuthenticationToken("bob", "ssap",
				AuthorityUtils.createAuthorityList("FACTOR_TWO"));
		PreAuthenticatedAuthenticationToken result = factorOne.toBuilder()
			.authorities((a) -> a.addAll(factorTwo.getAuthorities()))
			.principal(factorTwo.getPrincipal())
			.credentials(factorTwo.getCredentials())
			.build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isSameAs(factorTwo.getPrincipal());
		assertThat(result.getCredentials()).isSameAs(factorTwo.getCredentials());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
