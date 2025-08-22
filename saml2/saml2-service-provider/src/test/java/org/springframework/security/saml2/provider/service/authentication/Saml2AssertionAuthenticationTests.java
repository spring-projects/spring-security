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

package org.springframework.security.saml2.provider.service.authentication;

import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

class Saml2AssertionAuthenticationTests {

	@Test
	void toBuilderWhenApplyThenCopies() {
		Saml2ResponseAssertion.Builder prototype = Saml2ResponseAssertion.withResponseValue("response");
		Saml2AssertionAuthentication factorOne = new Saml2AssertionAuthentication("alice",
				prototype.nameId("alice").build(), AuthorityUtils.createAuthorityList("FACTOR_ONE"), "alice");
		Saml2AssertionAuthentication factorTwo = new Saml2AssertionAuthentication("bob",
				prototype.nameId("alice").build(), AuthorityUtils.createAuthorityList("FACTOR_TWO"), "bob");
		Saml2AssertionAuthentication result = factorOne.toBuilder().apply(factorTwo).build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isSameAs(factorTwo.getPrincipal());
		assertThat(result.getCredentials()).isSameAs(factorTwo.getCredentials());
		assertThat(result.getRelyingPartyRegistrationId()).isSameAs(factorTwo.getRelyingPartyRegistrationId());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
