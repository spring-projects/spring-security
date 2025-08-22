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

package org.springframework.security.authentication.jaas;

import java.util.Set;

import javax.security.auth.login.LoginContext;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class JaasAuthenticationTokenTests {

	@Test
	void toBuilderWhenApplyThenCopies() {
		JaasAuthenticationToken factorOne = new JaasAuthenticationToken("alice", "pass",
				AuthorityUtils.createAuthorityList("FACTOR_ONE"), mock(LoginContext.class));
		JaasAuthenticationToken factorTwo = new JaasAuthenticationToken("bob", "ssap",
				AuthorityUtils.createAuthorityList("FACTOR_TWO"), mock(LoginContext.class));
		JaasAuthenticationToken result = factorOne.toBuilder().apply(factorTwo).build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isSameAs(factorTwo.getPrincipal());
		assertThat(result.getCredentials()).isSameAs(factorTwo.getCredentials());
		assertThat(result.getLoginContext()).isSameAs(factorTwo.getLoginContext());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
