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

package org.springframework.security.authentication.ott;

import java.util.Set;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jackson.SecurityJacksonModules;

import static org.assertj.core.api.Assertions.assertThat;

class OneTimeTokenAuthenticationTests {

	@Test
	void toBuilderWhenApplyThenCopies() {
		OneTimeTokenAuthentication factorOne = new OneTimeTokenAuthentication("alice",
				AuthorityUtils.createAuthorityList("FACTOR_ONE"));
		OneTimeTokenAuthentication factorTwo = new OneTimeTokenAuthentication("bob",
				AuthorityUtils.createAuthorityList("FACTOR_TWO"));
		OneTimeTokenAuthentication result = factorOne.toBuilder()
			.authorities((a) -> a.addAll(factorTwo.getAuthorities()))
			.principal(factorTwo.getPrincipal())
			.build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isSameAs(factorTwo.getPrincipal());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

	// gh-18095
	@Test
	void shouldBeAbleToDeserializeFromJsonWithDefaultTypingActivated() {
		JsonMapper mapper = JsonMapper.builder()
			.addModules(SecurityJacksonModules.getModules(getClass().getClassLoader()))
			.build();
		OneTimeTokenAuthentication oneTimeTokenAuthentication = new OneTimeTokenAuthentication("principal",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		byte[] serialized = mapper.writeValueAsBytes(oneTimeTokenAuthentication);
		OneTimeTokenAuthentication deserialized = mapper.readValue(serialized, OneTimeTokenAuthentication.class);
		assertThat(deserialized.getPrincipal()).isEqualTo(oneTimeTokenAuthentication.getPrincipal());
		assertThat(deserialized.getAuthorities()).extracting(GrantedAuthority::getAuthority).contains("ROLE_USER");
	}

}
