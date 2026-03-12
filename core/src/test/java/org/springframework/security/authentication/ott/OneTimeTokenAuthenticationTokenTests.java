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

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jackson2.SecurityJackson2Modules;

import static org.assertj.core.api.Assertions.assertThat;

class OneTimeTokenAuthenticationTokenTests {

	// gh-18095
	@Test
	@SuppressWarnings("removal")
	void shouldBeAbleToDeserializeFromJsonWithDefaultTypingActivated() throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
		OneTimeTokenAuthenticationToken oneTimeTokenAuthenticationToken = new OneTimeTokenAuthenticationToken(
				"principal", AuthorityUtils.createAuthorityList("ROLE_USER"));
		byte[] serialized = mapper.writeValueAsBytes(oneTimeTokenAuthenticationToken);
		OneTimeTokenAuthenticationToken deserialized = mapper.readValue(serialized,
				OneTimeTokenAuthenticationToken.class);
		assertThat(deserialized.getPrincipal()).isEqualTo(oneTimeTokenAuthenticationToken.getPrincipal());
		assertThat(deserialized.getAuthorities()).extracting(GrantedAuthority::getAuthority).contains("ROLE_USER");
	}

}
