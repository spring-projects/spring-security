/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.jackson2;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jackson2.AbstractMixinTests;
import org.springframework.security.jackson2.SimpleGrantedAuthorityMixinTests;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Markus Heiden
 * @since 5.8
 */
public class SwitchUserGrantedAuthorityMixInTest extends AbstractMixinTests {

	// language=JSON
	private static final String SWITCH_JSON = """
			{
				"@class": "org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority",
				"role": "switched",
				"source": {
					"@class": "org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
					"principal": "principal",
					"credentials": "credentials",
					"authenticated": true,
					"details": null,
					"authorities": %s
				}
			}
			""".formatted(SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON);
	SwitchUserGrantedAuthority expected;

	Authentication source;

	@BeforeEach
	public void setupExpected() {
		this.source = new UsernamePasswordAuthenticationToken("principal", "credentials",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.expected = new SwitchUserGrantedAuthority("switched", this.source);
	}

	@Test
	public void serializeWhenPrincipalCredentialsAuthoritiesThenSuccess() throws Exception {
		String serializedJson = this.mapper.writeValueAsString(this.expected);
		JSONAssert.assertEquals(SWITCH_JSON, serializedJson, true);
	}

	@Test
	public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws Exception {
		SwitchUserGrantedAuthority deserialized = this.mapper.readValue(SWITCH_JSON, SwitchUserGrantedAuthority.class);
		assertThat(deserialized).isNotNull();
		assertThat(deserialized.getAuthority()).isEqualTo("switched");
		assertThat(deserialized.getSource()).isEqualTo(this.source);
	}

}
