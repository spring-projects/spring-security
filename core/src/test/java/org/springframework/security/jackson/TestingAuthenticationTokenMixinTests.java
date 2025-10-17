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

package org.springframework.security.jackson;

import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link TestingAuthenticationTokenMixin}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class TestingAuthenticationTokenMixinTests extends AbstractMixinTests {

	private static final String EXPECTED_JSON = """
			{
				"@class": "org.springframework.security.authentication.TestingAuthenticationToken",
				"authorities": [
				  "java.util.Collections$UnmodifiableRandomAccessList",
				  [
				    {
				      "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
				      "authority": "ROLE_A"
				    },
				    {
				      "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
				      "authority": "ROLE_B"
				    }
				  ]
				],
				"details": null,
				"authenticated": true,
				"credentials": null,
				"principal": "principal"
			}""";

	private TestingAuthenticationToken expectedToken = new TestingAuthenticationToken("principal", null, "ROLE_A",
			"ROLE_B");

	@Test
	void serialize() throws Exception {
		String json = this.mapper.writeValueAsString(this.expectedToken);
		JSONAssert.assertEquals(EXPECTED_JSON, json, true);
	}

	@Test
	void deserialize() {
		TestingAuthenticationToken actual = (TestingAuthenticationToken) this.mapper.readValue(EXPECTED_JSON,
				Object.class);
		assertThat(actual).isEqualTo(this.expectedToken);
	}

}
