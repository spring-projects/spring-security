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

package org.springframework.security.jackson2;

import java.io.IOException;
import java.time.Instant;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 7.0
 */
class FactorGrantedAuthorityMixinTests extends AbstractMixinTests {

	// @formatter:off
	public static final String AUTHORITY_JSON = "{\"@class\": \"org.springframework.security.core.authority.FactorGrantedAuthority\", \"authority\": \"FACTOR_PASSWORD\", \"issuedAt\": 1759177143.043000000 }";

	private Instant issuedAt = Instant.ofEpochMilli(1759177143043L);

	// @formatter:on

	@Test
	void serializeSimpleGrantedAuthorityTest() throws JsonProcessingException, JSONException {
		GrantedAuthority authority = FactorGrantedAuthority.withAuthority("FACTOR_PASSWORD")
			.issuedAt(this.issuedAt)
			.build();
		String serializeJson = this.mapper.writeValueAsString(authority);
		JSONAssert.assertEquals(AUTHORITY_JSON, serializeJson, true);
	}

	@Test
	void deserializeGrantedAuthorityTest() throws IOException {
		FactorGrantedAuthority authority = (FactorGrantedAuthority) this.mapper.readValue(AUTHORITY_JSON, Object.class);
		assertThat(authority).isNotNull();
		assertThat(authority.getAuthority()).isEqualTo("FACTOR_PASSWORD");
		assertThat(authority.getIssuedAt()).isEqualTo(this.issuedAt);
	}

}
