/*
 * Copyright 2015-2016 the original author or authors.
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class AnonymousAuthenticationTokenMixinTests extends AbstractMixinTests {

	private static final String HASH_KEY = "key";

	// @formatter:off
	private static final String ANONYMOUS_JSON = "{"
		+ "\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", "
		+ "\"details\": null,"
		+ "\"principal\": " + UserDeserializerTests.USER_JSON + ","
		+ "\"authenticated\": true, "
		+ "\"keyHash\": " + HASH_KEY.hashCode() + ","
		+ "\"authorities\": " + SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON
	+ "}";
	// @formatter:on

	@Test
	public void serializeAnonymousAuthenticationTokenTest() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(HASH_KEY, user, user.getAuthorities());
		String actualJson = this.mapper.writeValueAsString(token);
		JSONAssert.assertEquals(ANONYMOUS_JSON, actualJson, true);
	}

	@Test
	public void deserializeAnonymousAuthenticationTokenTest() throws IOException {
		AnonymousAuthenticationToken token = this.mapper.readValue(ANONYMOUS_JSON, AnonymousAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getKeyHash()).isEqualTo(HASH_KEY.hashCode());
		assertThat(token.getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test(expected = JsonMappingException.class)
	public void deserializeAnonymousAuthenticationTokenWithoutAuthoritiesTest() throws IOException {
		String jsonString = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null,"
				+ "\"principal\": \"user\", \"authenticated\": true, \"keyHash\": " + HASH_KEY.hashCode() + ","
				+ "\"authorities\": [\"java.util.ArrayList\", []]}";
		this.mapper.readValue(jsonString, AnonymousAuthenticationToken.class);
	}

	@Test
	public void serializeAnonymousAuthenticationTokenMixinAfterEraseCredentialTest()
			throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(HASH_KEY, user, user.getAuthorities());
		token.eraseCredentials();
		String actualJson = this.mapper.writeValueAsString(token);
		JSONAssert.assertEquals(ANONYMOUS_JSON.replace(UserDeserializerTests.USER_PASSWORD, "null"), actualJson, true);
	}

}
