/*
 * Copyright 2015-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

	String hashKey = "key";
	String anonymousAuthTokenJson = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null," +
			"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"dummy\", \"password\": %s," +
			" \"accountNonExpired\": true, \"enabled\": true, " +
			"\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\"," +
			"[{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}]]}, \"authenticated\": true, \"keyHash\": " + hashKey.hashCode() + "," +
			"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}]]}";


	@Test
	public void serializeAnonymousAuthenticationTokenTest() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
				hashKey, user, user.getAuthorities()
		);
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(anonymousAuthTokenJson, "\"password\""), actualJson, true);
	}

	@Test
	public void deserializeAnonymousAuthenticationTokenTest() throws IOException {
		AnonymousAuthenticationToken token = buildObjectMapper()
				.readValue(String.format(anonymousAuthTokenJson,"\"password\""), AnonymousAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getKeyHash()).isEqualTo(hashKey.hashCode());
		assertThat(token.getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test(expected = JsonMappingException.class)
	public void deserializeAnonymousAuthenticationTokenWithoutAuthoritiesTest() throws IOException {
		String jsonString = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null," +
				"\"principal\": \"user\", \"authenticated\": true, \"keyHash\": " + hashKey.hashCode() + "," +
				"\"authorities\": [\"java.util.ArrayList\", []]}";
		buildObjectMapper().readValue(jsonString, AnonymousAuthenticationToken.class);
	}

	@Test
	public void serializeAnonymousAuthenticationTokenMixinAfterEraseCredentialTest() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
				hashKey, user, user.getAuthorities()
		);
		token.eraseCredentials();
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(anonymousAuthTokenJson, "null"), actualJson, true);
	}
}
