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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class AnonymousAuthenticationTokenMixinTests extends AbstractMixinTests {

	@Test(expected = IllegalArgumentException.class)
	public void testWithNullAuthorities() throws JsonProcessingException, JSONException {
		new AnonymousAuthenticationToken("key", "principal", null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testWithEmptyAuthorities() throws JsonProcessingException, JSONException {
		new AnonymousAuthenticationToken("key", "principal", Collections.<GrantedAuthority>emptyList());
	}

	@Test
	public void serializeAnonymousAuthenticationTokenTest() throws JsonProcessingException, JSONException {
		String key = "key";
		String expectedJson = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null,"+
				"\"principal\": \"user\", \"authenticated\": true, \"keyHash\": "+key.hashCode()+","+
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
				key, "user", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
		);
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(expectedJson, actualJson, true);
	}

	@Test
	public void deserializeAnonymousAuthenticationTokenTest() throws IOException {
		String key = "123456789";
		String jsonString = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null,"+
				"\"principal\": \"user\", \"authenticated\": true, \"keyHash\": "+key.hashCode()+","+
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		AnonymousAuthenticationToken token = buildObjectMapper().readValue(jsonString, AnonymousAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getKeyHash()).isEqualTo(key.hashCode());
		assertThat(token.getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test(expected = JsonMappingException.class)
	public void deserializeAnonymousAuthenticationTokenWithoutAuthoritiesTest() throws IOException {
		String key = "123456789";
		String jsonString = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null,"+
				"\"principal\": \"user\", \"authenticated\": true, \"keyHash\": "+key.hashCode()+","+
				"\"authorities\": [\"java.util.ArrayList\", []]}";
		buildObjectMapper().readValue(jsonString, AnonymousAuthenticationToken.class);
	}

	@Test
	public void serializeAnonymousAuthenticationTokenMixinAfterEraseCredentialTest() throws JsonProcessingException, JSONException {
		String key = "key";
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		User user = new User("user", "password", Collections.singleton(authority));
		String expectedJson = "{\"@class\": \"org.springframework.security.authentication.AnonymousAuthenticationToken\", \"details\": null,"+
				"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"user\", \"password\": null, \"accountNonExpired\": true, \"enabled\": true, " +
				"\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\"," +
				"[{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}, \"authenticated\": true, \"keyHash\": "+key.hashCode()+","+
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
				key, user, Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
		);
		token.eraseCredentials();
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(expectedJson, actualJson, true);
	}
}
