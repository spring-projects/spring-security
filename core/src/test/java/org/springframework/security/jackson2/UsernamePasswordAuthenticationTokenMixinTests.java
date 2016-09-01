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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
public class UsernamePasswordAuthenticationTokenMixinTests extends AbstractMixinTests {

	String unauthenticatedTokenWithoutUserPrincipal = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
			" \"principal\": \"user1\", \"credentials\": \"password\", \"authenticated\": false, \"details\": null, " +
			"\"authorities\": [\"java.util.ArrayList\", []]}";

	String authenticatedTokenWithoutUserPrincipal = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
			" \"principal\": \"user1\", \"credentials\": \"password\", \"authenticated\": true, \"details\": null, " +
			"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}]]}";

	String authenticatedTokenWithUserPrincipal = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
			"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"user\", \"password\": %s, \"accountNonExpired\": true, \"enabled\": true, " +
			"\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\"," +
			"[{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}]]}, \"credentials\": %s," +
			"\"details\": null, \"authenticated\": true," +
			"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}]]}";

	@Test
	public void serializeUnauthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws JsonProcessingException, JSONException {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user1", "password");
		String serializedJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(unauthenticatedTokenWithoutUserPrincipal, serializedJson, true);
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws JsonProcessingException, JSONException {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user1", "password", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
		String serializedJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(authenticatedTokenWithoutUserPrincipal, serializedJson, true);
	}

	@Test
	public void deserializeUnauthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws IOException, JSONException {
		UsernamePasswordAuthenticationToken token = buildObjectMapper()
				.readValue(unauthenticatedTokenWithoutUserPrincipal, UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.isAuthenticated()).isEqualTo(false);
		assertThat(token.getAuthorities()).isNotNull().hasSize(0);
	}

	@Test
	public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws IOException {
		UsernamePasswordAuthenticationToken token = buildObjectMapper()
				.readValue(authenticatedTokenWithoutUserPrincipal, UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.isAuthenticated()).isEqualTo(true);
		assertThat(token.getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinWithUserTest() throws JsonProcessingException, JSONException {
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		User user = new User("user", "password", Collections.singleton(authority));
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, "password", Collections.singleton(authority));
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(authenticatedTokenWithUserPrincipal, "password", "password"), actualJson, true);
	}

	@Test
	public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenWithUserTest() throws IOException {
		ObjectMapper mapper = buildObjectMapper();
		UsernamePasswordAuthenticationToken token = mapper
				.readValue(String.format(authenticatedTokenWithUserPrincipal, "\"password\"", "\"password\""), UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User)token.getPrincipal()).getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.isAuthenticated()).isEqualTo(true);
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinAfterEraseCredentialInvoked() throws JsonProcessingException, JSONException {
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		User user = new User("user", "password", Collections.singleton(authority));
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, "password", Collections.singleton(authority));
		token.eraseCredentials();
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(authenticatedTokenWithUserPrincipal, "null", "null"), actualJson, true);
	}
}
