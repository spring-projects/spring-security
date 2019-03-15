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
import java.util.ArrayList;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh
 * @author Greg Turnquist
 * @since 4.2
 */
public class UsernamePasswordAuthenticationTokenMixinTests extends AbstractMixinTests {
	// @formatter:off
	private static final String AUTHENTICATED_JSON = "{"
		+ "\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\","
		+ "\"principal\": "+ UserDeserializerTests.USER_JSON + ", "
		+ "\"credentials\": \"1234\", "
		+ "\"authenticated\": true, "
		+ "\"details\": null, "
		+ "\"authorities\": "+ SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON
	+ "}";
	// @formatter:on

	// @formatter:off
	public static final String AUTHENTICATED_STRINGPRINCIPAL_JSON = AUTHENTICATED_JSON.replace( UserDeserializerTests.USER_JSON, "\"admin\"");
	// @formatter:on

	// @formatter:off
	private static final String NON_USER_PRINCIPAL_JSON = "{"
		+ "\"@class\": \"org.springframework.security.jackson2.UsernamePasswordAuthenticationTokenMixinTests$NonUserPrincipal\", "
		+ "\"username\": \"admin\""
		+ "}";
	// @formatter:on

	// @formatter:off
	private static final String AUTHENTICATED_NON_USER_PRINCIPAL_JSON = AUTHENTICATED_JSON
		.replace(UserDeserializerTests.USER_JSON, NON_USER_PRINCIPAL_JSON)
		.replaceAll(UserDeserializerTests.USER_PASSWORD, "null")
		.replace(SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON, SimpleGrantedAuthorityMixinTests.NO_AUTHORITIES_ARRAYLIST_JSON);
	// @formatter:on

	// @formatter:off
	private static final String UNAUTHENTICATED_STRINGPRINCIPAL_JSON = AUTHENTICATED_STRINGPRINCIPAL_JSON
		.replace("\"authenticated\": true, ", "\"authenticated\": false, ")
		.replace(SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON, SimpleGrantedAuthorityMixinTests.EMPTY_AUTHORITIES_ARRAYLIST_JSON);
	// @formatter:on

	@Test
	public void serializeUnauthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws JsonProcessingException, JSONException {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("admin", "1234");
		String serializedJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(UNAUTHENTICATED_STRINGPRINCIPAL_JSON, serializedJson, true);
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
		String serializedJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(AUTHENTICATED_STRINGPRINCIPAL_JSON, serializedJson, true);
	}

	@Test
	public void deserializeUnauthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws IOException, JSONException {
		UsernamePasswordAuthenticationToken token = mapper
				.readValue(UNAUTHENTICATED_STRINGPRINCIPAL_JSON, UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.isAuthenticated()).isEqualTo(false);
		assertThat(token.getAuthorities()).isNotNull().hasSize(0);
	}

	@Test
	public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws IOException {
		UsernamePasswordAuthenticationToken expectedToken = createToken();
		UsernamePasswordAuthenticationToken token = mapper
				.readValue(AUTHENTICATED_STRINGPRINCIPAL_JSON, UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.isAuthenticated()).isTrue();
		assertThat(token.getAuthorities()).isEqualTo(expectedToken.getAuthorities());
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinWithUserTest() throws JsonProcessingException, JSONException {
		UsernamePasswordAuthenticationToken token = createToken();
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(AUTHENTICATED_JSON, actualJson, true);
	}

	@Test
	public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenWithUserTest() throws IOException {
		UsernamePasswordAuthenticationToken token = mapper
				.readValue(AUTHENTICATED_JSON, UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User)token.getPrincipal()).getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.isAuthenticated()).isEqualTo(true);
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinAfterEraseCredentialInvoked() throws JsonProcessingException, JSONException {
		UsernamePasswordAuthenticationToken token = createToken();
		token.eraseCredentials();
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(AUTHENTICATED_JSON.replaceAll(UserDeserializerTests.USER_PASSWORD, "null"), actualJson, true);
	}

	@Test
	public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinWithNonUserPrincipalTest() throws JsonProcessingException, JSONException {
		NonUserPrincipal principal = new NonUserPrincipal();
		principal.setUsername("admin");
		UsernamePasswordAuthenticationToken token =
			new UsernamePasswordAuthenticationToken(principal, null, new ArrayList<GrantedAuthority>());
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(AUTHENTICATED_NON_USER_PRINCIPAL_JSON, actualJson, true);
	}

	@Test
	public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenWithNonUserPrincipalTest() throws IOException {
		UsernamePasswordAuthenticationToken token = mapper
			.readValue(AUTHENTICATED_NON_USER_PRINCIPAL_JSON, UsernamePasswordAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(NonUserPrincipal.class);
	}

	@Test
	public void serializingThenDeserializingWithNoCredentialsOrDetailsShouldWork() throws IOException {
		// given
		UsernamePasswordAuthenticationToken original = new UsernamePasswordAuthenticationToken("Frodo", null);

		// when
		String serialized = this.mapper.writeValueAsString(original);
		UsernamePasswordAuthenticationToken deserialized = this.mapper.readValue(serialized, UsernamePasswordAuthenticationToken.class);

		// then
		assertThat(deserialized).isEqualTo(original);
	}


	private UsernamePasswordAuthenticationToken createToken() {
		User user = createDefaultUser();
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
		return token;
	}

	@JsonClassDescription
	public static class NonUserPrincipal {
		private String username;

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}
	}
}
