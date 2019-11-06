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

import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
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
public class RememberMeAuthenticationTokenMixinTests extends AbstractMixinTests {

	private static final String REMEMBERME_KEY = "rememberMe";

	// @formatter:off
	private static final String REMEMBERME_AUTH_JSON = "{"
		+ "\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\", "
		+ "\"keyHash\": " + REMEMBERME_KEY.hashCode() + ", "
		+ "\"authenticated\": true, \"details\": null" + ", "
		+ "\"principal\": " + UserDeserializerTests.USER_JSON + ", "
		+ "\"authorities\": " + SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON
	+ "}";
	// @formatter:on

	// @formatter:off
	private static final String REMEMBERME_AUTH_STRINGPRINCIPAL_JSON = "{"
		+ "\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\","
		+ "\"keyHash\": " + REMEMBERME_KEY.hashCode() + ", "
		+ "\"authenticated\": true, "
		+ "\"details\": null,"
		+ "\"principal\": \"admin\", "
		+ "\"authorities\": " + SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON
	+ "}";
	// @formatter:on

	@Test(expected = IllegalArgumentException.class)
	public void testWithNullPrincipal() {
		new RememberMeAuthenticationToken("key", null, Collections.<GrantedAuthority>emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testWithNullKey() {
		new RememberMeAuthenticationToken(null, "principal", Collections.<GrantedAuthority>emptyList());
	}

	@Test
	public void serializeRememberMeAuthenticationToken() throws JsonProcessingException, JSONException {
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(REMEMBERME_KEY, "admin", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(REMEMBERME_AUTH_STRINGPRINCIPAL_JSON, actualJson, true);
	}

	@Test
	public void serializeRememberMeAuthenticationWithUserToken() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(REMEMBERME_KEY, user, user.getAuthorities());
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(String.format(REMEMBERME_AUTH_JSON, "\"password\""), actualJson, true);
	}

	@Test
	public void serializeRememberMeAuthenticationWithUserTokenAfterEraseCredential() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(REMEMBERME_KEY, user, user.getAuthorities());
		token.eraseCredentials();
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(REMEMBERME_AUTH_JSON.replace(UserDeserializerTests.USER_PASSWORD, "null"), actualJson, true);
	}

	@Test
	public void deserializeRememberMeAuthenticationToken() throws IOException {
		RememberMeAuthenticationToken token = mapper.readValue(REMEMBERME_AUTH_STRINGPRINCIPAL_JSON, RememberMeAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isEqualTo("admin").isEqualTo(token.getName());
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void deserializeRememberMeAuthenticationTokenWithUserTest() throws IOException {
		RememberMeAuthenticationToken token = mapper
				.readValue(String.format(REMEMBERME_AUTH_JSON, "\"password\""), RememberMeAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User) token.getPrincipal()).getUsername()).isEqualTo("admin");
		assertThat(((User) token.getPrincipal()).getPassword()).isEqualTo("1234");
		assertThat(((User) token.getPrincipal()).getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(((User) token.getPrincipal()).isEnabled()).isEqualTo(true);
	}
}
