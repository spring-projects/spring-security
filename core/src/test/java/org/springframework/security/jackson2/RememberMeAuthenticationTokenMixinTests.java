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

	String rememberMeKey = "rememberMe";
	String rememberMeAuthTokenJson = "{\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\"," +
			"\"keyHash\": " + rememberMeKey.hashCode() + ", \"authenticated\": true, \"details\": null," +
			"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"dummy\", \"password\": %s," +
			" \"enabled\": true, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, " +
			"\"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}," +
			"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";

	String rememberMeAuthTokenWithoutUserJson = "{\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\"," +
			"\"keyHash\": " + rememberMeKey.hashCode() + ", \"authenticated\": true, \"details\": null," +
			"\"principal\": \"dummy\", \"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";

	@Test(expected = IllegalArgumentException.class)
	public void testWithNullPrincipal() throws JsonProcessingException, JSONException {
		new RememberMeAuthenticationToken("key", null, Collections.<GrantedAuthority>emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testWithNullKey() throws JsonProcessingException, JSONException {
		new RememberMeAuthenticationToken(null, "principal", Collections.<GrantedAuthority>emptyList());
	}

	@Test
	public void serializeRememberMeAuthenticationToken() throws JsonProcessingException, JSONException {
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(rememberMeKey, "dummy", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(rememberMeAuthTokenWithoutUserJson, actualJson, true);
	}

	@Test
	public void serializeRememberMeAuthenticationWithUserToken() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(rememberMeKey, user, user.getAuthorities());
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(rememberMeAuthTokenJson, "\"password\""), actualJson, true);
	}

	@Test
	public void serializeRememberMeAuthenticationWithUserTokenAfterEraseCredential() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(rememberMeKey, user, user.getAuthorities());
		token.eraseCredentials();
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(rememberMeAuthTokenJson, "null"), actualJson, true);
	}

	@Test
	public void deserializeRememberMeAuthenticationToken() throws IOException {
		RememberMeAuthenticationToken token = buildObjectMapper().readValue(rememberMeAuthTokenWithoutUserJson, RememberMeAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isEqualTo("dummy").isEqualTo(token.getName());
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void deserializeRememberMeAuthenticationTokenWithUserTest() throws IOException {
		RememberMeAuthenticationToken token = buildObjectMapper()
				.readValue(String.format(rememberMeAuthTokenJson, "\"password\""), RememberMeAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User)token.getPrincipal()).getUsername()).isEqualTo("dummy");
		assertThat(((User)token.getPrincipal()).getPassword()).isEqualTo("password");
		assertThat(((User) token.getPrincipal()).getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(((User) token.getPrincipal()).isEnabled()).isEqualTo(true);
	}
}
