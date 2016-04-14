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
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 */
public class RememberMeAuthenticationTokenMixinTest extends AbstractMixinTests {

	@Override
	public ObjectMapper buildObjectMapper() {
		return super.buildObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.addMixIn(User.class, UserMixin.class)
				.addMixIn(Collections.unmodifiableSet(Collections.EMPTY_SET).getClass(), UnmodifiableSetMixin.class)
				.addMixIn(RememberMeAuthenticationToken.class, RememberMeAuthenticationTokenMixin.class);
	}

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
		String key = "rememberMe";
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(key, "user", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		String expectedJson = "{\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\"," +
				"\"keyHash\": "+key.hashCode()+", \"principal\": \"user\", \"authenticated\": true, \"details\": null, \"name\": \"user\", \"credentials\": \"\"," +
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(expectedJson, actualJson, true);
	}

	@Test
	public void serializeRememberMeAuthenticationWithUserToken() throws JsonProcessingException, JSONException {
		String key = "rememberMe";
		List<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(key, new User("user", "password", authorities), authorities);
		String expectedJson = "{\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\"," +
				"\"keyHash\": "+key.hashCode()+", \"authenticated\": true, \"details\": null, \"name\": \"user\", \"credentials\": \"\"," +
				"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"user\", \"password\": \"password\", \"enabled\": true, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]},"+
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(expectedJson, actualJson, true);
	}

	@Test
	public void deserializeRememberMeAuthenticationToken() throws IOException {
		String key = "rememberMe";
		String expectedJson = "{\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\"," +
				"\"keyHash\": "+key.hashCode()+", \"principal\": \"user\", \"authenticated\": true, \"details\": null, \"name\": \"user\", \"credentials\": \"\"," +
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		RememberMeAuthenticationToken token = buildObjectMapper().readValue(expectedJson, RememberMeAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isEqualTo("user").isEqualTo(token.getName());
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void deserializeRememberMeAuthenticationTokenWithUserTest() throws IOException {
		String key = "rememberMe";
		String expectedJson = "{\"@class\": \"org.springframework.security.authentication.RememberMeAuthenticationToken\"," +
				"\"keyHash\": "+key.hashCode()+", \"authenticated\": true, \"details\": null, \"name\": \"user\", \"credentials\": \"\"," +
				"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"user\", \"password\": \"password\", \"enabled\": true, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]},"+
				"\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
		RememberMeAuthenticationToken token = buildObjectMapper().readValue(expectedJson, RememberMeAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User)token.getPrincipal()).getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(((User)token.getPrincipal()).isEnabled()).isEqualTo(true);
	}
}
