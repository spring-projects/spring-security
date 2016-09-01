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
public class UserDeserializerTests extends AbstractMixinTests {

	String userWithAuthoritiesJson = "{\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"admin\"," +
			" \"password\": %s, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, " +
			"\"enabled\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}]]}";

	String userWithoutAuthoritiesJson = "{\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"admin\"," +
			" \"password\": \"1234\", \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true," +
			" \"enabled\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", []]}";

	@Test
	public void serializeUserTest() throws JsonProcessingException, JSONException {
		ObjectMapper mapper = buildObjectMapper();
		User user = new User("admin", "1234", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
		String userJson = mapper.writeValueAsString(user);
		JSONAssert.assertEquals(String.format(userWithAuthoritiesJson, "\"1234\""), userJson, true);
	}

	@Test
	public void serializeUserWithoutAuthority() throws JsonProcessingException, JSONException {
		ObjectMapper mapper = buildObjectMapper();
		User user = new User("admin", "1234", Collections.<GrantedAuthority>emptyList());
		String userJson = mapper.writeValueAsString(user);
		JSONAssert.assertEquals(userWithoutAuthoritiesJson, userJson, true);
	}

	@Test(expected = IllegalArgumentException.class)
	public void deserializeUserWithNullPasswordEmptyAuthorityTest() throws IOException {
		String userJsonWithoutPasswordString = "{\"@class\": \"org.springframework.security.core.userdetails.User\", " +
				"\"username\": \"user\", \"accountNonExpired\": true, " +
				"\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"enabled\": true, " +
				"\"authorities\": []}";
		ObjectMapper mapper = buildObjectMapper();
		mapper.readValue(userJsonWithoutPasswordString, User.class);
	}

	@Test
	public void deserializeUserWithNullPasswordNoAuthorityTest() throws IOException {
		String userJsonWithoutPasswordString = "{\"@class\": \"org.springframework.security.core.userdetails.User\", " +
				"\"username\": \"admin\", \"accountNonExpired\": true, " +
				"\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"enabled\": true, " +
				"\"authorities\": [\"java.util.HashSet\", []]}";
		ObjectMapper mapper = buildObjectMapper();
		User user = mapper.readValue(userJsonWithoutPasswordString, User.class);
		assertThat(user).isNotNull();
		assertThat(user.getUsername()).isEqualTo("admin");
		assertThat(user.getPassword()).isEqualTo("");
		assertThat(user.getAuthorities()).hasSize(0);
		assertThat(user.isEnabled()).isEqualTo(true);
	}

	@Test(expected = IllegalArgumentException.class)
	public void deserializeUserWithNoClassIdInAuthoritiesTest() throws IOException {
		String userJson = "{\"@class\": \"org.springframework.security.core.userdetails.User\", " +
				"\"username\": \"user\", \"password\": \"pass\", \"accountNonExpired\": false, " +
				"\"accountNonLocked\": false, \"credentialsNonExpired\": false, \"enabled\": false, " +
				"\"authorities\": [{\"authority\": \"ROLE_USER\"}]}";
		buildObjectMapper().readValue(userJson, User.class);
	}

	@Test
	public void deserializeUserWithClassIdInAuthoritiesTest() throws IOException {
		User user = buildObjectMapper().readValue(String.format(userWithAuthoritiesJson, "\"1234\""), User.class);
		assertThat(user).isNotNull();
		assertThat(user.getUsername()).isEqualTo("admin");
		assertThat(user.getPassword()).isEqualTo("1234");
		assertThat(user.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}
}
