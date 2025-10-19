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

package org.springframework.security.jackson;

import java.io.IOException;
import java.util.Collections;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class UserDeserializerTests extends AbstractMixinTests {

	public static final String USER_PASSWORD = "\"1234\"";

	// @formatter:off
	public static final String USER_JSON = "{"
		+ "\"@class\": \"org.springframework.security.core.userdetails.User\", "
		+ "\"username\": \"admin\","
		+ " \"password\": " + USER_PASSWORD + ", "
		+ "\"accountNonExpired\": true, "
		+ "\"accountNonLocked\": true, "
		+ "\"credentialsNonExpired\": true, "
		+ "\"enabled\": true, "
		+ "\"authorities\": " + SimpleGrantedAuthorityMixinTests.AUTHORITIES_SET_JSON
	+ "}";
	// @formatter:on
	@Test
	public void serializeUserTest() throws JsonProcessingException, JSONException {
		User user = createDefaultUser();
		String userJson = this.mapper.writeValueAsString(user);
		JSONAssert.assertEquals(userWithPasswordJson(user.getPassword()), userJson, true);
	}

	@Test
	public void serializeUserWithoutAuthority() throws JsonProcessingException, JSONException {
		User user = new User("admin", "1234", Collections.<GrantedAuthority>emptyList());
		String userJson = this.mapper.writeValueAsString(user);
		JSONAssert.assertEquals(userWithNoAuthoritiesJson(), userJson, true);
	}

	@Test
	public void deserializeUserWithNullPasswordEmptyAuthorityTest() throws IOException {
		String userJsonWithoutPasswordString = USER_JSON.replace(SimpleGrantedAuthorityMixinTests.AUTHORITIES_SET_JSON,
				"[]");
		assertThatExceptionOfType(MismatchedInputException.class)
			.isThrownBy(() -> this.mapper.readValue(userJsonWithoutPasswordString, User.class));
	}

	@Test
	public void deserializeUserWithNullPasswordNoAuthorityTest() throws Exception {
		String userJsonWithoutPasswordString = removeNode(userWithNoAuthoritiesJson(), this.mapper, "password");
		User user = this.mapper.readValue(userJsonWithoutPasswordString, User.class);
		assertThat(user).isNotNull();
		assertThat(user.getUsername()).isEqualTo("admin");
		assertThat(user.getPassword()).isNull();
		assertThat(user.getAuthorities()).isEmpty();
		assertThat(user.isEnabled()).isEqualTo(true);
	}

	@Test
	public void deserializeUserWithNoClassIdInAuthoritiesTest() throws Exception {
		String userJson = USER_JSON.replace(SimpleGrantedAuthorityMixinTests.AUTHORITIES_SET_JSON,
				"[{\"authority\": \"ROLE_USER\"}]");
		assertThatExceptionOfType(MismatchedInputException.class)
			.isThrownBy(() -> this.mapper.readValue(userJson, User.class));
	}

	@Test
	public void deserializeUserWithClassIdInAuthoritiesTest() {
		User user = this.mapper.readValue(userJson(), User.class);
		assertThat(user).isNotNull();
		assertThat(user.getUsername()).isEqualTo("admin");
		assertThat(user.getPassword()).isEqualTo("1234");
		assertThat(user.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
	}

	private String removeNode(String json, JsonMapper mapper, String toRemove) throws Exception {
		ObjectNode node = mapper.createParser(json).readValueAsTree();
		node.remove(toRemove);
		String result = mapper.writeValueAsString(node);
		JSONAssert.assertNotEquals(json, result, false);
		return result;
	}

	public static String userJson() {
		return USER_JSON;
	}

	public static String userWithPasswordJson(String password) {
		return userJson().replaceAll(Pattern.quote(USER_PASSWORD), "\"" + password + "\"");
	}

	public static String userWithNoAuthoritiesJson() {
		return userJson().replace(SimpleGrantedAuthorityMixinTests.AUTHORITIES_SET_JSON,
				SimpleGrantedAuthorityMixinTests.NO_AUTHORITIES_SET_JSON);
	}

}
