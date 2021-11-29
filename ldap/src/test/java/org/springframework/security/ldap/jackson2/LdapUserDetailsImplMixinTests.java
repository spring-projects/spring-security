/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.ldap.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link LdapUserDetailsImplMixin}.
 */
public class LdapUserDetailsImplMixinTests {

	private static final String USER_PASSWORD = "Password1234";

	private static final String AUTHORITIES_ARRAYLIST_JSON = "[\"java.util.Collections$UnmodifiableRandomAccessList\", []]";

	// @formatter:off
	private static final String USER_JSON = "{"
			+ "\"@class\": \"org.springframework.security.ldap.userdetails.LdapUserDetailsImpl\", "
			+ "\"dn\": \"ignored=ignored\","
			+ "\"username\": \"ghengis\","
			+ "\"password\": \"" + USER_PASSWORD + "\","
			+ "\"accountNonExpired\": true, "
			+ "\"accountNonLocked\": true, "
			+ "\"credentialsNonExpired\": true, "
			+ "\"enabled\": true, "
			+ "\"authorities\": " + AUTHORITIES_ARRAYLIST_JSON + ","
			+ "\"graceLoginsRemaining\": " + Integer.MAX_VALUE + ","
			+ "\"timeBeforeExpiration\": " + Integer.MAX_VALUE
			+ "}";
	// @formatter:on

	private ObjectMapper mapper;

	@BeforeEach
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();
		LdapUserDetailsImpl p = (LdapUserDetailsImpl) mapper.mapUserFromContext(createUserContext(), "ghengis",
				AuthorityUtils.NO_AUTHORITIES);

		String json = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(USER_JSON, json, true);
	}

	@Test
	public void serializeWhenEraseCredentialInvokedThenUserPasswordIsNull()
			throws JsonProcessingException, JSONException {
		LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();
		LdapUserDetailsImpl p = (LdapUserDetailsImpl) mapper.mapUserFromContext(createUserContext(), "ghengis",
				AuthorityUtils.NO_AUTHORITIES);
		p.eraseCredentials();
		String actualJson = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(USER_JSON.replaceAll("\"" + USER_PASSWORD + "\"", "null"), actualJson, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		assertThatExceptionOfType(JsonProcessingException.class)
				.isThrownBy(() -> new ObjectMapper().readValue(USER_JSON, LdapUserDetailsImpl.class));
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();
		LdapUserDetailsImpl expectedAuthentication = (LdapUserDetailsImpl) mapper
				.mapUserFromContext(createUserContext(), "ghengis", AuthorityUtils.NO_AUTHORITIES);

		LdapUserDetailsImpl authentication = this.mapper.readValue(USER_JSON, LdapUserDetailsImpl.class);
		assertThat(authentication.getAuthorities()).containsExactlyElementsOf(expectedAuthentication.getAuthorities());
		assertThat(authentication.getDn()).isEqualTo(expectedAuthentication.getDn());
		assertThat(authentication.getUsername()).isEqualTo(expectedAuthentication.getUsername());
		assertThat(authentication.getPassword()).isEqualTo(expectedAuthentication.getPassword());
		assertThat(authentication.getGraceLoginsRemaining())
				.isEqualTo(expectedAuthentication.getGraceLoginsRemaining());
		assertThat(authentication.getTimeBeforeExpiration())
				.isEqualTo(expectedAuthentication.getTimeBeforeExpiration());
		assertThat(authentication.isAccountNonExpired()).isEqualTo(expectedAuthentication.isAccountNonExpired());
		assertThat(authentication.isAccountNonLocked()).isEqualTo(expectedAuthentication.isAccountNonLocked());
		assertThat(authentication.isEnabled()).isEqualTo(expectedAuthentication.isEnabled());
		assertThat(authentication.isCredentialsNonExpired())
				.isEqualTo(expectedAuthentication.isCredentialsNonExpired());
	}

	private DirContextAdapter createUserContext() {
		DirContextAdapter ctx = new DirContextAdapter();
		ctx.setDn(new DistinguishedName("ignored=ignored"));
		ctx.setAttributeValue("userPassword", USER_PASSWORD);
		return ctx;
	}

}
