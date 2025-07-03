/*
 * Copyright 2002-2025 the original author or authors.
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
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.ldap.userdetails.Person;
import org.springframework.security.ldap.userdetails.PersonContextMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link PersonMixin}.
 */
public class PersonMixinTests {

	private static final String USER_PASSWORD = "Password1234";

	private static final String AUTHORITIES_ARRAYLIST_JSON = "[\"java.util.Collections$UnmodifiableRandomAccessList\", []]";

	// @formatter:off
	private static final String PERSON_JSON = "{"
			+ "\"@class\": \"org.springframework.security.ldap.userdetails.Person\", "
			+ "\"dn\": \"ignored=ignored\","
			+ "\"username\": \"ghengis\","
			+ "\"password\": \"" + USER_PASSWORD + "\","
			+ "\"givenName\": \"Ghengis\","
			+ "\"sn\": \"Khan\","
			+ "\"cn\": [\"java.util.Arrays$ArrayList\",[\"Ghengis Khan\"]],"
			+ "\"description\": \"Scary\","
			+ "\"telephoneNumber\": \"+442075436521\","
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
		PersonContextMapper mapper = new PersonContextMapper();
		Person p = (Person) mapper.mapUserFromContext(createUserContext(), "ghengis", AuthorityUtils.NO_AUTHORITIES);

		String json = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(PERSON_JSON, json, true);
	}

	@Test
	public void serializeWhenEraseCredentialInvokedThenUserPasswordIsNull()
			throws JsonProcessingException, JSONException {
		PersonContextMapper mapper = new PersonContextMapper();
		Person p = (Person) mapper.mapUserFromContext(createUserContext(), "ghengis", AuthorityUtils.NO_AUTHORITIES);
		p.eraseCredentials();
		String actualJson = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(PERSON_JSON.replaceAll("\"" + USER_PASSWORD + "\"", "null"), actualJson, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		assertThatExceptionOfType(JsonProcessingException.class)
			.isThrownBy(() -> new ObjectMapper().readValue(PERSON_JSON, Person.class));
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		PersonContextMapper mapper = new PersonContextMapper();
		Person expectedAuthentication = (Person) mapper.mapUserFromContext(createUserContext(), "ghengis",
				AuthorityUtils.NO_AUTHORITIES);

		Person authentication = this.mapper.readValue(PERSON_JSON, Person.class);
		assertThat(authentication.getAuthorities()).containsExactlyElementsOf(expectedAuthentication.getAuthorities());
		assertThat(authentication.getDn()).isEqualTo(expectedAuthentication.getDn());
		assertThat(authentication.getDescription()).isEqualTo(expectedAuthentication.getDescription());
		assertThat(authentication.getUsername()).isEqualTo(expectedAuthentication.getUsername());
		assertThat(authentication.getPassword()).isEqualTo(expectedAuthentication.getPassword());
		assertThat(authentication.getSn()).isEqualTo(expectedAuthentication.getSn());
		assertThat(authentication.getGivenName()).isEqualTo(expectedAuthentication.getGivenName());
		assertThat(authentication.getTelephoneNumber()).isEqualTo(expectedAuthentication.getTelephoneNumber());
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
		ctx.setDn(LdapNameBuilder.newInstance("ignored=ignored").build());
		ctx.setAttributeValue("userPassword", USER_PASSWORD);
		ctx.setAttributeValue("cn", "Ghengis Khan");
		ctx.setAttributeValue("description", "Scary");
		ctx.setAttributeValue("givenName", "Ghengis");
		ctx.setAttributeValue("sn", "Khan");
		ctx.setAttributeValue("telephoneNumber", "+442075436521");
		return ctx;
	}

}
