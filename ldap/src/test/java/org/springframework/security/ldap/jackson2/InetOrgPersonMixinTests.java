/*
 * Copyright 2002-2021 the original author or authors.
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
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link InetOrgPersonMixin}.
 */
public class InetOrgPersonMixinTests {

	private static final String USER_PASSWORD = "Password1234";

	private static final String AUTHORITIES_ARRAYLIST_JSON = "[\"java.util.Collections$UnmodifiableRandomAccessList\", []]";

	// @formatter:off
	private static final String INET_ORG_PERSON_JSON = "{\n"
			+ "\"@class\": \"org.springframework.security.ldap.userdetails.InetOrgPerson\","
			+ "\"dn\": \"ignored=ignored\","
			+ "\"uid\": \"ghengis\","
			+ "\"username\": \"ghengis\","
			+ "\"password\": \"" + USER_PASSWORD + "\","
			+ "\"carLicense\": \"HORS1\","
			+ "\"givenName\": \"Ghengis\","
			+ "\"destinationIndicator\": \"West\","
			+ "\"displayName\": \"Ghengis McCann\","
			+ "\"givenName\": \"Ghengis\","
			+ "\"homePhone\": \"+467575436521\","
			+ "\"initials\": \"G\","
			+ "\"employeeNumber\": \"00001\","
			+ "\"homePostalAddress\": \"Steppes\","
			+ "\"mail\": \"ghengis@mongolia\","
			+ "\"mobile\": \"always\","
			+ "\"o\": \"Hordes\","
			+ "\"ou\": \"Horde1\","
			+ "\"postalAddress\": \"On the Move\","
			+ "\"postalCode\": \"Changes Frequently\","
			+ "\"roomNumber\": \"Yurt 1\","
			+ "\"sn\": \"Khan\","
			+ "\"street\": \"Westward Avenue\","
			+ "\"telephoneNumber\": \"+442075436521\","
			+ "\"departmentNumber\": \"5679\","
			+ "\"title\": \"T\","
			+ "\"cn\": [\"java.util.Arrays$ArrayList\",[\"Ghengis Khan\"]],"
			+ "\"description\": \"Scary\","
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
		InetOrgPersonContextMapper mapper = new InetOrgPersonContextMapper();
		InetOrgPerson p = (InetOrgPerson) mapper.mapUserFromContext(createUserContext(), "ghengis",
				AuthorityUtils.NO_AUTHORITIES);

		String json = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(INET_ORG_PERSON_JSON, json, true);
	}

	@Test
	public void serializeWhenEraseCredentialInvokedThenUserPasswordIsNull()
			throws JsonProcessingException, JSONException {
		InetOrgPersonContextMapper mapper = new InetOrgPersonContextMapper();
		InetOrgPerson p = (InetOrgPerson) mapper.mapUserFromContext(createUserContext(), "ghengis",
				AuthorityUtils.NO_AUTHORITIES);
		p.eraseCredentials();
		String actualJson = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(INET_ORG_PERSON_JSON.replaceAll("\"" + USER_PASSWORD + "\"", "null"), actualJson, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		assertThatExceptionOfType(JsonProcessingException.class)
				.isThrownBy(() -> new ObjectMapper().readValue(INET_ORG_PERSON_JSON, InetOrgPerson.class));
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		InetOrgPersonContextMapper mapper = new InetOrgPersonContextMapper();
		InetOrgPerson expectedAuthentication = (InetOrgPerson) mapper.mapUserFromContext(createUserContext(), "ghengis",
				AuthorityUtils.NO_AUTHORITIES);

		InetOrgPerson authentication = this.mapper.readValue(INET_ORG_PERSON_JSON, InetOrgPerson.class);
		assertThat(authentication.getAuthorities()).containsExactlyElementsOf(expectedAuthentication.getAuthorities());
		assertThat(authentication.getCarLicense()).isEqualTo(expectedAuthentication.getCarLicense());
		assertThat(authentication.getDepartmentNumber()).isEqualTo(expectedAuthentication.getDepartmentNumber());
		assertThat(authentication.getDestinationIndicator())
				.isEqualTo(expectedAuthentication.getDestinationIndicator());
		assertThat(authentication.getDn()).isEqualTo(expectedAuthentication.getDn());
		assertThat(authentication.getDescription()).isEqualTo(expectedAuthentication.getDescription());
		assertThat(authentication.getDisplayName()).isEqualTo(expectedAuthentication.getDisplayName());
		assertThat(authentication.getUid()).isEqualTo(expectedAuthentication.getUid());
		assertThat(authentication.getUsername()).isEqualTo(expectedAuthentication.getUsername());
		assertThat(authentication.getPassword()).isEqualTo(expectedAuthentication.getPassword());
		assertThat(authentication.getHomePhone()).isEqualTo(expectedAuthentication.getHomePhone());
		assertThat(authentication.getEmployeeNumber()).isEqualTo(expectedAuthentication.getEmployeeNumber());
		assertThat(authentication.getHomePostalAddress()).isEqualTo(expectedAuthentication.getHomePostalAddress());
		assertThat(authentication.getInitials()).isEqualTo(expectedAuthentication.getInitials());
		assertThat(authentication.getMail()).isEqualTo(expectedAuthentication.getMail());
		assertThat(authentication.getMobile()).isEqualTo(expectedAuthentication.getMobile());
		assertThat(authentication.getO()).isEqualTo(expectedAuthentication.getO());
		assertThat(authentication.getOu()).isEqualTo(expectedAuthentication.getOu());
		assertThat(authentication.getPostalAddress()).isEqualTo(expectedAuthentication.getPostalAddress());
		assertThat(authentication.getPostalCode()).isEqualTo(expectedAuthentication.getPostalCode());
		assertThat(authentication.getRoomNumber()).isEqualTo(expectedAuthentication.getRoomNumber());
		assertThat(authentication.getStreet()).isEqualTo(expectedAuthentication.getStreet());
		assertThat(authentication.getSn()).isEqualTo(expectedAuthentication.getSn());
		assertThat(authentication.getTitle()).isEqualTo(expectedAuthentication.getTitle());
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
		ctx.setDn(new DistinguishedName("ignored=ignored"));
		ctx.setAttributeValue("uid", "ghengis");
		ctx.setAttributeValue("userPassword", USER_PASSWORD);
		ctx.setAttributeValue("carLicense", "HORS1");
		ctx.setAttributeValue("cn", "Ghengis Khan");
		ctx.setAttributeValue("description", "Scary");
		ctx.setAttributeValue("destinationIndicator", "West");
		ctx.setAttributeValue("displayName", "Ghengis McCann");
		ctx.setAttributeValue("givenName", "Ghengis");
		ctx.setAttributeValue("homePhone", "+467575436521");
		ctx.setAttributeValue("initials", "G");
		ctx.setAttributeValue("employeeNumber", "00001");
		ctx.setAttributeValue("homePostalAddress", "Steppes");
		ctx.setAttributeValue("mail", "ghengis@mongolia");
		ctx.setAttributeValue("mobile", "always");
		ctx.setAttributeValue("o", "Hordes");
		ctx.setAttributeValue("ou", "Horde1");
		ctx.setAttributeValue("postalAddress", "On the Move");
		ctx.setAttributeValue("postalCode", "Changes Frequently");
		ctx.setAttributeValue("roomNumber", "Yurt 1");
		ctx.setAttributeValue("sn", "Khan");
		ctx.setAttributeValue("street", "Westward Avenue");
		ctx.setAttributeValue("telephoneNumber", "+442075436521");
		ctx.setAttributeValue("departmentNumber", "5679");
		ctx.setAttributeValue("title", "T");
		return ctx;
	}

}
