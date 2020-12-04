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

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.Person;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link InetOrgPersonMixin}.
 */
class InetOrgPersonMixinTests {

	private ObjectMapper mapper;

	@BeforeEach
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Disabled
	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
		InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

		String expectedJson = asJson(p);
		String json = this.mapper.writeValueAsString(p);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	private DirContextAdapter createUserContext() {
		DirContextAdapter ctx = new DirContextAdapter();
		ctx.setDn(new DistinguishedName("ignored=ignored"));
		ctx.setAttributeValue("uid", "ghengis");
		ctx.setAttributeValue("userPassword", "pillage");
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
		ctx.setAttributeValue("roomNumber", "Yurt 1");
		ctx.setAttributeValue("sn", "Khan");
		ctx.setAttributeValue("street", "Westward Avenue");
		ctx.setAttributeValue("telephoneNumber", "+442075436521");
		return ctx;
	}

	private String asJson(Person person) {
		// @formatter:off
		return "{\n" +
			   "    \"@class\": \"org.springframework.security.ldap.userdetails.InetOrgPerson\"\n" +
			   "}";
		// @formatter:on
	}

}
