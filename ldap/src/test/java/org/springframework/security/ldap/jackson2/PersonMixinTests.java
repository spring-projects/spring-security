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

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.ldap.userdetails.Person;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link PersonMixin}.
 */
class PersonMixinTests {

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
		Person person = null;
		String expectedJson = asJson(person);
		String json = this.mapper.writeValueAsString(person);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	private String asJson(Person person) {
		// @formatter:off
		return "{\n" +
			   "    \"@class\": \"org.springframework.security.ldap.userdetails.Person\"\n" +
			   "}";
		// @formatter:on
	}
}
