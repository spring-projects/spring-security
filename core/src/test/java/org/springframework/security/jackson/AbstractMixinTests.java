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

import org.junit.jupiter.api.BeforeEach;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

/**
 * @author Jitenra Singh
 * @since 4.2
 */
public abstract class AbstractMixinTests {

	protected JsonMapper mapper;

	@BeforeEach
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder()
			.allowIfSubType(
					"org.springframework.security.jackson.UsernamePasswordAuthenticationTokenMixinTests$NonUserPrincipal");
		this.mapper = JsonMapper.builder().addModules(SecurityJacksonModules.getModules(loader, builder)).build();
	}

	User createDefaultUser() {
		return createUser("admin", "1234", "ROLE_USER");
	}

	User createUser(String username, String password, String authority) {
		return new User(username, password, AuthorityUtils.createAuthorityList(authority));
	}

}
