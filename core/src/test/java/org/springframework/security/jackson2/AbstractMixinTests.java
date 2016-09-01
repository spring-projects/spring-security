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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.ObjectUtils;

import java.util.Collections;

/**
 * @author Jitenra Singh
 * @since 4.2
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class AbstractMixinTests {

	ObjectMapper mapper;

	protected ObjectMapper buildObjectMapper() {
		if (ObjectUtils.isEmpty(mapper)) {
			mapper = new ObjectMapper();
			ClassLoader loader = getClass().getClassLoader();
			mapper.registerModules(SecurityJacksonModules.getModules(loader));
		}
		return mapper;
	}

	User createDefaultUser() {
		return createUser("dummy", "password", "ROLE_USER");
	}

	User createUser(String username, String password, String authority) {
		return new User(username, password, Collections.singletonList(new SimpleGrantedAuthority(authority)));
	}
}
