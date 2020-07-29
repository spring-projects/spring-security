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

package org.springframework.security.oauth2.core.user;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Rob Winch
 */
public final class TestOAuth2Users {

	private TestOAuth2Users() {
	}

	public static DefaultOAuth2User create() {
		String nameAttributeKey = "username";
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(nameAttributeKey, "user");
		Collection<GrantedAuthority> authorities = authorities(attributes);
		return new DefaultOAuth2User(authorities, attributes, nameAttributeKey);
	}

	private static Collection<GrantedAuthority> authorities(Map<String, Object> attributes) {
		return new LinkedHashSet<>(Arrays.asList(new OAuth2UserAuthority(attributes),
				new SimpleGrantedAuthority("SCOPE_read"), new SimpleGrantedAuthority("SCOPE_write")));
	}

}
