/*
 * Copyright 2012-2017 the original author or authors.
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

package org.springframework.security.oauth2.core.user;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultOAuth2User}.
 *
 * @author Vedran Pavic
 */
public class DefaultOAuth2UserTests {

	private static final SimpleGrantedAuthority TEST_AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");

	private static final Set<GrantedAuthority> TEST_AUTHORITIES = Collections.singleton(TEST_AUTHORITY);

	private static final String TEST_ATTRIBUTE_NAME_KEY = "username";

	private static final String TEST_USERNAME = "test";

	private static final Map<String, Object> TEST_ATTRIBUTES = Collections.singletonMap(
			TEST_ATTRIBUTE_NAME_KEY, TEST_USERNAME);

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void constructorWhenParametersAreValidThenIsCreated() {
		DefaultOAuth2User user = new DefaultOAuth2User(TEST_AUTHORITIES, TEST_ATTRIBUTES, TEST_ATTRIBUTE_NAME_KEY);

		assertThat(user.getName()).isEqualTo(TEST_USERNAME);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(TEST_AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(TEST_ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenAuthoritiesAreNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("authorities cannot be empty");

		new DefaultOAuth2User(null, TEST_ATTRIBUTES, TEST_ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenAuthoritiesAreEmptyThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("authorities cannot be empty");

		new DefaultOAuth2User(Collections.emptySet(), TEST_ATTRIBUTES, TEST_ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenAttributesAreNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("attributes cannot be empty");

		new DefaultOAuth2User(TEST_AUTHORITIES, null, TEST_ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenAttributesAreEmptyThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("attributes cannot be empty");

		new DefaultOAuth2User(TEST_AUTHORITIES, Collections.emptyMap(), TEST_ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenNameAttributeKeyIsNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("nameAttributeKey cannot be empty");

		new DefaultOAuth2User(TEST_AUTHORITIES, TEST_ATTRIBUTES, null);
	}

	@Test
	public void constructorWhenNameAttributeKeyIsInvalidThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Missing attribute 'invalid' in attributes");

		new DefaultOAuth2User(TEST_AUTHORITIES, TEST_ATTRIBUTES, "invalid");
	}

}
