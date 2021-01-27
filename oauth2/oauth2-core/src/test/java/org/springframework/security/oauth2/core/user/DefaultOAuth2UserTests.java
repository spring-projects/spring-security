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

package org.springframework.security.oauth2.core.user;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link DefaultOAuth2User}.
 *
 * @author Vedran Pavic
 * @author Joe Grandja
 */
public class DefaultOAuth2UserTests {

	private static final SimpleGrantedAuthority AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");

	private static final Set<GrantedAuthority> AUTHORITIES = Collections.singleton(AUTHORITY);

	private static final String ATTRIBUTE_NAME_KEY = "username";

	private static final String USERNAME = "test";

	private static final Map<String, Object> ATTRIBUTES = Collections.singletonMap(ATTRIBUTE_NAME_KEY, USERNAME);

	@Test
	public void constructorWhenAttributesIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DefaultOAuth2User(AUTHORITIES, null, ATTRIBUTE_NAME_KEY));
	}

	@Test
	public void constructorWhenAttributesIsEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DefaultOAuth2User(AUTHORITIES, Collections.emptyMap(), ATTRIBUTE_NAME_KEY));
	}

	@Test
	public void constructorWhenNameAttributeKeyIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DefaultOAuth2User(AUTHORITIES, ATTRIBUTES, null));
	}

	@Test
	public void constructorWhenNameAttributeKeyIsInvalidThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DefaultOAuth2User(AUTHORITIES, ATTRIBUTES, "invalid"));
	}

	@Test
	public void constructorWhenAuthoritiesIsNullThenCreatedWithEmptyAuthorities() {
		DefaultOAuth2User user = new DefaultOAuth2User(null, ATTRIBUTES, ATTRIBUTE_NAME_KEY);
		assertThat(user.getName()).isEqualTo(USERNAME);
		assertThat(user.getAuthorities()).isEmpty();
		assertThat(user.getAttributes()).containsOnlyKeys(ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenAuthoritiesIsEmptyThenCreated() {
		DefaultOAuth2User user = new DefaultOAuth2User(Collections.emptySet(), ATTRIBUTES, ATTRIBUTE_NAME_KEY);
		assertThat(user.getName()).isEqualTo(USERNAME);
		assertThat(user.getAuthorities()).isEmpty();
		assertThat(user.getAttributes()).containsOnlyKeys(ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		DefaultOAuth2User user = new DefaultOAuth2User(AUTHORITIES, ATTRIBUTES, ATTRIBUTE_NAME_KEY);
		assertThat(user.getName()).isEqualTo(USERNAME);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(ATTRIBUTE_NAME_KEY);
	}

	// gh-4917
	@Test
	public void constructorWhenCreatedThenIsSerializable() {
		DefaultOAuth2User user = new DefaultOAuth2User(AUTHORITIES, ATTRIBUTES, ATTRIBUTE_NAME_KEY);
		SerializationUtils.serialize(user);
	}

}
