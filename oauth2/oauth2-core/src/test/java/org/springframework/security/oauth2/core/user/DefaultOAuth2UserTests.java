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

package org.springframework.security.oauth2.core.user;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

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
 * @author Park Hyojong
 * @author Yoobin Yoon
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
	public void constructorWhenAttributeValueIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DefaultOAuth2User(AUTHORITIES,
				Collections.singletonMap(ATTRIBUTE_NAME_KEY, null), ATTRIBUTE_NAME_KEY));
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

	@Test
	public void withUsernameWhenValidParametersThenCreated() {
		String directUsername = "directUser";
		DefaultOAuth2User user = DefaultOAuth2User.withUsername(directUsername)
			.authorities(AUTHORITIES)
			.attributes(ATTRIBUTES)
			.build();

		assertThat(user.getName()).isEqualTo(directUsername);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(ATTRIBUTE_NAME_KEY);
		assertThat(user.getAttributes().get(ATTRIBUTE_NAME_KEY)).isEqualTo(USERNAME);
	}

	@Test
	public void withUsernameWhenUsernameIsEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> DefaultOAuth2User.withUsername(""));
	}

	@Test
	public void withUsernameWhenAttributesIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> DefaultOAuth2User.withUsername("username").authorities(AUTHORITIES).attributes(null).build());
	}

	@Test
	public void withUsernameWhenAttributesIsEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> DefaultOAuth2User.withUsername("username")
			.authorities(AUTHORITIES)
			.attributes(Collections.emptyMap())
			.build());
	}

	@Test
	public void withUsernameWhenUsernameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> DefaultOAuth2User.withUsername((String) null));
	}

	@Test
	public void withUsernameWhenCreatedThenIsSerializable() {
		DefaultOAuth2User user = DefaultOAuth2User.withUsername("directUser")
			.authorities(AUTHORITIES)
			.attributes(ATTRIBUTES)
			.build();
		SerializationUtils.serialize(user);
	}

	@Test
	public void withUsernameWhenUsernameProvidedThenTakesPrecedenceOverAttributes() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("username", "fromAttributes");
		attributes.put("id", "123");

		DefaultOAuth2User user = DefaultOAuth2User.withUsername("directUsername")
			.authorities(AUTHORITIES)
			.attributes(attributes)
			.build();

		assertThat(user.getName()).isEqualTo("directUsername");
		assertThat((String) user.getAttribute("username")).isEqualTo("fromAttributes");
	}

	@Test
	public void constructorWhenSimpleAttributeKeyThenWorksAsUsual() {
		DefaultOAuth2User user = new DefaultOAuth2User(AUTHORITIES, ATTRIBUTES, ATTRIBUTE_NAME_KEY);

		assertThat(user.getName()).isEqualTo(USERNAME);
		assertThat(user.getAttributes()).containsOnlyKeys(ATTRIBUTE_NAME_KEY);
	}

	@Test
	public void withUsernameAndDeprecatedConstructorWhenSameDataThenEqual() {
		DefaultOAuth2User user1 = new DefaultOAuth2User(AUTHORITIES, ATTRIBUTES, ATTRIBUTE_NAME_KEY);
		DefaultOAuth2User user2 = DefaultOAuth2User.withUsername(USERNAME)
			.authorities(AUTHORITIES)
			.attributes(ATTRIBUTES)
			.build();

		assertThat(user1.getName()).isEqualTo(user2.getName());
		assertThat(user1.getAuthorities()).isEqualTo(user2.getAuthorities());
		assertThat(user1.getAttributes()).isEqualTo(user2.getAttributes());
		assertThat(user1).isEqualTo(user2);
	}

	@Test
	public void withUsernameWhenAuthoritiesIsNullThenCreatedWithEmptyAuthorities() {
		DefaultOAuth2User user = DefaultOAuth2User.withUsername("testUser")
			.authorities(null)
			.attributes(ATTRIBUTES)
			.build();

		assertThat(user.getName()).isEqualTo("testUser");
		assertThat(user.getAuthorities()).isEmpty();
		assertThat(user.getAttributes()).isEqualTo(ATTRIBUTES);
	}

	@Test
	public void withUsernameWhenAuthoritiesIsEmptyThenCreated() {
		DefaultOAuth2User user = DefaultOAuth2User.withUsername("testUser")
			.authorities(Collections.emptySet())
			.attributes(ATTRIBUTES)
			.build();

		assertThat(user.getName()).isEqualTo("testUser");
		assertThat(user.getAuthorities()).isEmpty();
		assertThat(user.getAttributes()).isEqualTo(ATTRIBUTES);
	}

	@Test
	public void withUsernameWhenNestedAttributesThenUsernameExtractedCorrectly() {
		Map<String, Object> nestedAttributes = new HashMap<>();
		Map<String, Object> userData = new HashMap<>();
		userData.put("name", "nestedUser");
		userData.put("id", "123");
		nestedAttributes.put("data", userData);
		nestedAttributes.put("other", "value");

		DefaultOAuth2User user = DefaultOAuth2User.withUsername("nestedUser")
			.authorities(AUTHORITIES)
			.attributes(nestedAttributes)
			.build();

		assertThat(user.getName()).isEqualTo("nestedUser");
		assertThat(user.getAttributes()).hasSize(2);
		assertThat(user.getAttributes().get("data")).isEqualTo(userData);
		assertThat(user.getAttributes().get("other")).isEqualTo("value");
	}

	@Test
	public void withUsernameWhenComplexNestedAttributesThenCorrectlyHandled() {
		Map<String, Object> attributes = new HashMap<>();
		Map<String, Object> profile = new HashMap<>();
		Map<String, Object> socialMedia = new HashMap<>();

		socialMedia.put("twitter", "twitterUser");
		socialMedia.put("github", "githubUser");
		profile.put("social", socialMedia);
		profile.put("email", "user@example.com");
		attributes.put("profile", profile);
		attributes.put("id", "user123");

		DefaultOAuth2User user = DefaultOAuth2User.withUsername("customUsername")
			.authorities(AUTHORITIES)
			.attributes(attributes)
			.build();

		assertThat(user.getName()).isEqualTo("customUsername");
		assertThat(user.getAttributes()).isEqualTo(attributes);
		assertThat(((Map<?, ?>) ((Map<?, ?>) user.getAttribute("profile")).get("social")).get("twitter"))
			.isEqualTo("twitterUser");
	}

}
