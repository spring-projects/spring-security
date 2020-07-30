/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.userdetails;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link User}.
 *
 * @author Ben Alex
 */
public class UserTests {

	private static final List<GrantedAuthority> ROLE_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	@Test
	public void equalsReturnsTrueIfUsernamesAreTheSame() {
		User user1 = new User("rod", "koala", true, true, true, true, ROLE_12);

		assertThat(user1).isNotNull();
		assertThat(user1).isNotEqualTo("A STRING");
		assertThat(user1).isEqualTo(user1);
		assertThat(user1).isEqualTo((new User("rod", "notthesame", true, true, true, true, ROLE_12)));
	}

	@Test
	public void hashLookupOnlyDependsOnUsername() {
		User user1 = new User("rod", "koala", true, true, true, true, ROLE_12);
		Set<UserDetails> users = new HashSet<>();
		users.add(user1);

		assertThat(users).contains(new User("rod", "koala", true, true, true, true, ROLE_12));
		assertThat(users).contains(new User("rod", "anotherpass", false, false, false, false,
				AuthorityUtils.createAuthorityList("ROLE_X")));
		assertThat(users).doesNotContain(new User("bod", "koala", true, true, true, true, ROLE_12));
	}

	@Test
	public void testNoArgConstructorDoesntExist() {
		Class<User> clazz = User.class;

		try {
			clazz.getDeclaredConstructor((Class[]) null);
			fail("Should have thrown NoSuchMethodException");
		}
		catch (NoSuchMethodException expected) {
		}
	}

	@Test
	public void testNullValuesRejected() {
		try {
			new User(null, "koala", true, true, true, true, ROLE_12);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new User("rod", null, true, true, true, true, ROLE_12);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_ONE");
			auths.add(null);
			new User("rod", "koala", true, true, true, true, auths);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void testNullWithinGrantedAuthorityElementIsRejected() {
		try {
			List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_ONE");
			auths.add(null);
			auths.add(new SimpleGrantedAuthority("ROLE_THREE"));
			new User(null, "koala", true, true, true, true, auths);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void testUserGettersSetter() {
		UserDetails user = new User("rod", "koala", true, true, true, true,
				AuthorityUtils.createAuthorityList("ROLE_TWO", "ROLE_ONE"));
		assertThat(user.getUsername()).isEqualTo("rod");
		assertThat(user.getPassword()).isEqualTo("koala");
		assertThat(user.isEnabled()).isTrue();
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities())).contains("ROLE_ONE");
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities())).contains("ROLE_TWO");
		assertThat(user.toString()).contains("rod");
	}

	@Test
	public void enabledFlagIsFalseForDisabledAccount() {
		UserDetails user = new User("rod", "koala", false, true, true, true, ROLE_12);
		assertThat(user.isEnabled()).isFalse();
	}

	@Test
	public void useIsSerializable() throws Exception {
		UserDetails user = new User("rod", "koala", false, true, true, true, ROLE_12);
		// Serialize to a byte array
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(bos);
		out.writeObject(user);
		out.close();
	}

	@Test
	public void withUserDetailsWhenAllEnabled() {
		User expected = new User("rob", "pass", true, true, true, true, ROLE_12);

		UserDetails actual = User.withUserDetails(expected).build();

		assertThat(actual.getUsername()).isEqualTo(expected.getUsername());
		assertThat(actual.getPassword()).isEqualTo(expected.getPassword());
		assertThat(actual.getAuthorities()).isEqualTo(expected.getAuthorities());
		assertThat(actual.isAccountNonExpired()).isEqualTo(expected.isAccountNonExpired());
		assertThat(actual.isAccountNonLocked()).isEqualTo(expected.isAccountNonLocked());
		assertThat(actual.isCredentialsNonExpired()).isEqualTo(expected.isCredentialsNonExpired());
		assertThat(actual.isEnabled()).isEqualTo(expected.isEnabled());
	}

	@Test
	public void withUserDetailsWhenAllDisabled() {
		User expected = new User("rob", "pass", false, false, false, false, ROLE_12);

		UserDetails actual = User.withUserDetails(expected).build();

		assertThat(actual.getUsername()).isEqualTo(expected.getUsername());
		assertThat(actual.getPassword()).isEqualTo(expected.getPassword());
		assertThat(actual.getAuthorities()).isEqualTo(expected.getAuthorities());
		assertThat(actual.isAccountNonExpired()).isEqualTo(expected.isAccountNonExpired());
		assertThat(actual.isAccountNonLocked()).isEqualTo(expected.isAccountNonLocked());
		assertThat(actual.isCredentialsNonExpired()).isEqualTo(expected.isCredentialsNonExpired());
		assertThat(actual.isEnabled()).isEqualTo(expected.isEnabled());
	}

	@Test
	public void withUserWhenDetailsPasswordEncoderThenEncodes() {
		UserDetails userDetails = User.withUsername("user").password("password").roles("USER").build();

		UserDetails withEncodedPassword = User.withUserDetails(userDetails).passwordEncoder((p) -> p + "encoded")
				.build();

		assertThat(withEncodedPassword.getPassword()).isEqualTo("passwordencoded");
	}

	@Test
	public void withUsernameWhenPasswordEncoderAndPasswordThenEncodes() {
		UserDetails withEncodedPassword = User.withUsername("user").password("password")
				.passwordEncoder((p) -> p + "encoded").roles("USER").build();

		assertThat(withEncodedPassword.getPassword()).isEqualTo("passwordencoded");
	}

	@Test
	public void withUsernameWhenPasswordAndPasswordEncoderThenEncodes() {
		// @formatter:off
		UserDetails withEncodedPassword = User.withUsername("user")
			.passwordEncoder((p) -> p + "encoded")
			.password("password")
			.roles("USER")
			.build();
		// @formatter:on

		assertThat(withEncodedPassword.getPassword()).isEqualTo("passwordencoded");
	}

	@Test
	public void withUsernameWhenPasswordAndPasswordEncoderTwiceThenEncodesOnce() {
		Function<String, String> encoder = (p) -> p + "encoded";
		// @formatter:off
		UserDetails withEncodedPassword = User.withUsername("user")
			.passwordEncoder(encoder)
			.password("password")
			.passwordEncoder(encoder)
			.roles("USER")
			.build();
		// @formatter:on

		assertThat(withEncodedPassword.getPassword()).isEqualTo("passwordencoded");
	}

}
