/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.acls.sid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import org.junit.Test;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class SidTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testPrincipalSidConstructorsRequiredFields() {
		// Check one String-argument constructor
		try {
			String string = null;
			new PrincipalSid(string);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new PrincipalSid("");
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		new PrincipalSid("johndoe");
		// throws no exception

		// Check one Authentication-argument constructor
		try {
			Authentication authentication = null;
			new PrincipalSid(authentication);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			Authentication authentication = new TestingAuthenticationToken(null,
					"password");
			new PrincipalSid(authentication);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		Authentication authentication = new TestingAuthenticationToken("johndoe",
				"password");
		new PrincipalSid(authentication);
		// throws no exception
	}

	@Test
	public void testGrantedAuthoritySidConstructorsRequiredFields() {
		// Check one String-argument constructor
		try {
			String string = null;
			new GrantedAuthoritySid(string);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			new GrantedAuthoritySid("");
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			new GrantedAuthoritySid("ROLE_TEST");

		}
		catch (IllegalArgumentException notExpected) {
			fail("It shouldn't have thrown IllegalArgumentException");
		}

		// Check one GrantedAuthority-argument constructor
		try {
			GrantedAuthority ga = null;
			new GrantedAuthoritySid(ga);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			GrantedAuthority ga = new SimpleGrantedAuthority(null);
			new GrantedAuthoritySid(ga);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
			new GrantedAuthoritySid(ga);

		}
		catch (IllegalArgumentException notExpected) {
			fail("It shouldn't have thrown IllegalArgumentException");
		}
	}

	@Test
	public void testPrincipalSidEquals() {
		Authentication authentication = new TestingAuthenticationToken("johndoe",
				"password");
		Sid principalSid = new PrincipalSid(authentication);

		assertThat(principalSid.equals(null)).isFalse();
		assertThat(principalSid.equals("DIFFERENT_TYPE_OBJECT")).isFalse();
		assertThat(principalSid.equals(principalSid)).isTrue();
		assertThat(principalSid.equals(new PrincipalSid(authentication))).isTrue();
		assertThat(principalSid.equals(new PrincipalSid(
				new TestingAuthenticationToken("johndoe", null)))).isTrue();
		assertThat(principalSid.equals(new PrincipalSid(
				new TestingAuthenticationToken("scott", null)))).isFalse();
		assertThat(principalSid.equals(new PrincipalSid("johndoe"))).isTrue();
		assertThat(principalSid.equals(new PrincipalSid("scott"))).isFalse();
	}

	@Test
	public void testGrantedAuthoritySidEquals() {
		GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
		Sid gaSid = new GrantedAuthoritySid(ga);

		assertThat(gaSid.equals(null)).isFalse();
		assertThat(gaSid.equals("DIFFERENT_TYPE_OBJECT")).isFalse();
		assertThat(gaSid.equals(gaSid)).isTrue();
		assertThat(gaSid.equals(new GrantedAuthoritySid(ga))).isTrue();
		assertThat(gaSid.equals(new GrantedAuthoritySid(
				new SimpleGrantedAuthority("ROLE_TEST")))).isTrue();
		assertThat(gaSid.equals(new GrantedAuthoritySid(
				new SimpleGrantedAuthority("ROLE_NOT_EQUAL")))).isFalse();
		assertThat(gaSid.equals(new GrantedAuthoritySid("ROLE_TEST"))).isTrue();
		assertThat(gaSid.equals(new GrantedAuthoritySid("ROLE_NOT_EQUAL"))).isFalse();
	}

	@Test
	public void testPrincipalSidHashCode() {
		Authentication authentication = new TestingAuthenticationToken("johndoe",
				"password");
		Sid principalSid = new PrincipalSid(authentication);

		assertThat(principalSid.hashCode()).isEqualTo("johndoe".hashCode());
		assertThat(principalSid.hashCode()).isEqualTo(
				new PrincipalSid("johndoe").hashCode());
		assertThat(principalSid.hashCode()).isNotEqualTo(
				new PrincipalSid("scott").hashCode());
		assertThat(principalSid.hashCode()).isNotEqualTo(new PrincipalSid(
				new TestingAuthenticationToken("scott", "password")).hashCode());
	}

	@Test
	public void testGrantedAuthoritySidHashCode() {
		GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
		Sid gaSid = new GrantedAuthoritySid(ga);

		assertThat(gaSid.hashCode()).isEqualTo("ROLE_TEST".hashCode());
		assertThat(gaSid.hashCode()).isEqualTo(
				new GrantedAuthoritySid("ROLE_TEST").hashCode());
		assertThat(gaSid.hashCode()).isNotEqualTo(
				new GrantedAuthoritySid("ROLE_TEST_2").hashCode());
		assertThat(gaSid.hashCode()).isNotEqualTo(new GrantedAuthoritySid(
				new SimpleGrantedAuthority("ROLE_TEST_2")).hashCode());
	}

	@Test
	public void testGetters() {
		Authentication authentication = new TestingAuthenticationToken("johndoe",
				"password");
		PrincipalSid principalSid = new PrincipalSid(authentication);
		GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
		GrantedAuthoritySid gaSid = new GrantedAuthoritySid(ga);

		assertThat("johndoe".equals(principalSid.getPrincipal())).isTrue();
		assertThat("scott".equals(principalSid.getPrincipal())).isFalse();

		assertThat("ROLE_TEST".equals(gaSid.getGrantedAuthority())).isTrue();
		assertThat("ROLE_TEST2".equals(gaSid.getGrantedAuthority())).isFalse();
	}
}
