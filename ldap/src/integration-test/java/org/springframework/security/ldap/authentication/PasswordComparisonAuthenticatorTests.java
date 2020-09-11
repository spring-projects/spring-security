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

package org.springframework.security.ldap.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.ldap.ApacheDsContainerConfig;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PasswordComparisonAuthenticator}.
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
public class PasswordComparisonAuthenticatorTests {

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	private PasswordComparisonAuthenticator authenticator;

	private Authentication bob;

	private Authentication ben;

	@Before
	public void setUp() {
		this.authenticator = new PasswordComparisonAuthenticator(this.contextSource);
		this.authenticator.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });
		this.bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");
		this.ben = new UsernamePasswordAuthenticationToken("ben", "benspassword");
	}

	@Test
	public void testAllAttributesAreRetrievedByDefault() {
		DirContextAdapter user = (DirContextAdapter) this.authenticator.authenticate(this.bob);
		// System.out.println(user.getAttributes().toString());
		assertThat(user.getAttributes().size()).withFailMessage("User should have 5 attributes").isEqualTo(5);
	}

	@Test
	public void testFailedSearchGivesUserNotFoundException() throws Exception {
		this.authenticator = new PasswordComparisonAuthenticator(this.contextSource);
		assertThat(this.authenticator.getUserDns("Bob")).withFailMessage("User DN matches shouldn't be available")
				.isEmpty();
		this.authenticator.setUserSearch(new MockUserSearch(null));
		this.authenticator.afterPropertiesSet();
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(
				() -> this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("Joe", "pass")));
	}

	@Test
	public void testLdapPasswordCompareFailsWithWrongPassword() {
		// Don't retrieve the password
		this.authenticator.setUserAttributes(new String[] { "uid", "cn", "sn" });
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(
				() -> this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "wrongpass")));
	}

	@Test
	public void testMultipleDnPatternsWorkOk() {
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=nonexistent", "uid={0},ou=people" });
		this.authenticator.authenticate(this.bob);
	}

	@Test
	public void testOnlySpecifiedAttributesAreRetrieved() {
		this.authenticator.setUserAttributes(new String[] { "uid", "userPassword" });

		DirContextAdapter user = (DirContextAdapter) this.authenticator.authenticate(this.bob);
		assertThat(user.getAttributes().size()).withFailMessage("Should have retrieved 2 attribute (uid)").isEqualTo(2);
	}

	@Test
	public void testLdapCompareSucceedsWithCorrectPassword() {
		// Don't retrieve the password
		this.authenticator.setUserAttributes(new String[] { "uid" });
		this.authenticator.authenticate(this.bob);
	}

	@Test
	public void testLdapCompareSucceedsWithShaEncodedPassword() {
		// Don't retrieve the password
		this.authenticator.setUserAttributes(new String[] { "uid" });
		this.authenticator.setPasswordEncoder(new LdapShaPasswordEncoder(KeyGenerators.shared(0)));
		this.authenticator.setUsePasswordAttrCompare(false);
		this.authenticator.authenticate(this.ben);
	}

	@Test
	public void testPasswordEncoderCantBeNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authenticator.setPasswordEncoder(null));
	}

	@Test
	public void testUseOfDifferentPasswordAttributeSucceeds() {
		this.authenticator.setPasswordAttributeName("uid");
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "bob"));
	}

	@Test
	public void testLdapCompareWithDifferentPasswordAttributeSucceeds() {
		this.authenticator.setUserAttributes(new String[] { "uid" });
		this.authenticator.setPasswordAttributeName("cn");
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("ben", "Ben Alex"));
	}

	@Test
	public void testWithUserSearch() {
		this.authenticator = new PasswordComparisonAuthenticator(this.contextSource);
		this.authenticator.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		assertThat(this.authenticator.getUserDns("Bob")).withFailMessage("User DN matches shouldn't be available")
				.isEmpty();

		DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=Bob,ou=people"));
		ctx.setAttributeValue("userPassword", "bobspassword");

		this.authenticator.setUserSearch(new MockUserSearch(ctx));
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("shouldntbeused", "bobspassword"));
	}

}
