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

import org.junit.*;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.ldap.ApacheDsContainerConfig;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link PasswordComparisonAuthenticator}.
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
public class PasswordComparisonAuthenticatorTests {

	// ~ Instance fields
	// ================================================================================================

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	private PasswordComparisonAuthenticator authenticator;

	private Authentication bob;

	private Authentication ben;

	// ~ Methods
	// ========================================================================================================

	@Before
	public void setUp() {
		authenticator = new PasswordComparisonAuthenticator(this.contextSource);
		authenticator.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });
		bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");
		ben = new UsernamePasswordAuthenticationToken("ben", "benspassword");
	}

	@Test
	public void testAllAttributesAreRetrievedByDefault() {
		DirContextAdapter user = (DirContextAdapter) authenticator.authenticate(bob);
		// System.out.println(user.getAttributes().toString());
		assertThat(user.getAttributes().size()).withFailMessage("User should have 5 attributes").isEqualTo(5);
	}

	@Test
	public void testFailedSearchGivesUserNotFoundException() throws Exception {
		authenticator = new PasswordComparisonAuthenticator(this.contextSource);
		assertThat(authenticator.getUserDns("Bob")).withFailMessage("User DN matches shouldn't be available").isEmpty();
		authenticator.setUserSearch(new MockUserSearch(null));
		authenticator.afterPropertiesSet();

		try {
			authenticator.authenticate(new UsernamePasswordAuthenticationToken("Joe", "pass"));
			fail("Expected exception on failed user search");
		}
		catch (UsernameNotFoundException expected) {
		}
	}

	@Test(expected = BadCredentialsException.class)
	public void testLdapPasswordCompareFailsWithWrongPassword() {
		// Don't retrieve the password
		authenticator.setUserAttributes(new String[] { "uid", "cn", "sn" });
		authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "wrongpass"));
	}

	@Test
	public void testMultipleDnPatternsWorkOk() {
		authenticator.setUserDnPatterns(new String[] { "uid={0},ou=nonexistent", "uid={0},ou=people" });
		authenticator.authenticate(bob);
	}

	@Test
	public void testOnlySpecifiedAttributesAreRetrieved() {
		authenticator.setUserAttributes(new String[] { "uid", "userPassword" });

		DirContextAdapter user = (DirContextAdapter) authenticator.authenticate(bob);
		assertThat(user.getAttributes().size()).withFailMessage("Should have retrieved 2 attribute (uid)").isEqualTo(2);
	}

	@Test
	public void testLdapCompareSucceedsWithCorrectPassword() {
		// Don't retrieve the password
		authenticator.setUserAttributes(new String[] { "uid" });
		authenticator.authenticate(bob);
	}

	@Test
	public void testLdapCompareSucceedsWithShaEncodedPassword() {
		// Don't retrieve the password
		authenticator.setUserAttributes(new String[] { "uid" });
		authenticator.setPasswordEncoder(new LdapShaPasswordEncoder(KeyGenerators.shared(0)));
		authenticator.setUsePasswordAttrCompare(false);
		authenticator.authenticate(ben);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPasswordEncoderCantBeNull() {
		authenticator.setPasswordEncoder(null);
	}

	@Test
	public void testUseOfDifferentPasswordAttributeSucceeds() {
		authenticator.setPasswordAttributeName("uid");
		authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "bob"));
	}

	@Test
	public void testLdapCompareWithDifferentPasswordAttributeSucceeds() {
		authenticator.setUserAttributes(new String[] { "uid" });
		authenticator.setPasswordAttributeName("cn");
		authenticator.authenticate(new UsernamePasswordAuthenticationToken("ben", "Ben Alex"));
	}

	@Test
	public void testWithUserSearch() {
		authenticator = new PasswordComparisonAuthenticator(this.contextSource);
		authenticator.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		assertThat(authenticator.getUserDns("Bob")).withFailMessage("User DN matches shouldn't be available").isEmpty();

		DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=Bob,ou=people"));
		ctx.setAttributeValue("userPassword", "bobspassword");

		authenticator.setUserSearch(new MockUserSearch(ctx));
		authenticator.authenticate(new UsernamePasswordAuthenticationToken("shouldntbeused", "bobspassword"));
	}

}
