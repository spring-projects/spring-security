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
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.ldap.ApacheDsContainerConfig;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests for {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
public class BindAuthenticatorTests {

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	private BindAuthenticator authenticator;

	private Authentication bob;

	@Before
	public void setUp() {
		this.authenticator = new BindAuthenticator(this.contextSource);
		this.authenticator.setMessageSource(new SpringSecurityMessageSource());
		this.bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");

	}

	@Test(expected = BadCredentialsException.class)
	public void emptyPasswordIsRejected() {
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("jen", ""));
	}

	@Test
	public void testAuthenticationWithCorrectPasswordSucceeds() {
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people", "cn={0},ou=people" });

		DirContextOperations user = this.authenticator.authenticate(this.bob);
		assertThat(user.getStringAttribute("uid")).isEqualTo("bob");
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("mouse, jerry", "jerryspassword"));
	}

	@Test
	public void testAuthenticationWithInvalidUserNameFails() {
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });

		try {
			this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("nonexistentsuser", "password"));
			fail("Shouldn't be able to bind with invalid username");
		}
		catch (BadCredentialsException expected) {
		}
	}

	@Test
	public void testAuthenticationWithUserSearch() throws Exception {
		// DirContextAdapter ctx = new DirContextAdapter(new
		// DistinguishedName("uid=bob,ou=people"));
		this.authenticator.setUserSearch(new FilterBasedLdapUserSearch("ou=people", "(uid={0})", this.contextSource));
		this.authenticator.afterPropertiesSet();
		DirContextOperations result = this.authenticator.authenticate(this.bob);
		// ensure we are getting the same attributes back
		assertThat(result.getStringAttribute("cn")).isEqualTo("Bob Hamilton");
		// SEC-1444
		this.authenticator.setUserSearch(new FilterBasedLdapUserSearch("ou=people", "(cn={0})", this.contextSource));
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("mouse, jerry", "jerryspassword"));
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("slash/guy", "slashguyspassword"));
		// SEC-1661
		this.authenticator.setUserSearch(
				new FilterBasedLdapUserSearch("ou=\\\"quoted people\\\"", "(cn={0})", this.contextSource));
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("quote\"guy", "quoteguyspassword"));
		this.authenticator.setUserSearch(new FilterBasedLdapUserSearch("", "(cn={0})", this.contextSource));
		this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("quote\"guy", "quoteguyspassword"));
	}

	/*
	 * @Test public void messingWithEscapedChars() throws Exception {
	 * Hashtable<String,String> env = new Hashtable<>();
	 * env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	 * env.put(Context.PROVIDER_URL, "ldap://127.0.0.1:22389/dc=springsource,dc=com");
	 * env.put(Context.SECURITY_AUTHENTICATION, "simple");
	 * env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=springsource,dc=com");
	 * env.put(Context.SECURITY_CREDENTIALS, "password");
	 *
	 * InitialDirContext idc = new InitialDirContext(env); SearchControls searchControls =
	 * new SearchControls(); searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	 * DistinguishedName baseDn = new DistinguishedName("ou=\\\"quoted people\\\"");
	 * NamingEnumeration<SearchResult> matches = idc.search(baseDn, "(cn=*)", new Object[]
	 * {"quoteguy"}, searchControls);
	 *
	 * while(matches.hasMore()) { SearchResult match = matches.next(); DistinguishedName
	 * dn = new DistinguishedName(match.getName()); System.out.println("**** Match: " +
	 * match.getName() + " ***** " + dn);
	 *
	 * } }
	 */
	@Test
	public void testAuthenticationWithWrongPasswordFails() {
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });

		try {
			this.authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "wrongpassword"));
			fail("Shouldn't be able to bind with wrong password");
		}
		catch (BadCredentialsException expected) {
		}
	}

	@Test
	public void testUserDnPatternReturnsCorrectDn() {
		this.authenticator.setUserDnPatterns(new String[] { "cn={0},ou=people" });
		assertThat(this.authenticator.getUserDns("Joe").get(0)).isEqualTo("cn=Joe,ou=people");
	}

}
