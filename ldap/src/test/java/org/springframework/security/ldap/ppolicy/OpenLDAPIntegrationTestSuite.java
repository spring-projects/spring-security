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

package org.springframework.security.ldap.ppolicy;

/**
 * Test cases which run against an OpenLDAP server.
 * <p>
 * Run the script in the module root to start the server and import the data before
 * running.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class OpenLDAPIntegrationTestSuite {

	PasswordPolicyAwareContextSource cs;

	/*
	 * @Before public void createContextSource() throws Exception { cs = new
	 * PasswordPolicyAwareContextSource("ldap://localhost:22389/dc=springsource,dc=com");
	 * cs.setUserDn("cn=admin,dc=springsource,dc=com"); cs.setPassword("password");
	 * cs.afterPropertiesSet(); }
	 *
	 * @Test public void simpleBindSucceeds() throws Exception { BindAuthenticator
	 * authenticator = new BindAuthenticator(cs); authenticator.setUserDnPatterns(new
	 * String[] {"uid={0},ou=users"}); LdapAuthenticationProvider provider = new
	 * LdapAuthenticationProvider(authenticator); provider.authenticate(new
	 * UsernamePasswordAuthenticationToken("luke","password")); }
	 *
	 * @Test(expected=LockedException.class) public void
	 * repeatedBindWithWrongPasswordLocksAccount() throws Exception { BindAuthenticator
	 * authenticator = new BindAuthenticator(cs); authenticator.setUserDnPatterns(new
	 * String[] {"uid={0},ou=users"}); LdapAuthenticationProvider provider = new
	 * LdapAuthenticationProvider(authenticator); for (int count=1; count < 4; count++) {
	 * try { Authentication a = provider.authenticate(new
	 * UsernamePasswordAuthenticationToken("lockme","wrong")); LdapUserDetailsImpl ud =
	 * (LdapUserDetailsImpl) a.getPrincipal(); assertTrue(ud.getTimeBeforeExpiration() <
	 * Integer.MAX_VALUE && ud.getTimeBeforeExpiration() > 0); } catch
	 * (BadCredentialsException expected) { } } }
	 *
	 * @Test public void passwordExpiryTimeIsDetectedCorrectly() throws Exception {
	 * BindAuthenticator authenticator = new BindAuthenticator(cs);
	 * authenticator.setUserDnPatterns(new String[] {"uid={0},ou=users"});
	 * LdapAuthenticationProvider provider = new
	 * LdapAuthenticationProvider(authenticator); Authentication a =
	 * provider.authenticate(new
	 * UsernamePasswordAuthenticationToken("expireme","password")); PasswordPolicyData ud
	 * = (LdapUserDetailsImpl) a.getPrincipal(); assertTrue(ud.getTimeBeforeExpiration() <
	 * Integer.MAX_VALUE && ud.getTimeBeforeExpiration() > 0); }
	 */

}
