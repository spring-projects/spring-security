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

package org.springframework.security.ldap;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.junit.Test;

/**
 * Tests {@link LdapUtils}
 *
 * @author Luke Taylor
 */
public class LdapUtilsTests {

	// ~ Methods
	// ========================================================================================================

	@Test
	public void testCloseContextSwallowsNamingException() throws Exception {
		final DirContext dirCtx = mock(DirContext.class);
		doThrow(new NamingException()).when(dirCtx).close();

		LdapUtils.closeContext(dirCtx);
	}

	@Test
	public void testGetRelativeNameReturnsEmptyStringForDnEqualToBaseName()
			throws Exception {
		final DirContext mockCtx = mock(DirContext.class);

		when(mockCtx.getNameInNamespace()).thenReturn("dc=springframework,dc=org");

		assertThat(LdapUtils.getRelativeName("dc=springframework,dc=org",mockCtx)).isEqualTo("");
	}

	@Test
	public void testGetRelativeNameReturnsFullDnWithEmptyBaseName() throws Exception {
		final DirContext mockCtx = mock(DirContext.class);
		when(mockCtx.getNameInNamespace()).thenReturn("");

		assertThat(LdapUtils.getRelativeName("cn=jane,dc=springframework,dc=org", mockCtx)).isEqualTo("cn=jane,dc=springframework,dc=org");
	}

	@Test
	public void testGetRelativeNameWorksWithArbitrarySpaces() throws Exception {
		final DirContext mockCtx = mock(DirContext.class);
		when(mockCtx.getNameInNamespace()).thenReturn("dc=springsecurity,dc = org");

		assertThat(LdapUtils.getRelativeName(
				"cn=jane smith, dc = springsecurity , dc=org", mockCtx)).isEqualTo("cn=jane smith");
	}

	@Test
	public void testRootDnsAreParsedFromUrlsCorrectly() {
		assertThat(LdapUtils.parseRootDnFromUrl("ldap://monkeymachine")).isEqualTo("");
		assertThat(LdapUtils.parseRootDnFromUrl("ldap://monkeymachine:11389")).isEqualTo("");
		assertThat(LdapUtils.parseRootDnFromUrl("ldap://monkeymachine/")).isEqualTo("");
		assertThat(LdapUtils.parseRootDnFromUrl("ldap://monkeymachine.co.uk/")).isEqualTo("");
		assertThat(
				LdapUtils
						.parseRootDnFromUrl("ldaps://monkeymachine.co.uk/dc=springframework,dc=org")).isEqualTo("dc=springframework,dc=org");
		assertThat(
				LdapUtils.parseRootDnFromUrl("ldap:///dc=springframework,dc=org")).isEqualTo("dc=springframework,dc=org");
		assertThat(
				LdapUtils
						.parseRootDnFromUrl("ldap://monkeymachine/dc=springframework,dc=org")).isEqualTo("dc=springframework,dc=org");
		assertThat(
				LdapUtils
						.parseRootDnFromUrl("ldap://monkeymachine.co.uk/dc=springframework,dc=org/ou=blah")).isEqualTo("dc=springframework,dc=org/ou=blah");
		assertThat(
				LdapUtils
						.parseRootDnFromUrl("ldap://monkeymachine.co.uk:389/dc=springframework,dc=org/ou=blah")).isEqualTo("dc=springframework,dc=org/ou=blah");
	}
}
