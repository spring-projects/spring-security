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

import javax.naming.NamingEnumeration;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

import org.junit.Test;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Luke Taylor
 */
public class PasswordComparisonAuthenticatorMockTests {

	@Test
	public void ldapCompareOperationIsUsedWhenPasswordIsNotRetrieved() throws Exception {
		final DirContext dirCtx = mock(DirContext.class);
		final BaseLdapPathContextSource source = mock(BaseLdapPathContextSource.class);
		final BasicAttributes attrs = new BasicAttributes();
		attrs.put(new BasicAttribute("uid", "bob"));

		PasswordComparisonAuthenticator authenticator = new PasswordComparisonAuthenticator(source);

		authenticator.setUserDnPatterns(new String[] { "cn={0},ou=people" });

		// Get the mock to return an empty attribute set
		when(source.getReadOnlyContext()).thenReturn(dirCtx);
		when(dirCtx.getAttributes(eq("cn=Bob,ou=people"), any(String[].class))).thenReturn(attrs);
		when(dirCtx.getNameInNamespace()).thenReturn("dc=springframework,dc=org");

		// Setup a single return value (i.e. success)
		final NamingEnumeration searchResults = new BasicAttributes("", null).getAll();

		when(dirCtx.search(eq("cn=Bob,ou=people"), eq("(userPassword={0})"), any(Object[].class),
				any(SearchControls.class))).thenReturn(searchResults);

		authenticator.authenticate(new UsernamePasswordAuthenticationToken("Bob", "bobspassword"));
	}

}
