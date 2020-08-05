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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.*;
import org.springframework.ldap.UncategorizedLdapException;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import java.util.*;

/**
 * @author Luke Taylor
 */
public class PasswordPolicyAwareContextSourceTests {

	private PasswordPolicyAwareContextSource ctxSource;

	private final LdapContext ctx = mock(LdapContext.class);

	@Before
	public void setUp() {
		reset(ctx);
		ctxSource = new PasswordPolicyAwareContextSource("ldap://blah:789/dc=springframework,dc=org") {
			@Override
			protected DirContext createContext(Hashtable env) {
				if ("manager".equals(env.get(Context.SECURITY_PRINCIPAL))) {
					return ctx;
				}

				return null;
			}
		};
		ctxSource.setUserDn("manager");
		ctxSource.setPassword("password");
		ctxSource.afterPropertiesSet();
	}

	@Test
	public void contextIsReturnedWhenNoControlsAreSetAndReconnectIsSuccessful() {
		assertThat(ctxSource.getContext("user", "ignored")).isNotNull();
	}

	@Test(expected = UncategorizedLdapException.class)
	public void standardExceptionIsPropagatedWhenExceptionRaisedAndNoControlsAreSet() throws Exception {
		doThrow(new NamingException("some LDAP exception")).when(ctx).reconnect(any(Control[].class));

		ctxSource.getContext("user", "ignored");
	}

	@Test(expected = PasswordPolicyException.class)
	public void lockedPasswordPolicyControlRaisesPasswordPolicyException() throws Exception {
		when(ctx.getResponseControls()).thenReturn(new Control[] {
				new PasswordPolicyResponseControl(PasswordPolicyResponseControlTests.OPENLDAP_LOCKED_CTRL) });

		doThrow(new NamingException("locked message")).when(ctx).reconnect(any(Control[].class));

		ctxSource.getContext("user", "ignored");
	}

}
