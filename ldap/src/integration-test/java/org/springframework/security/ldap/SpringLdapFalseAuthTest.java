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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPException;
import org.junit.Test;


/**
 * @Auther - dratler
 */
public class SpringLdapFalseAuthTest {


	@Test(expected = IllegalArgumentException.class)
	public void testInMemoryDirectoryServerInvalidLdifFile() {
		//TODO - get exception here in case of invalid root base
		try {
			new InMemoryDirectoryServer("dc=springframework,dc=org",
					"classpath:missing-file.ldif");
		} catch (LDAPException e) {
			throw new IllegalArgumentException(e);
		}
	}


}
