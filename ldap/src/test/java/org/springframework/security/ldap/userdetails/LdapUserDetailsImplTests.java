/*
 * Copyright 2012-2016 the original author or authors.
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

package org.springframework.security.ldap.userdetails;

import org.junit.Test;

import org.springframework.security.core.CredentialsContainer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link LdapUserDetailsImpl}
 *
 * @author Joe Grandja
 */
public class LdapUserDetailsImplTests {

	@Test
	public void credentialsAreCleared() {
		LdapUserDetailsImpl.Essence mutableLdapUserDetails = new LdapUserDetailsImpl.Essence();
		mutableLdapUserDetails.setDn("uid=username1,ou=people,dc=example,dc=com");
		mutableLdapUserDetails.setUsername("username1");
		mutableLdapUserDetails.setPassword("password");

		LdapUserDetails ldapUserDetails = mutableLdapUserDetails.createUserDetails();
		assertThat(ldapUserDetails).isInstanceOf(CredentialsContainer.class);
		ldapUserDetails.eraseCredentials();
		assertThat(ldapUserDetails.getPassword()).isNull();
	}

}
