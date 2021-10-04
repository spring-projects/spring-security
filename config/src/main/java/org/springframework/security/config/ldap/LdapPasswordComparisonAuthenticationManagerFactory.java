/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.ldap;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.util.Assert;

/**
 * Creates an {@link AuthenticationManager} that can perform LDAP authentication using
 * password comparison.
 *
 * @author Eleftheria Stein
 * @since 5.7
 */
public class LdapPasswordComparisonAuthenticationManagerFactory
		extends AbstractLdapAuthenticationManagerFactory<PasswordComparisonAuthenticator> {

	private PasswordEncoder passwordEncoder;

	private String passwordAttribute;

	public LdapPasswordComparisonAuthenticationManagerFactory(BaseLdapPathContextSource contextSource,
			PasswordEncoder passwordEncoder) {
		super(contextSource);
		setPasswordEncoder(passwordEncoder);
	}

	/**
	 * Specifies the {@link PasswordEncoder} to be used when authenticating with password
	 * comparison.
	 * @param passwordEncoder the {@link PasswordEncoder} to use
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder must not be null.");
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * The attribute in the directory which contains the user password. Only used when
	 * authenticating with password comparison. Defaults to "userPassword".
	 * @param passwordAttribute the attribute in the directory which contains the user
	 * password
	 */
	public void setPasswordAttribute(String passwordAttribute) {
		this.passwordAttribute = passwordAttribute;
	}

	@Override
	protected PasswordComparisonAuthenticator createDefaultLdapAuthenticator() {
		PasswordComparisonAuthenticator ldapAuthenticator = new PasswordComparisonAuthenticator(getContextSource());
		if (this.passwordAttribute != null) {
			ldapAuthenticator.setPasswordAttributeName(this.passwordAttribute);
		}
		ldapAuthenticator.setPasswordEncoder(this.passwordEncoder);
		return ldapAuthenticator;
	}

}
