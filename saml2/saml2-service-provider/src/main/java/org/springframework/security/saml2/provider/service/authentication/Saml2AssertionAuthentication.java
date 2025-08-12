/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serial;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * An authentication based off of a SAML 2.0 Assertion
 *
 * @author Josh Cummings
 * @since 7.0
 * @see Saml2ResponseAssertionAccessor
 * @see Saml2ResponseAssertion
 */
public class Saml2AssertionAuthentication extends Saml2Authentication {

	@Serial
	private static final long serialVersionUID = -4194323643788693205L;

	private final Saml2ResponseAssertionAccessor assertion;

	private final String relyingPartyRegistrationId;

	public Saml2AssertionAuthentication(Saml2ResponseAssertionAccessor assertion,
			Collection<? extends GrantedAuthority> authorities, String relyingPartyRegistrationId) {
		super(assertion, assertion.getResponseValue(), authorities);
		this.assertion = assertion;
		this.relyingPartyRegistrationId = relyingPartyRegistrationId;
	}

	public Saml2AssertionAuthentication(Object principal, Saml2ResponseAssertionAccessor assertion,
			Collection<? extends GrantedAuthority> authorities, String relyingPartyRegistrationId) {
		super(principal, assertion.getResponseValue(), authorities);
		this.assertion = assertion;
		this.relyingPartyRegistrationId = relyingPartyRegistrationId;
		setAuthenticated(true);
	}

	@Override
	public Saml2AssertionAuthentication withGrantedAuthorities(Collection<GrantedAuthority> authorities) {
		return new Saml2AssertionAuthentication(getPrincipal(), getCredentials(), authorities,
				this.relyingPartyRegistrationId);
	}

	@Override
	public Saml2ResponseAssertionAccessor getCredentials() {
		return this.assertion;
	}

	public String getRelyingPartyRegistrationId() {
		return this.relyingPartyRegistrationId;
	}

}
