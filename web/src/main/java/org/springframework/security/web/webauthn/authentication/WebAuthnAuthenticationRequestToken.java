/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} used in
 * {@link WebAuthnAuthenticationProvider} for authenticating via WebAuthn.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class WebAuthnAuthenticationRequestToken extends AbstractAuthenticationToken {

	private final RelyingPartyAuthenticationRequest webAuthnRequest;

	/**
	 * Creates a new instance.
	 * @param webAuthnRequest the {@link RelyingPartyAuthenticationRequest} to use for
	 * authentication. Cannot be null.
	 */
	public WebAuthnAuthenticationRequestToken(RelyingPartyAuthenticationRequest webAuthnRequest) {
		super(AuthorityUtils.NO_AUTHORITIES);
		Assert.notNull(webAuthnRequest, "webAuthnRequest cannot be null");
		this.webAuthnRequest = webAuthnRequest;
	}

	/**
	 * Gets the {@link RelyingPartyAuthenticationRequest}
	 * @return the {@link RelyingPartyAuthenticationRequest}
	 */
	public RelyingPartyAuthenticationRequest getWebAuthnRequest() {
		return this.webAuthnRequest;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		Assert.isTrue(!authenticated, "Cannot set this token to trusted");
		super.setAuthenticated(authenticated);
	}

	@Override
	public Object getCredentials() {
		return this.webAuthnRequest.getPublicKey();
	}

	@Override
	public Object getPrincipal() {
		return this.webAuthnRequest.getPublicKey().getResponse().getUserHandle();
	}

}
