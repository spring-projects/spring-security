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

package org.springframework.security.saml2.provider.service.authentication;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.util.Assert;

/**
 * Represents an incoming SAML 2.0 response containing an assertion that has not been
 * validated. {@link Saml2AuthenticationToken#isAuthenticated()} will always return false.
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 */
public class Saml2AuthenticationToken extends AbstractAuthenticationToken {

	private final RelyingPartyRegistration relyingPartyRegistration;

	private final String saml2Response;

	private final AbstractSaml2AuthenticationRequest authenticationRequest;

	/**
	 * Creates a {@link Saml2AuthenticationToken} with the provided parameters.
	 *
	 * Note that the given {@link RelyingPartyRegistration} should have all its templates
	 * resolved at this point. See {@link Saml2WebSsoAuthenticationFilter} for an example
	 * of performing that resolution.
	 * @param relyingPartyRegistration the resolved {@link RelyingPartyRegistration} to
	 * use
	 * @param saml2Response the SAML 2.0 response to authenticate
	 * @param authenticationRequest the {@code AuthNRequest} sent to the asserting party
	 *
	 * @since 5.6
	 */
	public Saml2AuthenticationToken(RelyingPartyRegistration relyingPartyRegistration, String saml2Response,
			AbstractSaml2AuthenticationRequest authenticationRequest) {
		super(Collections.emptyList());
		Assert.notNull(relyingPartyRegistration, "relyingPartyRegistration cannot be null");
		Assert.notNull(saml2Response, "saml2Response cannot be null");
		this.relyingPartyRegistration = relyingPartyRegistration;
		this.saml2Response = saml2Response;
		this.authenticationRequest = authenticationRequest;
	}

	/**
	 * Creates a {@link Saml2AuthenticationToken} with the provided parameters
	 *
	 * Note that the given {@link RelyingPartyRegistration} should have all its templates
	 * resolved at this point. See {@link Saml2WebSsoAuthenticationFilter} for an example
	 * of performing that resolution.
	 * @param relyingPartyRegistration the resolved {@link RelyingPartyRegistration} to
	 * use
	 * @param saml2Response the SAML 2.0 response to authenticate
	 *
	 * @since 5.4
	 */
	public Saml2AuthenticationToken(RelyingPartyRegistration relyingPartyRegistration, String saml2Response) {
		this(relyingPartyRegistration, saml2Response, null);
	}

	/**
	 * Returns the decoded and inflated SAML 2.0 Response XML object as a string
	 * @return decoded and inflated XML data as a {@link String}
	 */
	@Override
	public Object getCredentials() {
		return getSaml2Response();
	}

	/**
	 * Always returns null.
	 * @return null
	 */
	@Override
	public Object getPrincipal() {
		return null;
	}

	/**
	 * Get the resolved {@link RelyingPartyRegistration} associated with the request
	 * @return the resolved {@link RelyingPartyRegistration}
	 * @since 5.4
	 */
	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.relyingPartyRegistration;
	}

	/**
	 * Returns inflated and decoded XML representation of the SAML 2 Response
	 * @return inflated and decoded XML representation of the SAML 2 Response
	 */
	public String getSaml2Response() {
		return this.saml2Response;
	}

	/**
	 * @return false
	 */
	@Override
	public boolean isAuthenticated() {
		return false;
	}

	/**
	 * The state of this object cannot be changed. Will always throw an exception
	 * @param authenticated ignored
	 */
	@Override
	public void setAuthenticated(boolean authenticated) {
		throw new IllegalArgumentException();
	}

	/**
	 * Returns the authentication request sent to the assertion party or {@code null} if
	 * no authentication request is present
	 * @return the authentication request sent to the assertion party
	 * @since 5.6
	 */
	public AbstractSaml2AuthenticationRequest getAuthenticationRequest() {
		return this.authenticationRequest;
	}

}
