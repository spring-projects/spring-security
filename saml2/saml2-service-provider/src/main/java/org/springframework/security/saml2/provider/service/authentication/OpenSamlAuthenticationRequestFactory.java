/*
 * Copyright 2002-2020 the original author or authors.
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

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest.Builder;
import org.springframework.util.Assert;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlDeflate;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlEncode;

/**
 * @since 5.2
 */
public class OpenSamlAuthenticationRequestFactory implements Saml2AuthenticationRequestFactory {
	private Clock clock = Clock.systemUTC();
	private final OpenSamlImplementation saml = OpenSamlImplementation.getInstance();
	private String protocolBinding = SAMLConstants.SAML2_POST_BINDING_URI;

	@Override
	@Deprecated
	public String createAuthenticationRequest(Saml2AuthenticationRequest request) {
		AuthnRequest authnRequest = createAuthnRequest(request.getIssuer(),
				request.getDestination(), request.getAssertionConsumerServiceUrl());
		return this.saml.serialize(authnRequest, request.getCredentials());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2PostAuthenticationRequest createPostAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = createAuthnRequest(context);
		String xml = context.getRelyingPartyRegistration().getProviderDetails().isSignAuthNRequest() ?
			this.saml.serialize(authnRequest, context.getRelyingPartyRegistration().getSigningCredentials()) :
			this.saml.serialize(authnRequest);

		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(samlEncode(xml.getBytes(UTF_8)))
				.build();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = createAuthnRequest(context);
		String xml = this.saml.serialize(authnRequest);
		Builder result = Saml2RedirectAuthenticationRequest.withAuthenticationRequestContext(context);
		String deflatedAndEncoded = samlEncode(samlDeflate(xml));
		result.samlRequest(deflatedAndEncoded)
				.relayState(context.getRelayState());

		if (context.getRelyingPartyRegistration().getProviderDetails().isSignAuthNRequest()) {
			List<Saml2X509Credential> signingCredentials = context.getRelyingPartyRegistration().getSigningCredentials();
			Map<String, String> signedParams = this.saml.signQueryParameters(
					signingCredentials,
					deflatedAndEncoded,
					context.getRelayState()
			);
			result.samlRequest(signedParams.get("SAMLRequest"))
					.relayState(signedParams.get("RelayState"))
					.sigAlg(signedParams.get("SigAlg"))
					.signature(signedParams.get("Signature"));
		}

		return result.build();
	}

	private AuthnRequest createAuthnRequest(Saml2AuthenticationRequestContext context) {
		return createAuthnRequest(context.getIssuer(),
				context.getDestination(), context.getAssertionConsumerServiceUrl());
	}

	private AuthnRequest createAuthnRequest(String issuer, String destination, String assertionConsumerServiceUrl) {
		AuthnRequest auth = this.saml.buildSamlObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
		auth.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		auth.setIssueInstant(new DateTime(this.clock.millis()));
		auth.setForceAuthn(Boolean.FALSE);
		auth.setIsPassive(Boolean.FALSE);
		auth.setProtocolBinding(protocolBinding);
		Issuer iss = this.saml.buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
		iss.setValue(issuer);
		auth.setIssuer(iss);
		auth.setDestination(destination);
		auth.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		return auth;
	}

	/**
	 * '
	 * Use this {@link Clock} with {@link Instant#now()} for generating
	 * timestamps
	 *
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * Sets the {@code protocolBinding} to use when generating authentication requests.
	 * Acceptable values are {@link SAMLConstants#SAML2_POST_BINDING_URI} and
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * The IDP will be reading this value in the {@code AuthNRequest} to determine how to
	 * send the Response/Assertion to the ACS URL, assertion consumer service URL.
	 *
	 * @param protocolBinding either {@link SAMLConstants#SAML2_POST_BINDING_URI} or
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * @throws IllegalArgumentException if the protocolBinding is not valid
	 */
	public void setProtocolBinding(String protocolBinding) {
		boolean isAllowedBinding = SAMLConstants.SAML2_POST_BINDING_URI.equals(protocolBinding) ||
				SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(protocolBinding);
		if (!isAllowedBinding) {
			throw new IllegalArgumentException("Invalid protocol binding: " + protocolBinding);
		}
		this.protocolBinding = protocolBinding;
	}
}
