/*
 * Copyright 2002-2021 the original author or authors.
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

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlSigningUtils.QueryParametersPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link Saml2AuthenticationRequestFactory} that generates, signs, and serializes a
 * SAML 2.0 AuthnRequest using OpenSAML 3
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 * @deprecated Because OpenSAML 3 has reached End-of-Life, please update to
 * {@link OpenSaml4AuthenticationRequestFactory}
 */
public class OpenSamlAuthenticationRequestFactory implements Saml2AuthenticationRequestFactory {

	static {
		OpenSamlInitializationService.initialize();
	}

	private AuthnRequestBuilder authnRequestBuilder;

	private IssuerBuilder issuerBuilder;

	private Clock clock = Clock.systemUTC();

	private Converter<Saml2AuthenticationRequestContext, Saml2MessageBinding> protocolBindingResolver = (context) -> {
		if (context == null) {
			return Saml2MessageBinding.POST;
		}
		return context.getRelyingPartyRegistration().getAssertionConsumerServiceBinding();
	};

	private Converter<Saml2AuthenticationRequestContext, AuthnRequest> authenticationRequestContextConverter;

	/**
	 * Creates an {@link OpenSamlAuthenticationRequestFactory}
	 */
	public OpenSamlAuthenticationRequestFactory() {
		this.authenticationRequestContextConverter = this::createAuthnRequest;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.authnRequestBuilder = (AuthnRequestBuilder) registry.getBuilderFactory()
				.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	}

	@Override
	@Deprecated
	public String createAuthenticationRequest(Saml2AuthenticationRequest request) {
		Saml2MessageBinding binding = this.protocolBindingResolver.convert(null);
		RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("noId")
				.assertionConsumerServiceBinding(binding)
				.assertionConsumerServiceLocation(request.getAssertionConsumerServiceUrl())
				.entityId(request.getIssuer()).remoteIdpEntityId("noIssuer").idpWebSsoUrl("noUrl")
				.credentials((credentials) -> credentials.addAll(request.getCredentials())).build();
		Saml2AuthenticationRequestContext context = Saml2AuthenticationRequestContext.builder()
				.relyingPartyRegistration(registration).issuer(request.getIssuer())
				.assertionConsumerServiceUrl(request.getAssertionConsumerServiceUrl()).build();
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		return OpenSamlSigningUtils.serialize(OpenSamlSigningUtils.sign(authnRequest, registration));
	}

	@Override
	public Saml2PostAuthenticationRequest createPostAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		RelyingPartyRegistration registration = context.getRelyingPartyRegistration();
		if (registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
			OpenSamlSigningUtils.sign(authnRequest, registration);
		}
		String xml = OpenSamlSigningUtils.serialize(authnRequest);
		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))).build();
	}

	@Override
	public Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(
			Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		RelyingPartyRegistration registration = context.getRelyingPartyRegistration();
		String xml = OpenSamlSigningUtils.serialize(authnRequest);
		Saml2RedirectAuthenticationRequest.Builder result = Saml2RedirectAuthenticationRequest
				.withAuthenticationRequestContext(context);
		String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
		result.samlRequest(deflatedAndEncoded).relayState(context.getRelayState());
		if (registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
			QueryParametersPartial partial = OpenSamlSigningUtils.sign(registration).param("SAMLRequest",
					deflatedAndEncoded);
			if (StringUtils.hasText(context.getRelayState())) {
				partial.param("RelayState", context.getRelayState());
			}
			Map<String, String> parameters = partial.parameters();
			return result.sigAlg(parameters.get("SigAlg")).signature(parameters.get("Signature")).build();
		}
		return result.build();
	}

	private AuthnRequest createAuthnRequest(Saml2AuthenticationRequestContext context) {
		String issuer = context.getIssuer();
		String destination = context.getDestination();
		String assertionConsumerServiceUrl = context.getAssertionConsumerServiceUrl();
		Saml2MessageBinding protocolBinding = this.protocolBindingResolver.convert(context);
		AuthnRequest auth = this.authnRequestBuilder.buildObject();
		if (auth.getID() == null) {
			auth.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		}
		if (auth.getIssueInstant() == null) {
			auth.setIssueInstant(new DateTime(this.clock.millis()));
		}
		if (auth.isForceAuthn() == null) {
			auth.setForceAuthn(Boolean.FALSE);
		}
		if (auth.isPassive() == null) {
			auth.setIsPassive(Boolean.FALSE);
		}
		if (auth.getProtocolBinding() == null) {
			auth.setProtocolBinding(protocolBinding.getUrn());
		}
		Issuer iss = this.issuerBuilder.buildObject();
		iss.setValue(issuer);
		auth.setIssuer(iss);
		auth.setDestination(destination);
		auth.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		return auth;
	}

	/**
	 * Set the {@link AuthnRequest} post-processor resolver
	 * @param authenticationRequestContextConverter
	 * @since 5.4
	 */
	public void setAuthenticationRequestContextConverter(
			Converter<Saml2AuthenticationRequestContext, AuthnRequest> authenticationRequestContextConverter) {
		Assert.notNull(authenticationRequestContextConverter, "authenticationRequestContextConverter cannot be null");
		this.authenticationRequestContextConverter = authenticationRequestContextConverter;
	}

	/**
	 * ' Use this {@link Clock} with {@link Instant#now()} for generating timestamps
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * Sets the {@code protocolBinding} to use when generating authentication requests.
	 * Acceptable values are {@link SAMLConstants#SAML2_POST_BINDING_URI} and
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI} The IDP will be reading this value
	 * in the {@code AuthNRequest} to determine how to send the Response/Assertion to the
	 * ACS URL, assertion consumer service URL.
	 * @param protocolBinding either {@link SAMLConstants#SAML2_POST_BINDING_URI} or
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * @throws IllegalArgumentException if the protocolBinding is not valid
	 * @deprecated Use
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.Builder#assertionConsumerServiceBinding(Saml2MessageBinding)}
	 * instead
	 */
	@Deprecated
	public void setProtocolBinding(String protocolBinding) {
		Saml2MessageBinding binding = Saml2MessageBinding.from(protocolBinding);
		Assert.notNull(binding, "Invalid protocol binding: " + protocolBinding);
		this.protocolBindingResolver = (context) -> binding;
	}

}
