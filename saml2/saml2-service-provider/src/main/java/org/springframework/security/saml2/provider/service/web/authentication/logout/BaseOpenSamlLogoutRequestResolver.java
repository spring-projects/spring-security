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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SessionIndexBuilder;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * For internal use only. Intended for consolidating common behavior related to minting a
 * SAML 2.0 Logout Request.
 */
final class BaseOpenSamlLogoutRequestResolver implements Saml2LogoutRequestResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final Log logger = LogFactory.getLog(getClass());

	private final OpenSamlOperations saml;

	private Clock clock = Clock.systemUTC();

	private final LogoutRequestMarshaller marshaller;

	private final IssuerBuilder issuerBuilder;

	private final NameIDBuilder nameIdBuilder;

	private final SessionIndexBuilder sessionIndexBuilder;

	private final LogoutRequestBuilder logoutRequestBuilder;

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private Converter<HttpServletRequest, String> relayStateResolver = (request) -> UUID.randomUUID().toString();

	private Consumer<LogoutRequestParameters> parametersConsumer = (parameters) -> {
	};

	/**
	 * Construct a {@link BaseOpenSamlLogoutRequestResolver}
	 */
	BaseOpenSamlLogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			OpenSamlOperations saml) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.saml = saml;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.marshaller = (LogoutRequestMarshaller) registry.getMarshallerFactory()
			.getMarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.marshaller, "logoutRequestMarshaller must be configured in OpenSAML");
		this.logoutRequestBuilder = (LogoutRequestBuilder) registry.getBuilderFactory()
			.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.logoutRequestBuilder, "logoutRequestBuilder must be configured in OpenSAML");
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
		this.nameIdBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.nameIdBuilder, "nameIdBuilder must be configured in OpenSAML");
		this.sessionIndexBuilder = (SessionIndexBuilder) registry.getBuilderFactory()
			.getBuilder(SessionIndex.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.sessionIndexBuilder, "sessionIndexBuilder must be configured in OpenSAML");
	}

	void setClock(Clock clock) {
		this.clock = clock;
	}

	void setRelayStateResolver(Converter<HttpServletRequest, String> relayStateResolver) {
		this.relayStateResolver = relayStateResolver;
	}

	void setParametersConsumer(Consumer<LogoutRequestParameters> parametersConsumer) {
		this.parametersConsumer = parametersConsumer;
	}

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Logout Request.
	 *
	 * By default, includes a {@code NameID} based on the {@link Authentication} instance
	 * as well as the {@code Destination} and {@code Issuer} based on the
	 * {@link RelyingPartyRegistration} derived from the {@link Authentication}.
	 * @param request the HTTP request
	 * @param authentication the current user
	 * @return a signed and serialized SAML 2.0 Logout Request
	 */
	@Override
	public Saml2LogoutRequest resolve(HttpServletRequest request, Authentication authentication) {
		String registrationId = getRegistrationId(authentication);
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null) {
			return null;
		}
		if (registration.getAssertingPartyMetadata().getSingleLogoutServiceLocation() == null) {
			return null;
		}
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		String entityId = uriResolver.resolve(registration.getEntityId());
		LogoutRequest logoutRequest = this.logoutRequestBuilder.buildObject();
		logoutRequest.setDestination(registration.getAssertingPartyMetadata().getSingleLogoutServiceLocation());
		Issuer issuer = this.issuerBuilder.buildObject();
		issuer.setValue(entityId);
		logoutRequest.setIssuer(issuer);
		NameID nameId = this.nameIdBuilder.buildObject();
		nameId.setValue(authentication.getName());
		logoutRequest.setNameID(nameId);
		if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal) {
			Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
			for (String index : principal.getSessionIndexes()) {
				SessionIndex sessionIndex = this.sessionIndexBuilder.buildObject();
				sessionIndex.setValue(index);
				logoutRequest.getSessionIndexes().add(sessionIndex);
			}
		}
		logoutRequest.setIssueInstant(Instant.now(this.clock));
		this.parametersConsumer
			.accept(new LogoutRequestParameters(request, registration, authentication, logoutRequest));
		if (logoutRequest.getID() == null) {
			logoutRequest.setID("LR" + UUID.randomUUID());
		}
		String relayState = this.relayStateResolver.convert(request);
		Saml2LogoutRequest.Builder result = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
			.id(logoutRequest.getID());
		if (registration.getAssertingPartyMetadata().getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
			String xml = serialize(this.saml.withSigningKeys(registration.getSigningX509Credentials())
				.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
				.sign(logoutRequest));
			String samlRequest = Saml2Utils.withDecoded(xml).encode();
			return result.samlRequest(samlRequest).relayState(relayState).build();
		}
		else {
			String xml = serialize(logoutRequest);
			String deflatedAndEncoded = Saml2Utils.withDecoded(xml).deflate(true).encode();
			result.samlRequest(deflatedAndEncoded);
			Map<String, String> signingParameters = new HashMap<>();
			signingParameters.put(Saml2ParameterNames.SAML_REQUEST, deflatedAndEncoded);
			signingParameters.put(Saml2ParameterNames.RELAY_STATE, relayState);
			Map<String, String> query = this.saml.withSigningKeys(registration.getSigningX509Credentials())
				.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
				.sign(signingParameters);
			return result.parameters((params) -> params.putAll(query)).build();
		}
	}

	private String getRegistrationId(Authentication authentication) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Attempting to resolve registrationId from " + authentication);
		}
		if (authentication == null) {
			return null;
		}
		Object principal = authentication.getPrincipal();
		if (principal instanceof Saml2AuthenticatedPrincipal) {
			return ((Saml2AuthenticatedPrincipal) principal).getRelyingPartyRegistrationId();
		}
		return null;
	}

	private String serialize(LogoutRequest logoutRequest) {
		return this.saml.serialize(logoutRequest).serialize();
	}

	static final class LogoutRequestParameters {

		private final HttpServletRequest request;

		private final RelyingPartyRegistration registration;

		private final Authentication authentication;

		private final LogoutRequest logoutRequest;

		LogoutRequestParameters(HttpServletRequest request, RelyingPartyRegistration registration,
				Authentication authentication, LogoutRequest logoutRequest) {
			this.request = request;
			this.registration = registration;
			this.authentication = authentication;
			this.logoutRequest = logoutRequest;
		}

		HttpServletRequest getRequest() {
			return this.request;
		}

		RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

		Authentication getAuthentication() {
			return this.authentication;
		}

		LogoutRequest getLogoutRequest() {
			return this.logoutRequest;
		}

	}

}
