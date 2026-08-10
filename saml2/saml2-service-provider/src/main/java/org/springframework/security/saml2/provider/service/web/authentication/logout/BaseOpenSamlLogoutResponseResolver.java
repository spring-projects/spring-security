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
import org.jspecify.annotations.Nullable;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.AbstractSAMLObjectBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * For internal use only. Intended for consolidating common behavior related to minting a
 * SAML 2.0 Logout Response.
 */
final class BaseOpenSamlLogoutResponseResolver implements Saml2LogoutResponseResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final Log logger = LogFactory.getLog(getClass());

	private final LogoutResponseBuilder logoutResponseBuilder;

	private final IssuerBuilder issuerBuilder;

	private final StatusBuilder statusBuilder;

	private final StatusCodeBuilder statusCodeBuilder;

	private final OpenSamlOperations saml;

	private final @Nullable RelyingPartyRegistrationRepository registrations;

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private Clock clock = Clock.systemUTC();

	private Consumer<LogoutResponseParameters> parametersConsumer = (parameters) -> {
	};

	/**
	 * Construct a {@link BaseOpenSamlLogoutResponseResolver}
	 */
	BaseOpenSamlLogoutResponseResolver(@Nullable RelyingPartyRegistrationRepository registrations,
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver, OpenSamlOperations saml) {
		this.saml = saml;
		this.registrations = registrations;
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		Assert.notNull(registry, "XMLObjectProviderRegistry cannot be null");
		XMLObjectBuilderFactory builderFactory = registry.getBuilderFactory();
		this.logoutResponseBuilder = builder(builderFactory.ensureBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME));
		this.issuerBuilder = builder(builderFactory.ensureBuilder(Issuer.DEFAULT_ELEMENT_NAME));
		this.statusBuilder = builder(builderFactory.ensureBuilder(Status.DEFAULT_ELEMENT_NAME));
		this.statusCodeBuilder = builder(builderFactory.ensureBuilder(StatusCode.DEFAULT_ELEMENT_NAME));
	}

	private static <T extends SAMLObject, B extends AbstractSAMLObjectBuilder<T>> B builder(
			XMLObjectBuilder<T> builder) {
		return (B) builder;
	}

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Logout Response.
	 *
	 * By default, includes a {@code RelayState} based on the {@link HttpServletRequest}
	 * as well as the {@code Destination} and {@code Issuer} based on the
	 * {@link RelyingPartyRegistration} derived from the {@link Authentication}. The
	 * logout response is also marked as {@code SUCCESS}.
	 * @param request the HTTP request
	 * @param authentication the current user
	 * @return a signed and serialized SAML 2.0 Logout Response
	 */
	@Override
	public @Nullable Saml2LogoutResponse resolve(HttpServletRequest request, @Nullable Authentication authentication) {
		return resolve(request, authentication, StatusCode.SUCCESS);
	}

	@Override
	public @Nullable Saml2LogoutResponse resolve(HttpServletRequest request, @Nullable Authentication authentication,
			Saml2AuthenticationException authenticationException) {
		return resolve(request, authentication, getSamlStatus(authenticationException));
	}

	private @Nullable Saml2LogoutResponse resolve(HttpServletRequest request, @Nullable Authentication authentication,
			String statusCode) {
		LogoutRequest logoutRequest = this.saml.deserialize(extractSamlRequest(request));
		String registrationId = getRegistrationId(authentication);
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null && this.registrations != null) {
			Issuer issuer = logoutRequest.getIssuer();
			Assert.notNull(issuer, "LogoutRequest#Issuer cannot be null");
			registration = this.registrations.findUniqueByAssertingPartyEntityId(getValue(issuer));
		}
		if (registration == null) {
			return null;
		}
		if (registration.getAssertingPartyMetadata().getSingleLogoutServiceResponseLocation() == null) {
			return null;
		}
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		String entityId = uriResolver.resolve(registration.getEntityId());
		LogoutResponse logoutResponse = this.logoutResponseBuilder.buildObject();
		logoutResponse
			.setDestination(registration.getAssertingPartyMetadata().getSingleLogoutServiceResponseLocation());
		Issuer issuer = this.issuerBuilder.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(entityId);
		logoutResponse.setIssuer(issuer);
		StatusCode code = this.statusCodeBuilder.buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
		code.setValue(statusCode);
		Status status = this.statusBuilder.buildObject(Status.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(code);
		logoutResponse.setStatus(status);
		logoutResponse.setInResponseTo(logoutRequest.getID());
		if (logoutResponse.getID() == null) {
			logoutResponse.setID("LR" + UUID.randomUUID());
		}
		logoutResponse.setIssueInstant(Instant.now(this.clock));
		this.parametersConsumer
			.accept(new LogoutResponseParameters(request, registration, authentication, logoutRequest));
		String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
		Saml2LogoutResponse.Builder result = Saml2LogoutResponse.withRelyingPartyRegistration(registration);
		if (registration.getAssertingPartyMetadata().getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
			String xml = serialize(this.saml.withSigningKeys(registration.getSigningX509Credentials())
				.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
				.sign(logoutResponse));
			String samlResponse = Saml2Utils.withDecoded(xml).encode();
			result.samlResponse(samlResponse);
			if (relayState != null) {
				result.relayState(relayState);
			}
			return result.build();
		}
		else {
			String xml = serialize(logoutResponse);
			String deflatedAndEncoded = Saml2Utils.withDecoded(xml).deflate(true).encode();
			result.samlResponse(deflatedAndEncoded);
			Map<String, String> signingParameters = new HashMap<>();
			signingParameters.put(Saml2ParameterNames.SAML_RESPONSE, deflatedAndEncoded);
			if (relayState != null) {
				signingParameters.put(Saml2ParameterNames.RELAY_STATE, relayState);
			}
			Map<String, String> parameters = this.saml.withSigningKeys(registration.getSigningX509Credentials())
				.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
				.sign(signingParameters);
			return result.parameters((params) -> params.putAll(parameters)).build();
		}
	}

	String getValue(XSString object) {
		String value = object.getValue();
		Assert.notNull(value, "required elements must have a value");
		return value;
	}

	void setClock(Clock clock) {
		this.clock = clock;
	}

	void setParametersConsumer(Consumer<LogoutResponseParameters> parametersConsumer) {
		this.parametersConsumer = parametersConsumer;
	}

	private @Nullable String getRegistrationId(@Nullable Authentication authentication) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Attempting to resolve registrationId from " + authentication);
		}
		if (authentication == null) {
			return null;
		}
		if (authentication instanceof Saml2AssertionAuthentication saml2) {
			return saml2.getRelyingPartyRegistrationId();
		}
		if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal saml2) {
			return saml2.getRelyingPartyRegistrationId();
		}
		return null;
	}

	private String extractSamlRequest(HttpServletRequest request) {
		return Saml2Utils.withEncoded(request.getParameter(Saml2ParameterNames.SAML_REQUEST))
			.inflate(Saml2MessageBindingUtils.isHttpRedirectBinding(request))
			.decode();
	}

	private String serialize(LogoutResponse logoutResponse) {
		return this.saml.serialize(logoutResponse).serialize();
	}

	private String getSamlStatus(Saml2AuthenticationException exception) {
		Saml2Error saml2Error = exception.getSaml2Error();
		return switch (saml2Error.getErrorCode()) {
			case Saml2ErrorCodes.INVALID_DESTINATION -> StatusCode.REQUEST_DENIED;
			case Saml2ErrorCodes.INVALID_REQUEST -> StatusCode.REQUESTER;
			default -> StatusCode.RESPONDER;
		};
	}

	static final class LogoutResponseParameters {

		private final HttpServletRequest request;

		private final RelyingPartyRegistration registration;

		private final @Nullable Authentication authentication;

		private final LogoutRequest logoutRequest;

		LogoutResponseParameters(HttpServletRequest request, RelyingPartyRegistration registration,
				@Nullable Authentication authentication, LogoutRequest logoutRequest) {
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

		@Nullable Authentication getAuthentication() {
			return this.authentication;
		}

		LogoutRequest getLogoutRequest() {
			return this.logoutRequest;
		}

	}

}
