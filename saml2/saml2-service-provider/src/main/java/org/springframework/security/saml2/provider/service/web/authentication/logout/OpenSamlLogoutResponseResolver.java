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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.BiConsumer;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseMarshaller;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;
import org.springframework.util.Assert;

/**
 * For internal use only. Intended for consolidating common behavior related to minting a
 * SAML 2.0 Logout Response.
 */
final class OpenSamlLogoutResponseResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final Log logger = LogFactory.getLog(getClass());

	private final ParserPool parserPool;

	private final LogoutRequestUnmarshaller unmarshaller;

	private final LogoutResponseMarshaller marshaller;

	private final LogoutResponseBuilder logoutResponseBuilder;

	private final IssuerBuilder issuerBuilder;

	private final StatusBuilder statusBuilder;

	private final StatusCodeBuilder statusCodeBuilder;

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	/**
	 * Construct a {@link OpenSamlLogoutResponseResolver}
	 */
	OpenSamlLogoutResponseResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutRequestUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
		this.marshaller = (LogoutResponseMarshaller) registry.getMarshallerFactory()
				.getMarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.marshaller, "logoutResponseMarshaller must be configured in OpenSAML");
		this.logoutResponseBuilder = (LogoutResponseBuilder) registry.getBuilderFactory()
				.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.logoutResponseBuilder, "logoutResponseBuilder must be configured in OpenSAML");
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
		this.statusBuilder = (StatusBuilder) registry.getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.statusBuilder, "statusBuilder must be configured in OpenSAML");
		this.statusCodeBuilder = (StatusCodeBuilder) registry.getBuilderFactory()
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.statusCodeBuilder, "statusCodeBuilder must be configured in OpenSAML");
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
	Saml2LogoutResponse resolve(HttpServletRequest request, Authentication authentication) {
		return resolve(request, authentication, (registration, logoutResponse) -> {
		});
	}

	Saml2LogoutResponse resolve(HttpServletRequest request, Authentication authentication,
			BiConsumer<RelyingPartyRegistration, LogoutResponse> logoutResponseConsumer) {
		String registrationId = getRegistrationId(authentication);
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null) {
			return null;
		}
		if (registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation() == null) {
			return null;
		}
		LogoutRequest logoutRequest = parse(extractSamlRequest(request));
		LogoutResponse logoutResponse = this.logoutResponseBuilder.buildObject();
		logoutResponse.setDestination(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation());
		Issuer issuer = this.issuerBuilder.buildObject();
		issuer.setValue(registration.getEntityId());
		logoutResponse.setIssuer(issuer);
		StatusCode code = this.statusCodeBuilder.buildObject();
		code.setValue(StatusCode.SUCCESS);
		Status status = this.statusBuilder.buildObject();
		status.setStatusCode(code);
		logoutResponse.setStatus(status);
		logoutResponse.setInResponseTo(logoutRequest.getID());
		if (logoutResponse.getID() == null) {
			logoutResponse.setID("LR" + UUID.randomUUID());
		}
		logoutResponseConsumer.accept(registration, logoutResponse);
		Saml2LogoutResponse.Builder result = Saml2LogoutResponse.withRelyingPartyRegistration(registration);
		if (registration.getAssertingPartyDetails().getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
			String xml = serialize(OpenSamlSigningUtils.sign(logoutResponse, registration));
			String samlResponse = Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8));
			result.samlResponse(samlResponse);
			if (request.getParameter(Saml2ParameterNames.RELAY_STATE) != null) {
				result.relayState(request.getParameter(Saml2ParameterNames.RELAY_STATE));
			}
			return result.build();
		}
		else {
			String xml = serialize(logoutResponse);
			String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
			result.samlResponse(deflatedAndEncoded);
			QueryParametersPartial partial = OpenSamlSigningUtils.sign(registration)
					.param(Saml2ParameterNames.SAML_RESPONSE, deflatedAndEncoded);
			if (request.getParameter(Saml2ParameterNames.RELAY_STATE) != null) {
				partial.param(Saml2ParameterNames.RELAY_STATE, request.getParameter(Saml2ParameterNames.RELAY_STATE));
			}
			return result.parameters((params) -> params.putAll(partial.parameters())).build();
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

	private String extractSamlRequest(HttpServletRequest request) {
		String serialized = request.getParameter(Saml2ParameterNames.SAML_REQUEST);
		byte[] b = Saml2Utils.samlDecode(serialized);
		if (Saml2MessageBindingUtils.isHttpRedirectBinding(request)) {
			return Saml2Utils.samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private LogoutRequest parse(String request) throws Saml2Exception {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(request.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutRequest) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutRequest", ex);
		}
	}

	private String serialize(LogoutResponse logoutResponse) {
		try {
			Element element = this.marshaller.marshall(logoutResponse);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

}
