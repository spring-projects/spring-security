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

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.BiConsumer;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SessionIndexBuilder;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;
import org.springframework.util.Assert;

/**
 * For internal use only. Intended for consolidating common behavior related to minting a
 * SAML 2.0 Logout Request.
 */
final class OpenSamlLogoutRequestResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final Log logger = LogFactory.getLog(getClass());

	private final LogoutRequestMarshaller marshaller;

	private final IssuerBuilder issuerBuilder;

	private final NameIDBuilder nameIdBuilder;

	private final SessionIndexBuilder sessionIndexBuilder;

	private final LogoutRequestBuilder logoutRequestBuilder;

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	/**
	 * Construct a {@link OpenSamlLogoutRequestResolver}
	 */
	OpenSamlLogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
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
	Saml2LogoutRequest resolve(HttpServletRequest request, Authentication authentication) {
		return resolve(request, authentication, (registration, logoutRequest) -> {
		});
	}

	Saml2LogoutRequest resolve(HttpServletRequest request, Authentication authentication,
			BiConsumer<RelyingPartyRegistration, LogoutRequest> logoutRequestConsumer) {
		String registrationId = getRegistrationId(authentication);
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null) {
			return null;
		}
		if (registration.getAssertingPartyDetails().getSingleLogoutServiceLocation() == null) {
			return null;
		}
		LogoutRequest logoutRequest = this.logoutRequestBuilder.buildObject();
		logoutRequest.setDestination(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation());
		Issuer issuer = this.issuerBuilder.buildObject();
		issuer.setValue(registration.getEntityId());
		logoutRequest.setIssuer(issuer);
		NameID nameId = this.nameIdBuilder.buildObject();
		nameId.setValue(authentication.getName());
		logoutRequest.setNameID(nameId);
		if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal) {
			Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
			for (String index : principal.getSessionIndexes()) {
				SessionIndex sessionIndex = this.sessionIndexBuilder.buildObject();
				sessionIndex.setSessionIndex(index);
				logoutRequest.getSessionIndexes().add(sessionIndex);
			}
		}
		logoutRequestConsumer.accept(registration, logoutRequest);
		if (logoutRequest.getID() == null) {
			logoutRequest.setID("LR" + UUID.randomUUID());
		}
		String relayState = UUID.randomUUID().toString();
		Saml2LogoutRequest.Builder result = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.id(logoutRequest.getID());
		if (registration.getAssertingPartyDetails().getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
			String xml = serialize(OpenSamlSigningUtils.sign(logoutRequest, registration));
			String samlRequest = Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8));
			return result.samlRequest(samlRequest).relayState(relayState).build();
		}
		else {
			String xml = serialize(logoutRequest);
			String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
			result.samlRequest(deflatedAndEncoded);
			QueryParametersPartial partial = OpenSamlSigningUtils.sign(registration)
					.param(Saml2ParameterNames.SAML_REQUEST, deflatedAndEncoded)
					.param(Saml2ParameterNames.RELAY_STATE, relayState);
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

	private String serialize(LogoutRequest logoutRequest) {
		try {
			Element element = this.marshaller.marshall(logoutRequest);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

}
