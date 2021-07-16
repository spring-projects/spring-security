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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlVerificationUtils.VerifierPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * A {@link Saml2LogoutRequestAuthenticator} that authenticates a SAML 2.0 Logout Requests
 * received from a SAML 2.0 Asserting Party using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class OpenSamlLogoutRequestAuthenticator implements Saml2LogoutRequestAuthenticator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ParserPool parserPool;

	private final LogoutRequestUnmarshaller unmarshaller;

	/**
	 * Constructs a {@link OpenSamlLogoutRequestAuthenticator}
	 */
	public OpenSamlLogoutRequestAuthenticator() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutRequestUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutAuthenticatorResult authenticate(Saml2LogoutRequestAuthenticatorParameters parameters) {
		Saml2LogoutRequest request = parameters.getLogoutRequest();
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		Authentication authentication = parameters.getAuthentication();
		byte[] b = Saml2Utils.samlDecode(request.getSamlRequest());
		LogoutRequest logoutRequest = parse(inflateIfRequired(request, b));
		Saml2LogoutAuthenticatorResult result = verifySignature(request, logoutRequest, registration);
		return result.concat(validateRequest(logoutRequest, registration, authentication));
	}

	private String inflateIfRequired(Saml2LogoutRequest request, byte[] b) {
		if (request.getBinding() == Saml2MessageBinding.REDIRECT) {
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

	private Saml2LogoutAuthenticatorResult verifySignature(Saml2LogoutRequest request, LogoutRequest logoutRequest,
			RelyingPartyRegistration registration) {
		VerifierPartial partial = OpenSamlVerificationUtils.verifySignature(logoutRequest, registration);
		if (logoutRequest.isSigned()) {
			return Saml2LogoutAuthenticatorResult.failure(partial.post(logoutRequest.getSignature()));
		}
		return Saml2LogoutAuthenticatorResult.failure(partial.redirect(request));
	}

	private Saml2LogoutAuthenticatorResult validateRequest(LogoutRequest request, RelyingPartyRegistration registration,
			Authentication authentication) {
		Saml2LogoutAuthenticatorResult result = Saml2LogoutAuthenticatorResult.success();
		return result.concat(validateIssuer(request, registration)).concat(validateDestination(request, registration))
				.concat(validateName(request, authentication));
	}

	private Saml2LogoutAuthenticatorResult validateIssuer(LogoutRequest request,
			RelyingPartyRegistration registration) {
		if (request.getIssuer() == null) {
			return Saml2LogoutAuthenticatorResult
					.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
		}
		String issuer = request.getIssuer().getValue();
		if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
			return Saml2LogoutAuthenticatorResult.failure(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Saml2LogoutAuthenticatorResult.success();
	}

	private Saml2LogoutAuthenticatorResult validateDestination(LogoutRequest request,
			RelyingPartyRegistration registration) {
		if (request.getDestination() == null) {
			return Saml2LogoutAuthenticatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to find destination in LogoutResponse"));
		}
		String destination = request.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceLocation())) {
			return Saml2LogoutAuthenticatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to match destination to configured destination"));
		}
		return Saml2LogoutAuthenticatorResult.success();
	}

	private Saml2LogoutAuthenticatorResult validateName(LogoutRequest request, Authentication authentication) {
		if (authentication == null) {
			return Saml2LogoutAuthenticatorResult.success();
		}
		NameID nameId = request.getNameID();
		if (nameId == null) {
			return Saml2LogoutAuthenticatorResult.failure(
					new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, "Failed to find subject in LogoutRequest"));
		}
		String name = nameId.getValue();
		if (!name.equals(authentication.getName())) {
			return Saml2LogoutAuthenticatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST,
					"Failed to match subject in LogoutRequest with currently logged in user"));
		}
		return Saml2LogoutAuthenticatorResult.success();
	}

}
