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
import java.util.Collection;
import java.util.function.Consumer;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlVerificationUtils.VerifierPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * A {@link Saml2LogoutResponseValidator} that authenticates a SAML 2.0 Logout Responses
 * received from a SAML 2.0 Asserting Party using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class OpenSamlLogoutResponseValidator implements Saml2LogoutResponseValidator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ParserPool parserPool;

	private final LogoutResponseUnmarshaller unmarshaller;

	/**
	 * Constructs a {@link OpenSamlLogoutRequestValidator}
	 */
	public OpenSamlLogoutResponseValidator() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutResponseUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters) {
		Saml2LogoutResponse response = parameters.getLogoutResponse();
		Saml2LogoutRequest request = parameters.getLogoutRequest();
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		byte[] b = Saml2Utils.samlDecode(response.getSamlResponse());
		LogoutResponse logoutResponse = parse(inflateIfRequired(response, b));
		return Saml2LogoutValidatorResult.withErrors().errors(verifySignature(response, logoutResponse, registration))
				.errors(validateRequest(logoutResponse, registration))
				.errors(validateLogoutRequest(logoutResponse, request.getId())).build();
	}

	private String inflateIfRequired(Saml2LogoutResponse response, byte[] b) {
		if (response.getBinding() == Saml2MessageBinding.REDIRECT) {
			return Saml2Utils.samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private LogoutResponse parse(String response) throws Saml2Exception {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutResponse", ex);
		}
	}

	private Consumer<Collection<Saml2Error>> verifySignature(Saml2LogoutResponse response,
			LogoutResponse logoutResponse, RelyingPartyRegistration registration) {
		return (errors) -> {
			VerifierPartial partial = OpenSamlVerificationUtils.verifySignature(logoutResponse, registration);
			if (logoutResponse.isSigned()) {
				errors.addAll(partial.post(logoutResponse.getSignature()));
			}
			else {
				errors.addAll(partial.redirect(response));
			}
		};
	}

	private Consumer<Collection<Saml2Error>> validateRequest(LogoutResponse response,
			RelyingPartyRegistration registration) {
		return (errors) -> {
			validateIssuer(response, registration).accept(errors);
			validateDestination(response, registration).accept(errors);
			validateStatus(response).accept(errors);
		};
	}

	private Consumer<Collection<Saml2Error>> validateIssuer(LogoutResponse response,
			RelyingPartyRegistration registration) {
		return (errors) -> {
			if (response.getIssuer() == null) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
				return;
			}
			String issuer = response.getIssuer().getValue();
			if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
				errors.add(
						new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
			}
		};
	}

	private Consumer<Collection<Saml2Error>> validateDestination(LogoutResponse response,
			RelyingPartyRegistration registration) {
		return (errors) -> {
			if (response.getDestination() == null) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
						"Failed to find destination in LogoutResponse"));
				return;
			}
			String destination = response.getDestination();
			if (!destination.equals(registration.getSingleLogoutServiceResponseLocation())) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
						"Failed to match destination to configured destination"));
			}
		};
	}

	private Consumer<Collection<Saml2Error>> validateStatus(LogoutResponse response) {
		return (errors) -> {
			if (response.getStatus() == null) {
				return;
			}
			if (response.getStatus().getStatusCode() == null) {
				return;
			}
			if (StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
				return;
			}
			if (StatusCode.PARTIAL_LOGOUT.equals(response.getStatus().getStatusCode().getValue())) {
				return;
			}
			errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response indicated logout failed"));
		};
	}

	private Consumer<Collection<Saml2Error>> validateLogoutRequest(LogoutResponse response, String id) {
		return (errors) -> {
			if (response.getInResponseTo() == null) {
				return;
			}
			if (response.getInResponseTo().equals(id)) {
				return;
			}
			errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
					"LogoutResponse InResponseTo doesn't match ID of associated LogoutRequest"));
		};
	}

}
