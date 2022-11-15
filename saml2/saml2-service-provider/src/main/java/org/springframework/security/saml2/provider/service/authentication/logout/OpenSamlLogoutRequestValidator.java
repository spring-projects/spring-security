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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.function.Consumer;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.EncryptedID;
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
 * A {@link Saml2LogoutRequestValidator} that authenticates a SAML 2.0 Logout Requests
 * received from a SAML 2.0 Asserting Party using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class OpenSamlLogoutRequestValidator implements Saml2LogoutRequestValidator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ParserPool parserPool;

	private final LogoutRequestUnmarshaller unmarshaller;

	/**
	 * Constructs a {@link OpenSamlLogoutRequestValidator}
	 */
	public OpenSamlLogoutRequestValidator() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutRequestUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutValidatorResult validate(Saml2LogoutRequestValidatorParameters parameters) {
		Saml2LogoutRequest request = parameters.getLogoutRequest();
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		Authentication authentication = parameters.getAuthentication();
		byte[] b = Saml2Utils.samlDecode(request.getSamlRequest());
		LogoutRequest logoutRequest = parse(inflateIfRequired(request, b));
		return Saml2LogoutValidatorResult.withErrors().errors(verifySignature(request, logoutRequest, registration))
				.errors(validateRequest(logoutRequest, registration, authentication)).build();
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

	private Consumer<Collection<Saml2Error>> verifySignature(Saml2LogoutRequest request, LogoutRequest logoutRequest,
			RelyingPartyRegistration registration) {
		return (errors) -> {
			VerifierPartial partial = OpenSamlVerificationUtils.verifySignature(logoutRequest, registration);
			if (logoutRequest.isSigned()) {
				errors.addAll(partial.post(logoutRequest.getSignature()));
			}
			else {
				errors.addAll(partial.redirect(request));
			}
		};
	}

	private Consumer<Collection<Saml2Error>> validateRequest(LogoutRequest request,
			RelyingPartyRegistration registration, Authentication authentication) {
		return (errors) -> {
			validateIssuer(request, registration).accept(errors);
			validateDestination(request, registration).accept(errors);
			validateSubject(request, registration, authentication).accept(errors);
		};
	}

	private Consumer<Collection<Saml2Error>> validateIssuer(LogoutRequest request,
			RelyingPartyRegistration registration) {
		return (errors) -> {
			if (request.getIssuer() == null) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutRequest"));
				return;
			}
			String issuer = request.getIssuer().getValue();
			if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
				errors.add(
						new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
			}
		};
	}

	private Consumer<Collection<Saml2Error>> validateDestination(LogoutRequest request,
			RelyingPartyRegistration registration) {
		return (errors) -> {
			if (request.getDestination() == null) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
						"Failed to find destination in LogoutRequest"));
				return;
			}
			String destination = request.getDestination();
			if (!destination.equals(registration.getSingleLogoutServiceLocation())) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
						"Failed to match destination to configured destination"));
			}
		};
	}

	private Consumer<Collection<Saml2Error>> validateSubject(LogoutRequest request,
			RelyingPartyRegistration registration, Authentication authentication) {
		return (errors) -> {
			if (authentication == null) {
				return;
			}
			NameID nameId = getNameId(request, registration);
			if (nameId == null) {
				errors.add(
						new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, "Failed to find subject in LogoutRequest"));
				return;
			}

			validateNameId(nameId, authentication, errors);
		};
	}

	private NameID getNameId(LogoutRequest request, RelyingPartyRegistration registration) {
		NameID nameId = request.getNameID();
		if (nameId != null) {
			return nameId;
		}
		EncryptedID encryptedId = request.getEncryptedID();
		if (encryptedId == null) {
			return null;
		}
		return decryptNameId(encryptedId, registration);
	}

	private void validateNameId(NameID nameId, Authentication authentication, Collection<Saml2Error> errors) {
		String name = nameId.getValue();
		if (!name.equals(authentication.getName())) {
			errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST,
					"Failed to match subject in LogoutRequest with currently logged in user"));
		}
	}

	private NameID decryptNameId(EncryptedID encryptedId, RelyingPartyRegistration registration) {
		final SAMLObject decryptedId = LogoutRequestEncryptedIdUtils.decryptEncryptedId(encryptedId, registration);
		if (decryptedId instanceof NameID) {
			return ((NameID) decryptedId);
		}
		return null;
	}

}
