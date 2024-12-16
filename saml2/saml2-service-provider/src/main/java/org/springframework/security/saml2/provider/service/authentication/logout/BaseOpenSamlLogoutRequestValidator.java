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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.util.Collection;
import java.util.function.Consumer;

import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlOperations.VerificationConfigurer;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlOperations.VerificationConfigurer.RedirectParameters;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

class BaseOpenSamlLogoutRequestValidator implements Saml2LogoutRequestValidator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final OpenSamlOperations saml;

	BaseOpenSamlLogoutRequestValidator(OpenSamlOperations saml) {
		this.saml = saml;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutValidatorResult validate(Saml2LogoutRequestValidatorParameters parameters) {
		Saml2LogoutRequest request = parameters.getLogoutRequest();
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		Authentication authentication = parameters.getAuthentication();
		LogoutRequest logoutRequest = this.saml.deserialize(Saml2Utils.withEncoded(request.getSamlRequest())
			.inflate(request.getBinding() == Saml2MessageBinding.REDIRECT)
			.decode());
		return Saml2LogoutValidatorResult.withErrors()
			.errors(verifySignature(request, logoutRequest, registration))
			.errors(validateRequest(logoutRequest, registration, authentication))
			.build();
	}

	private Consumer<Collection<Saml2Error>> verifySignature(Saml2LogoutRequest request, LogoutRequest logoutRequest,
			RelyingPartyRegistration registration) {
		AssertingPartyMetadata details = registration.getAssertingPartyMetadata();
		Collection<Saml2X509Credential> credentials = details.getVerificationX509Credentials();
		VerificationConfigurer verify = this.saml.withVerificationKeys(credentials).entityId(details.getEntityId());
		return (errors) -> {
			if (logoutRequest.isSigned()) {
				errors.addAll(verify.verify(logoutRequest));
			}
			else {
				RedirectParameters params = new RedirectParameters(request.getParameters(),
						request.getParametersQuery(), logoutRequest);
				errors.addAll(verify.verify(params));
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
			if (!issuer.equals(registration.getAssertingPartyMetadata().getEntityId())) {
				errors
					.add(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
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
				errors
					.add(new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, "Failed to find subject in LogoutRequest"));
				return;
			}

			validateNameId(nameId, authentication, errors);
		};
	}

	private NameID getNameId(LogoutRequest request, RelyingPartyRegistration registration) {
		this.saml.withDecryptionKeys(registration.getDecryptionX509Credentials()).decrypt(request);
		return request.getNameID();
	}

	private void validateNameId(NameID nameId, Authentication authentication, Collection<Saml2Error> errors) {
		String name = nameId.getValue();
		if (!name.equals(authentication.getName())) {
			errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST,
					"Failed to match subject in LogoutRequest with currently logged in user"));
		}
	}

}
