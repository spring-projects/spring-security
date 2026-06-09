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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

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

/**
 * A {@link Saml2LogoutRequestValidator} that authenticates a SAML 2.0 Logout Requests
 * received from a SAML 2.0 Asserting Party using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.6
 * @deprecated Please use the version-specific {@link Saml2LogoutRequestValidator} such as
 * {@code OpenSaml4LogoutRequestValidator}
 */
@Deprecated
public final class OpenSamlLogoutRequestValidator implements Saml2LogoutRequestValidator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final OpenSamlOperations saml = new OpenSaml4Template();

	/**
	 * Constructs a {@link OpenSamlLogoutRequestValidator}
	 */
	public OpenSamlLogoutRequestValidator() {
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
		Collection<Saml2Error> errors = verifySignature(request, logoutRequest, registration);
		if (!errors.isEmpty()) {
			return Saml2LogoutValidatorResult.withErrors(errors.toArray(Saml2Error[]::new)).build();
		}
		errors = validateRequest(logoutRequest, registration, authentication);
		return errors.isEmpty() ? Saml2LogoutValidatorResult.success()
				: Saml2LogoutValidatorResult.withErrors(errors.toArray(Saml2Error[]::new)).build();
	}

	private Collection<Saml2Error> verifySignature(Saml2LogoutRequest request, LogoutRequest logoutRequest,
			RelyingPartyRegistration registration) {
		AssertingPartyMetadata details = registration.getAssertingPartyMetadata();
		Collection<Saml2X509Credential> credentials = details.getVerificationX509Credentials();
		VerificationConfigurer verify = this.saml.withVerificationKeys(credentials).entityId(details.getEntityId());
		if (logoutRequest.isSigned()) {
			return verify.verify(logoutRequest);
		}
		RedirectParameters params = new RedirectParameters(request.getParameters(), request.getParametersQuery(),
				logoutRequest);
		return verify.verify(params);
	}

	private Collection<Saml2Error> validateRequest(LogoutRequest request, RelyingPartyRegistration registration,
			Authentication authentication) {
		Collection<Saml2Error> errors = new ArrayList<>();
		errors.addAll(validateIssuer(request, registration));
		errors.addAll(validateDestination(request, registration));
		errors.addAll(validateSubject(request, registration, authentication));
		return errors;
	}

	private Collection<Saml2Error> validateIssuer(LogoutRequest request, RelyingPartyRegistration registration) {
		if (request.getIssuer() == null) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutRequest"));
		}
		String issuer = request.getIssuer().getValue();
		if (!issuer.equals(registration.getAssertingPartyMetadata().getEntityId())) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Collections.emptyList();
	}

	private Collection<Saml2Error> validateDestination(LogoutRequest request, RelyingPartyRegistration registration) {
		if (request.getDestination() == null) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION, "Failed to find destination in LogoutRequest"));
		}
		String destination = request.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceLocation())) {
			return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to match destination to configured destination"));
		}
		return Collections.emptyList();
	}

	private Collection<Saml2Error> validateSubject(LogoutRequest request, RelyingPartyRegistration registration,
			Authentication authentication) {
		if (authentication == null) {
			return Collections.emptyList();
		}
		NameID nameId = getNameId(request, registration);
		if (nameId == null) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, "Failed to find subject in LogoutRequest"));
		}
		return validateNameId(nameId, authentication);
	}

	private NameID getNameId(LogoutRequest request, RelyingPartyRegistration registration) {
		this.saml.withDecryptionKeys(registration.getDecryptionX509Credentials()).decrypt(request);
		return request.getNameID();
	}

	private Collection<Saml2Error> validateNameId(NameID nameId, Authentication authentication) {
		String name = nameId.getValue();
		if (!name.equals(authentication.getName())) {
			return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST,
					"Failed to match subject in LogoutRequest with currently logged in user"));
		}
		return Collections.emptyList();
	}

}
