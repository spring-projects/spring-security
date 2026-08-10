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

import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;

import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlOperations.VerificationConfigurer;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlOperations.VerificationConfigurer.RedirectParameters;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;

class BaseOpenSamlLogoutResponseValidator implements Saml2LogoutResponseValidator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final OpenSamlOperations saml;

	BaseOpenSamlLogoutResponseValidator(OpenSamlOperations saml) {
		this.saml = saml;
	}

	@Override
	public Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters) {
		Saml2LogoutResponse response = parameters.getLogoutResponse();
		Saml2LogoutRequest request = parameters.getLogoutRequest();
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		LogoutResponse logoutResponse = this.saml.deserialize(Saml2Utils.withEncoded(response.getSamlResponse())
			.inflate(response.getBinding() == Saml2MessageBinding.REDIRECT)
			.decode());
		Collection<Saml2Error> errors = verifySignature(response, logoutResponse, registration);
		if (!errors.isEmpty()) {
			return Saml2LogoutValidatorResult.withErrors(errors.toArray(Saml2Error[]::new)).build();
		}
		errors = validateRequest(logoutResponse, registration, request.getId());
		return errors.isEmpty() ? Saml2LogoutValidatorResult.success()
				: Saml2LogoutValidatorResult.withErrors(errors.toArray(Saml2Error[]::new)).build();
	}

	private Collection<Saml2Error> verifySignature(Saml2LogoutResponse response, LogoutResponse logoutResponse,
			RelyingPartyRegistration registration) {
		AssertingPartyMetadata details = registration.getAssertingPartyMetadata();
		Collection<Saml2X509Credential> credentials = details.getVerificationX509Credentials();
		VerificationConfigurer verify = this.saml.withVerificationKeys(credentials).entityId(details.getEntityId());
		if (logoutResponse.isSigned()) {
			return verify.verify(logoutResponse);
		}
		String parametersQuery = response.getParametersQuery();
		Assert.notNull(parametersQuery, "parametersQuery cannot be null for redirect binding");
		RedirectParameters params = new RedirectParameters(response.getParameters(), parametersQuery, logoutResponse);
		return verify.verify(params);
	}

	private Collection<Saml2Error> validateRequest(LogoutResponse response, RelyingPartyRegistration registration,
			@Nullable String logoutRequestId) {
		Collection<Saml2Error> errors = new ArrayList<>();
		errors.addAll(validateIssuer(response, registration));
		errors.addAll(validateDestination(response, registration));
		errors.addAll(validateStatus(response));
		errors.addAll(validateLogoutRequest(response, logoutRequestId));
		return errors;
	}

	private Collection<Saml2Error> validateIssuer(LogoutResponse response, RelyingPartyRegistration registration) {
		if (response.getIssuer() == null) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
		}
		String issuer = response.getIssuer().getValue();
		if (!registration.getAssertingPartyMetadata().getEntityId().equals(issuer)) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Collections.emptyList();
	}

	private Collection<Saml2Error> validateDestination(LogoutResponse response, RelyingPartyRegistration registration) {
		if (response.getDestination() == null) {
			return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to find destination in LogoutResponse"));
		}
		String destination = response.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceResponseLocation())) {
			return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to match destination to configured destination"));
		}
		return Collections.emptyList();
	}

	private Collection<Saml2Error> validateStatus(LogoutResponse response) {
		if (response.getStatus() == null) {
			return Collections.emptyList();
		}
		if (response.getStatus().getStatusCode() == null) {
			return Collections.emptyList();
		}
		if (StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
			return Collections.emptyList();
		}
		if (StatusCode.PARTIAL_LOGOUT.equals(response.getStatus().getStatusCode().getValue())) {
			return Collections.emptyList();
		}
		return Collections
			.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response indicated logout failed"));
	}

	private Collection<Saml2Error> validateLogoutRequest(LogoutResponse response, @Nullable String id) {
		if (response.getInResponseTo() == null) {
			return Collections.emptyList();
		}
		if (response.getInResponseTo().equals(id)) {
			return Collections.emptyList();
		}
		return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
				"LogoutResponse InResponseTo doesn't match ID of associated LogoutRequest"));
	}

}
