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
		return Saml2LogoutValidatorResult.withErrors()
			.errors(verifySignature(response, logoutResponse, registration))
			.errors(validateRequest(logoutResponse, registration))
			.errors(validateLogoutRequest(logoutResponse, request.getId()))
			.build();
	}

	private Consumer<Collection<Saml2Error>> verifySignature(Saml2LogoutResponse response,
			LogoutResponse logoutResponse, RelyingPartyRegistration registration) {
		return (errors) -> {
			AssertingPartyMetadata details = registration.getAssertingPartyMetadata();
			Collection<Saml2X509Credential> credentials = details.getVerificationX509Credentials();
			VerificationConfigurer verify = this.saml.withVerificationKeys(credentials)
				.entityId(details.getEntityId())
				.entityId(details.getEntityId());
			if (logoutResponse.isSigned()) {
				errors.addAll(verify.verify(logoutResponse));
			}
			else {
				RedirectParameters params = new RedirectParameters(response.getParameters(),
						response.getParametersQuery(), logoutResponse);
				errors.addAll(verify.verify(params));
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
			if (!issuer.equals(registration.getAssertingPartyMetadata().getEntityId())) {
				errors
					.add(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
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
