/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.webauthn.exception.*;
import org.springframework.security.webauthn.server.WebAuthnOrigin;
import org.springframework.security.webauthn.server.WebAuthnServerProperty;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class WebAuthn4JWebAuthnManager implements WebAuthnManager {

	// ~ Instance fields
	// ================================================================================================
	private WebAuthnRegistrationContextValidator registrationContextValidator;
	private WebAuthnAuthenticationContextValidator authenticationContextValidator;

	private String rpId;

	private CborConverter cborConverter;

	public WebAuthn4JWebAuthnManager(
			WebAuthnRegistrationContextValidator registrationContextValidator,
			WebAuthnAuthenticationContextValidator authenticationContextValidator,
			WebAuthnDataConverter webAuthnDataConverter) {
		this.registrationContextValidator = registrationContextValidator;
		this.authenticationContextValidator = authenticationContextValidator;
		this.cborConverter = new CborConverter(webAuthnDataConverter.getJsonMapper(), webAuthnDataConverter.getCborMapper());
	}

	public WebAuthn4JWebAuthnManager(
			WebAuthnRegistrationContextValidator registrationContextValidator,
			WebAuthnAuthenticationContextValidator authenticationContextValidator) {
		this(registrationContextValidator, authenticationContextValidator, new WebAuthnDataConverter());
	}

	public WebAuthn4JWebAuthnManager(WebAuthnDataConverter webAuthnDataConverter) {
		this(WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator(),
				new WebAuthnAuthenticationContextValidator(), webAuthnDataConverter);
	}

	public WebAuthn4JWebAuthnManager() {
		this(new WebAuthnDataConverter());
	}


	public void verifyRegistrationData(
			WebAuthnRegistrationData registrationData
	) {

		Assert.notNull(registrationData.getClientDataJSON(), "clientDataJSON must not be null");
		Assert.notNull(registrationData.getAttestationObject(), "attestationObject must not be null");
		if (registrationData.getTransports() != null) {
			registrationData.getTransports().forEach(transport -> Assert.hasText(transport, "each transport must have text"));
		}
		Assert.notNull(registrationData.getServerProperty(), "serverProperty must not be null");

		WebAuthnRegistrationContext registrationContext = createRegistrationContext(registrationData);

		registrationContextValidator.validate(registrationContext);
	}

	@Override
	public void verifyAuthenticationData(WebAuthnAuthenticationData authenticationData, WebAuthnAuthenticator webAuthnAuthenticator) {

		//TODO: null check

		WebAuthnAuthenticationContext authenticationContext = createWebAuthnAuthenticationContext(authenticationData);

		AttestationObject attestationObject = cborConverter.readValue(webAuthnAuthenticator.getAttestationObject(), AttestationObject.class);

		Set<AuthenticatorTransport> transports;
		if (webAuthnAuthenticator.getTransports() == null) {
			transports = Collections.emptySet();
		} else {
			transports = webAuthnAuthenticator.getTransports().stream()
					.map(transport -> AuthenticatorTransport.create(transport.getValue()))
					.collect(Collectors.toSet());
		}

		Authenticator authenticator = new AuthenticatorImpl(
				attestationObject.getAuthenticatorData().getAttestedCredentialData(),
				attestationObject.getAttestationStatement(),
				webAuthnAuthenticator.getCounter(),
				transports
		);

		authenticationContextValidator.validate(authenticationContext, authenticator);

	}

	@Override
	public String getEffectiveRpId(HttpServletRequest request) {
		String effectiveRpId;
		if (this.rpId != null) {
			effectiveRpId = this.rpId;
		} else {
			WebAuthnOrigin origin = WebAuthnOrigin.create(request);
			effectiveRpId = origin.getHost();
		}
		return effectiveRpId;
	}

	public String getRpId() {
		return rpId;
	}

	public void setRpId(String rpId) {
		this.rpId = rpId;
	}

	private WebAuthnRegistrationContext createRegistrationContext(WebAuthnRegistrationData webAuthnRegistrationData) {

		byte[] clientDataBytes = webAuthnRegistrationData.getClientDataJSON();
		byte[] attestationObjectBytes = webAuthnRegistrationData.getAttestationObject();
		Set<String> transports = webAuthnRegistrationData.getTransports();
		String clientExtensionsJSON = webAuthnRegistrationData.getClientExtensionsJSON();
		ServerProperty serverProperty = convertToServerProperty(webAuthnRegistrationData.getServerProperty());

		return new WebAuthnRegistrationContext(
				clientDataBytes,
				attestationObjectBytes,
				transports,
				clientExtensionsJSON,
				serverProperty,
				false,
				false,
				webAuthnRegistrationData.getExpectedRegistrationExtensionIds());
	}

	private WebAuthnAuthenticationContext createWebAuthnAuthenticationContext(WebAuthnAuthenticationData webAuthnAuthenticationData) {

		ServerProperty serverProperty = convertToServerProperty(webAuthnAuthenticationData.getServerProperty());

		return new WebAuthnAuthenticationContext(
				webAuthnAuthenticationData.getCredentialId(),
				webAuthnAuthenticationData.getClientDataJSON(),
				webAuthnAuthenticationData.getAuthenticatorData(),
				webAuthnAuthenticationData.getSignature(),
				webAuthnAuthenticationData.getClientExtensionsJSON(),
				serverProperty,
				webAuthnAuthenticationData.isUserVerificationRequired(),
				webAuthnAuthenticationData.isUserPresenceRequired(),
				webAuthnAuthenticationData.getExpectedAuthenticationExtensionIds()
		);
	}

	private Origin convertToOrigin(WebAuthnOrigin webAuthnOrigin) {
		return new Origin(webAuthnOrigin.getScheme(), webAuthnOrigin.getHost(), webAuthnOrigin.getPort());
	}

	private ServerProperty convertToServerProperty(WebAuthnServerProperty webAuthnServerProperty) {
		return new ServerProperty(
				convertToOrigin(webAuthnServerProperty.getOrigin()),
				webAuthnServerProperty.getRpId(),
				new DefaultChallenge(webAuthnServerProperty.getChallenge().getValue()),
				webAuthnServerProperty.getTokenBindingId());
	}

}
