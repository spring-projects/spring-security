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

package integration.component;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.authenticator.webauthn.PackedAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.webauthn.*;
import org.springframework.security.webauthn.challenge.WebAuthnChallenge;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeImpl;
import org.springframework.security.webauthn.server.WebAuthnOrigin;
import org.springframework.security.webauthn.server.WebAuthnServerProperty;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProvider;

import java.util.Collections;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for WebAuthnRegistrationContextValidator
 */
public class RegistrationValidationTest {

	String rpId = "example.com";
	Challenge challenge = new DefaultChallenge();
	WebAuthnChallenge webAuthnChallenge = new WebAuthnChallengeImpl(challenge.getValue());
	private Origin origin = new Origin("http://localhost");
	private WebAuthnOrigin webAuthnOrigin = new WebAuthnOrigin(origin.toString());
	private WebAuthnAuthenticatorAdaptor webAuthnModelAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(new PackedAuthenticator());
	private ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnModelAuthenticatorAdaptor);
	private WebAuthnServerPropertyProvider webAuthnServerPropertyProvider = mock(WebAuthnServerPropertyProvider.class);
	private WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator = WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();
	private WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator = new WebAuthnAuthenticationContextValidator();
	private WebAuthnDataConverter webAuthnDataConverter = new WebAuthnDataConverter();
	private WebAuthnManager webAuthnManager = new WebAuthn4JWebAuthnManager(webAuthnRegistrationContextValidator, webAuthnAuthenticationContextValidator, webAuthnDataConverter);
	private WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(webAuthnManager, webAuthnServerPropertyProvider);

	@Test
	public void validate_test() {
		WebAuthnServerProperty serverProperty = new WebAuthnServerProperty(webAuthnOrigin, rpId, webAuthnChallenge, null);
		when(webAuthnServerPropertyProvider.provide(any())).thenReturn(serverProperty);


		AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
				new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);

		PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

		PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();

		PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
				new PublicKeyCredentialRpEntity(rpId, "example.com"),
				publicKeyCredentialUserEntity,
				challenge,
				Collections.singletonList(publicKeyCredentialParameters),
				null,
				null,
				authenticatorSelectionCriteria,
				AttestationConveyancePreference.NONE,
				null
		);

		AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);

		String clientDataBase64 = Base64UrlUtil.encodeToString(registrationRequest.getClientDataJSON());
		String attestationObjectBase64 = Base64UrlUtil.encodeToString(registrationRequest.getAttestationObject());
		Set<String> transports = Collections.emptySet();
		String clientExtensionsJSON = null;

		target.validate(new WebAuthnRegistrationRequest(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON));
	}

}
