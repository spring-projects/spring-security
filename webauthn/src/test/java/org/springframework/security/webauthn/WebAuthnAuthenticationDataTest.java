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

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.test.TestDataUtil;
import org.junit.Test;
import org.springframework.security.webauthn.challenge.WebAuthnChallenge;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeImpl;
import org.springframework.security.webauthn.server.WebAuthnOrigin;
import org.springframework.security.webauthn.server.WebAuthnServerProperty;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationDataTest {

	private CborConverter cborConverter = new CborConverter();

	@Test
	public void getter_test() {
		WebAuthnChallenge challenge = new WebAuthnChallengeImpl();
		byte[] clientDataJSON = TestDataUtil.createClientDataJSON(ClientDataType.GET);
		byte[] authenticatorData = new AuthenticatorDataConverter(cborConverter).convert(TestDataUtil.createAuthenticatorData());
		WebAuthnServerProperty serverProperty = new WebAuthnServerProperty(
				new WebAuthnOrigin("https://example.com"),
				"example.com",
				challenge,
				new byte[]{0x43, 0x21}
		);
		WebAuthnAuthenticationData authenticationData = new WebAuthnAuthenticationData(
				new byte[]{0x01, 0x23},
				clientDataJSON,
				authenticatorData,
				new byte[]{0x45, 0x56},
				"",
				serverProperty,
				true,
				true,
				Collections.singletonList("uvi")
		);
		assertThat(authenticationData.getCredentialId()).isEqualTo(new byte[]{0x01, 0x23});
		assertThat(authenticationData.getClientDataJSON()).isEqualTo(clientDataJSON);
		assertThat(authenticationData.getAuthenticatorData()).isEqualTo(authenticatorData);
		assertThat(authenticationData.getSignature()).isEqualTo(new byte[]{0x45, 0x56});
		assertThat(authenticationData.getClientExtensionsJSON()).isEqualTo("");
		assertThat(authenticationData.getServerProperty()).isEqualTo(serverProperty);
		assertThat(authenticationData.isUserVerificationRequired()).isEqualTo(true);
		assertThat(authenticationData.isUserPresenceRequired()).isEqualTo(true);
		assertThat(authenticationData.getExpectedAuthenticationExtensionIds()).isEqualTo(Collections.singletonList("uvi"));
	}

	@Test
	public void equals_hashCode_test() {
		WebAuthnChallenge challenge = new WebAuthnChallengeImpl();
		byte[] clientDataJSON = TestDataUtil.createClientDataJSON(ClientDataType.GET);
		byte[] authenticatorData = new AuthenticatorDataConverter(cborConverter).convert(TestDataUtil.createAuthenticatorData());
		WebAuthnAuthenticationData requestA = new WebAuthnAuthenticationData(
				new byte[]{0x01, 0x23},
				clientDataJSON,
				authenticatorData,
				new byte[]{0x45, 0x56},
				"",
				new WebAuthnServerProperty(
						new WebAuthnOrigin("https://example.com"),
						"example.com",
						challenge,
						new byte[]{0x43, 0x21}
				),
				true,
				Collections.singletonList("uvi")
		);
		WebAuthnAuthenticationData requestB = new WebAuthnAuthenticationData(
				new byte[]{0x01, 0x23},
				clientDataJSON,
				authenticatorData,
				new byte[]{0x45, 0x56},
				"",
				new WebAuthnServerProperty(
						new WebAuthnOrigin("https://example.com"),
						"example.com",
						challenge,
						new byte[]{0x43, 0x21}
				),
				true,
				Collections.singletonList("uvi")
		);

		assertThat(requestA).isEqualTo(requestB);
		assertThat(requestA).hasSameHashCodeAs(requestB);
	}
}
