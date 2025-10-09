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

package org.springframework.security.oauth2.server.authorization.settings;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ClientSettings}.
 *
 * @author Joe Grandja
 */
public class ClientSettingsTests {

	@Test
	public void buildWhenDefaultThenDefaultsAreSet() {
		ClientSettings clientSettings = ClientSettings.builder().build();
		assertThat(clientSettings.getSettings()).hasSize(2);
		assertThat(clientSettings.isRequireProofKey()).isTrue();
		assertThat(clientSettings.isRequireAuthorizationConsent()).isFalse();
	}

	@Test
	public void requireProofKeyWhenTrueThenSet() {
		ClientSettings clientSettings = ClientSettings.builder().requireProofKey(true).build();
		assertThat(clientSettings.isRequireProofKey()).isTrue();
	}

	@Test
	public void requireAuthorizationConsentWhenTrueThenSet() {
		ClientSettings clientSettings = ClientSettings.builder().requireAuthorizationConsent(true).build();
		assertThat(clientSettings.isRequireAuthorizationConsent()).isTrue();
	}

	@Test
	public void tokenEndpointAuthenticationSigningAlgorithmWhenHS256ThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
			.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
			.build();
		assertThat(clientSettings.getTokenEndpointAuthenticationSigningAlgorithm()).isEqualTo(MacAlgorithm.HS256);
	}

	@Test
	public void jwkSetUrlWhenProvidedThenSet() {
		ClientSettings clientSettings = ClientSettings.builder().jwkSetUrl("https://client.example.com/jwks").build();
		assertThat(clientSettings.getJwkSetUrl()).isEqualTo("https://client.example.com/jwks");
	}

	@Test
	public void x509CertificateSubjectDNWhenProvidedThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
			.x509CertificateSubjectDN("CN=demo-client-sample, OU=Spring Samples, O=Spring, C=US")
			.build();
		assertThat(clientSettings.getX509CertificateSubjectDN())
			.isEqualTo("CN=demo-client-sample, OU=Spring Samples, O=Spring, C=US");
	}

	@Test
	public void settingWhenCustomThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
			.setting("name1", "value1")
			.settings((settings) -> settings.put("name2", "value2"))
			.build();
		assertThat(clientSettings.getSettings()).hasSize(4);
		assertThat(clientSettings.<String>getSetting("name1")).isEqualTo("value1");
		assertThat(clientSettings.<String>getSetting("name2")).isEqualTo("value2");
	}

}
