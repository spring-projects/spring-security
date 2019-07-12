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

package org.springframework.security.webauthn.server;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.webauthn.challenge.WebAuthnChallenge;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeImpl;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class WebAuthnServerPropertyProviderImplTest {

	private WebAuthnChallengeRepository webAuthnChallengeRepository = mock(WebAuthnChallengeRepository.class);
	private EffectiveRpIdProvider effectiveRpIdProvider = mock(EffectiveRpIdProvider.class);
	private WebAuthnServerPropertyProviderImpl target = new WebAuthnServerPropertyProviderImpl(effectiveRpIdProvider, webAuthnChallengeRepository);

	@Test
	public void provide_test() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("https");
		request.setServerName("origin.example.com");
		request.setServerPort(443);
		WebAuthnChallenge mockChallenge = new WebAuthnChallengeImpl();
		when(webAuthnChallengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
		when(effectiveRpIdProvider.getEffectiveRpId(request)).thenReturn("rpid.example.com");

		WebAuthnServerProperty serverProperty = target.provide(request);

		assertThat(serverProperty.getRpId()).isEqualTo("rpid.example.com");
		assertThat(serverProperty.getOrigin()).isEqualTo(new WebAuthnOrigin("https://origin.example.com"));
		assertThat(serverProperty.getChallenge()).isEqualTo(mockChallenge);
	}
}
