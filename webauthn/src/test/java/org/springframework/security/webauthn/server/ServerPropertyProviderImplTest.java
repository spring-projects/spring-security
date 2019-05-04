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

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.webauthn.challenge.ChallengeRepository;
import org.springframework.security.webauthn.options.OptionsProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ServerPropertyProviderImplTest {

	private ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
	private OptionsProvider optionsProvider = mock(OptionsProvider.class);
	private ServerPropertyProviderImpl target = new ServerPropertyProviderImpl(optionsProvider, challengeRepository);

	@Test
	public void provide_test() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("https");
		request.setServerName("origin.example.com");
		request.setServerPort(443);
		Challenge mockChallenge = new DefaultChallenge();
		when(challengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
		when(optionsProvider.getEffectiveRpId(request)).thenReturn("rpid.example.com");

		ServerProperty serverProperty = target.provide(request);

		assertThat(serverProperty.getRpId()).isEqualTo("rpid.example.com");
		assertThat(serverProperty.getOrigin()).isEqualTo(new Origin("https://origin.example.com"));
		assertThat(serverProperty.getChallenge()).isEqualTo(mockChallenge);
	}
}
