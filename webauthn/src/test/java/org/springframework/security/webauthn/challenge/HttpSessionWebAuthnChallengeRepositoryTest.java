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

package org.springframework.security.webauthn.challenge;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.http.HttpSession;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for {@link HttpSessionWebAuthnChallengeRepository}
 */
public class HttpSessionWebAuthnChallengeRepositoryTest {

	private HttpSessionWebAuthnChallengeRepository target = new HttpSessionWebAuthnChallengeRepository();

	@Test
	public void generateChallenge_test() {
		WebAuthnChallenge challenge = target.generateChallenge();
		assertThat(challenge).isNotNull();
		assertThat(challenge.getValue()).hasSize(16);
	}

	@Test
	public void saveChallenge_test() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		String attrName = ".test-challenge";

		target.setSessionAttributeName(attrName);
		WebAuthnChallenge challenge = target.generateChallenge();
		target.saveChallenge(challenge, request);

		HttpSession session = request.getSession();
		assertThat((WebAuthnChallenge) session.getAttribute(attrName)).isEqualTo(challenge);
	}

	@Test
	public void saveChallenge_test_with_null() {
		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest prevRequest = new MockHttpServletRequest();
		prevRequest.setSession(session);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(session);

		WebAuthnChallenge challenge = target.generateChallenge();
		target.saveChallenge(challenge, prevRequest);
		target.saveChallenge(null, request);
		WebAuthnChallenge loadedChallenge = target.loadChallenge(request);

		assertThat(loadedChallenge).isNull();
	}

	@Test
	public void saveChallenge_test_without_prev_request() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		target.saveChallenge(null, request);
		WebAuthnChallenge loadedChallenge = target.loadChallenge(request);

		assertThat(loadedChallenge).isNull();
	}


	@Test
	public void loadChallenge_test() {
		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest prevRequest = new MockHttpServletRequest();
		prevRequest.setSession(session);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(session);
		String attrName = ".test-challenge";

		target.setSessionAttributeName(attrName);
		WebAuthnChallenge challenge = target.generateChallenge();
		target.saveChallenge(challenge, prevRequest);
		WebAuthnChallenge loadedChallenge = target.loadChallenge(request);

		assertThat(loadedChallenge).isEqualTo(challenge);
	}

	@Test
	public void loadChallenge_test_without_previous_request() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		WebAuthnChallenge loadedChallenge = target.loadChallenge(request);

		assertThat(loadedChallenge).isNull();
	}

	@Test
	public void loadOrGenerateChallenge_test_without_previous_request() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		WebAuthnChallenge loadedChallenge = target.loadOrGenerateChallenge(request);

		assertThat(loadedChallenge).isNotNull();
	}
}
