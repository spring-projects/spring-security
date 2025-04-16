/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.ott;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultGenerateOneTimeTokenRequestResolver}
 *
 * @author Max Batischev
 */
public class DefaultGenerateOneTimeTokenRequestResolverTests {

	private final DefaultGenerateOneTimeTokenRequestResolver requestResolver = new DefaultGenerateOneTimeTokenRequestResolver();

	@Test
	void resolveWhenUsernameParameterIsPresentThenResolvesGenerateRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("username", "test");

		GenerateOneTimeTokenRequest generateRequest = this.requestResolver.resolve(request);

		assertThat(generateRequest).isNotNull();
		assertThat(generateRequest.getUsername()).isEqualTo("test");
		assertThat(generateRequest.getExpiresIn()).isEqualTo(Duration.ofSeconds(300));
	}

	@Test
	void resolveWhenUsernameParameterIsNotPresentThenNull() {
		GenerateOneTimeTokenRequest generateRequest = this.requestResolver.resolve(new MockHttpServletRequest());

		assertThat(generateRequest).isNull();
	}

	@Test
	void resolveWhenExpiresInSetThenResolvesGenerateRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("username", "test");
		this.requestResolver.setExpiresIn(Duration.ofSeconds(600));

		GenerateOneTimeTokenRequest generateRequest = this.requestResolver.resolve(request);

		assertThat(generateRequest.getExpiresIn()).isEqualTo(Duration.ofSeconds(600));
	}

	@Test
	void resolveWhenTokenValueFactorySetThenResolvesGenerateRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("username", "test");
		this.requestResolver.setTokenValueFactory(() -> "tokenValue");

		GenerateOneTimeTokenRequest generateRequest = this.requestResolver.resolve(request);

		assertThat(generateRequest.getTokenValue()).isEqualTo("tokenValue");
	}

}
