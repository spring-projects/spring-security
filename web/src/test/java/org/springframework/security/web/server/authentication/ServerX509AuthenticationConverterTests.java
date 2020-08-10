/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509TestUtils;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ServerX509AuthenticationConverterTests {

	@Mock
	private X509PrincipalExtractor principalExtractor;

	@InjectMocks
	private ServerX509AuthenticationConverter converter;

	private X509Certificate certificate;

	private MockServerHttpRequest.BaseBuilder<?> request;

	@Before
	public void setUp() throws Exception {
		request = MockServerHttpRequest.get("/");

		certificate = X509TestUtils.buildTestCertificate();
		when(principalExtractor.extractPrincipal(any())).thenReturn("Luke Taylor");
	}

	@Test
	public void shouldReturnNullForInvalidCertificate() {
		Authentication authentication = converter.convert(MockServerWebExchange.from(request.build())).block();

		assertThat(authentication).isNull();
	}

	@Test
	public void shouldReturnAuthenticationForValidCertificate() {
		request.sslInfo(new MockSslInfo(certificate));

		Authentication authentication = converter.convert(MockServerWebExchange.from(request.build())).block();

		assertThat(authentication.getName()).isEqualTo("Luke Taylor");
		assertThat(authentication.getCredentials()).isEqualTo(certificate);
	}

	class MockSslInfo implements SslInfo {

		private final X509Certificate[] peerCertificates;

		MockSslInfo(X509Certificate... peerCertificates) {
			this.peerCertificates = peerCertificates;
		}

		@Override
		public String getSessionId() {
			return "mock-session-id";
		}

		@Override
		public X509Certificate[] getPeerCertificates() {
			return this.peerCertificates;
		}

	}

}
