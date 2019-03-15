/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;

@RunWith(MockitoJUnitRunner.class)
public class SecurityMockMvcRequestPostProcessorsCertificateTests {
	@Mock
	private X509Certificate certificate;

	private MockHttpServletRequest request;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
	}

	@Test
	public void x509SingleCertificate() {
		MockHttpServletRequest postProcessedRequest = x509(certificate)
				.postProcessRequest(request);

		X509Certificate[] certificates = (X509Certificate[]) postProcessedRequest
				.getAttribute("javax.servlet.request.X509Certificate");

		assertThat(certificates).containsOnly(certificate);
	}

	@Test
	public void x509ResourceName() throws Exception {
		MockHttpServletRequest postProcessedRequest = x509("rod.cer").postProcessRequest(
				request);

		X509Certificate[] certificates = (X509Certificate[]) postProcessedRequest
				.getAttribute("javax.servlet.request.X509Certificate");

		assertThat(certificates).hasSize(1);
		assertThat(certificates[0].getSubjectDN().getName()).isEqualTo(
				"CN=rod, OU=Spring Security, O=Spring Framework");
	}
}
