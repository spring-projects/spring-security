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

package org.springframework.security.docs.reactive.authentication.reactivex509;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.authentication.preauth.x509.X509TestUtils;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.test.web.reactive.server.UserWebTestClientConfigurer.x509;

/**
 * Tests {@link CustomX509Configuration}.
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class X509ConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	WebTestClient client;

	@Autowired
	void setSpringSecurityFilterChain(WebFilter springSecurityFilterChain) {
		this.client = WebTestClient.bindToController(WebTestClientBuilder.Http200RestController.class)
			.webFilter(springSecurityFilterChain)
			.apply(springSecurity())
			.configureClient()
			.build();
	}

	@Test
	void x509WhenDefaultX509Configuration() throws Exception {
		this.spring.register(DefaultX509Configuration.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		// @formatter:off
		this.client
			.mutateWith(x509(certificate))
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	void x509WhenCustomX509Configuration() throws Exception {
		this.spring.register(CustomX509Configuration.class).autowire();
		X509Certificate certificate = X509TestUtils.buildTestCertificate();
		// @formatter:off
		this.client
				.mutateWith(x509(certificate))
				.get()
				.uri("/")
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	private <T extends Certificate> T loadCert(String location) {
		try (InputStream is = new ClassPathResource(location).getInputStream()) {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (T) certFactory.generateCertificate(is);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}
}
