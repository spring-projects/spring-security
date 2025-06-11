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

package org.springframework.security.docs.servlet.authentication.servletx509config;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.jetbrains.annotations.NotNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.authentication.preauth.x509.X509TestUtils;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests {@link CustomX509Configuration}.
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class X509ConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mockMvc;

	@Test
	void x509WhenDefaultX509Configuration() throws Exception {
		this.spring.register(DefaultX509Configuration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/").with(x509("rod.cer")))
			.andExpect(status().isOk())
			.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	@Test
	void x509WhenDefaultX509ConfigurationXml() throws Exception {
		this.spring.testConfigLocations("DefaultX509Configuration.xml").autowire();
		// @formatter:off
		this.mockMvc.perform(get("/").with(x509("rod.cer")))
			.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	@Test
	void x509WhenCustomX509Configuration() throws Exception {
		this.spring.register(CustomX509Configuration.class, Http200Controller.class).autowire();
		X509Certificate certificate = X509TestUtils.buildTestCertificate();
		// @formatter:off
		this.mockMvc.perform(get("/").with(x509(certificate)))
				.andExpect(status().isOk())
				.andExpect(authenticated().withUsername("luke@monkeymachine"));
		// @formatter:on
	}

	@RestController
	static class Http200Controller {
		@GetMapping("/**")
		String ok() {
			return "ok";
		}
	}
}
