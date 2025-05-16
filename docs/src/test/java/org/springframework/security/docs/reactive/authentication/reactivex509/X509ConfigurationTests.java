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

package org.springframework.security.docs.reactive.authentication.reactivex509;

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
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.authentication.preauth.x509.X509TestUtils;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

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

	private static @NotNull WebTestClientConfigurer x509(X509Certificate certificate) {
		return (builder, httpHandlerBuilder, connector) -> {
			builder.apply(new WebTestClientConfigurer() {
				@Override
				public void afterConfigurerAdded(WebTestClient.Builder builder,
						@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
						@Nullable ClientHttpConnector connector) {
					SslInfo sslInfo = new SslInfo() {
						@Override
						public @Nullable String getSessionId() {
							return "sessionId";
						}

						@Override
						public X509Certificate @Nullable [] getPeerCertificates() {
							return new X509Certificate[] {  certificate };
						}
					};
					httpHandlerBuilder.filters((filters) -> filters.add(0, new SslInfoOverrideWebFilter(sslInfo)));
				}
			});
		};
	}

	private static class SslInfoOverrideWebFilter implements WebFilter {
		private final SslInfo sslInfo;

		private SslInfoOverrideWebFilter(SslInfo sslInfo) {
			this.sslInfo = sslInfo;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			ServerHttpRequest sslInfoRequest = exchange.getRequest().mutate().sslInfo(sslInfo)
					.build();
			ServerWebExchange sslInfoExchange = exchange.mutate().request(sslInfoRequest).build();
			return chain.filter(sslInfoExchange);
		}
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
