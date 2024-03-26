/*
 * Copyright 2002-2024 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author DingHao
 * @since 6.3
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingServerAuthenticationConverterTests {

	DelegatingServerAuthenticationConverter converter = new DelegatingServerAuthenticationConverter(
			new ApkServerAuthenticationConverter(), new ServerHttpBasicAuthenticationConverter());

	MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/");

	@Test
	public void applyServerHttpBasicAuthenticationConverter() {
		Mono<Authentication> result = this.converter.convert(MockServerWebExchange
			.from(this.request.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA==").build()));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
			.block();
		assertThat(authentication.getPrincipal()).isEqualTo("user");
		assertThat(authentication.getCredentials()).isEqualTo("password");
	}

	@Test
	public void applyApkServerAuthenticationConverter() {
		String apk = "123e4567e89b12d3a456426655440000";
		Mono<Authentication> result = this.converter
			.convert(MockServerWebExchange.from(this.request.header("APK", apk).build()));
		ApkTokenAuthenticationToken authentication = result.cast(ApkTokenAuthenticationToken.class).block();
		assertThat(authentication.getApk()).isEqualTo(apk);
	}

	@Test
	public void applyServerHttpBasicAuthenticationConverterWhenFirstAuthenticationConverterException() {
		this.converter.setContinueOnError(true);
		Mono<Authentication> result = this.converter.convert(MockServerWebExchange.from(this.request.header("APK", "")
			.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA==")
			.build()));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
			.block();
		assertThat(authentication.getPrincipal()).isEqualTo("user");
		assertThat(authentication.getCredentials()).isEqualTo("password");
	}

	@Test
	public void applyApkServerAuthenticationConverterThenDelegate2NotInvokedAndError() {
		Mono<Authentication> result = this.converter.convert(MockServerWebExchange.from(this.request.header("APK", "")
			.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA==")
			.build()));
		StepVerifier.create(result.cast(ApkTokenAuthenticationToken.class))
			.expectError(ApkAuthenticationException.class)
			.verify();
	}

	public static class ApkServerAuthenticationConverter implements ServerAuthenticationConverter {

		@Override
		public Mono<Authentication> convert(ServerWebExchange exchange) {
			return Mono.fromCallable(() -> exchange.getRequest().getHeaders().getFirst("APK")).map((apk) -> {
				if (apk.isEmpty()) {
					throw new ApkAuthenticationException("apk invalid");
				}
				return new ApkTokenAuthenticationToken(apk);
			});
		}

	}

	public static class ApkTokenAuthenticationToken extends AbstractAuthenticationToken {

		private final String apk;

		public ApkTokenAuthenticationToken(String apk) {
			super(AuthorityUtils.NO_AUTHORITIES);
			this.apk = apk;
		}

		public String getApk() {
			return this.apk;
		}

		@Override
		public Object getCredentials() {
			return this.getApk();
		}

		@Override
		public Object getPrincipal() {
			return this.getApk();
		}

	}

	public static class ApkAuthenticationException extends AuthenticationException {

		public ApkAuthenticationException(String msg) {
			super(msg);
		}

	}

}
