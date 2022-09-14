/*
 * Copyright 2002-2022 the original author or authors.
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

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class ServerHttpBasicAuthenticationConverterTests {

	ServerHttpBasicAuthenticationConverter converter = new ServerHttpBasicAuthenticationConverter();

	MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/");

	@Test
	public void setCredentialsCharsetWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.setCredentialsCharset(null))
				.withMessage("credentialsCharset cannot be null");
	}

	@Test
	public void applyWhenNoAuthorizationHeaderThenEmpty() {
		Mono<Authentication> result = apply(this.request);
		assertThat(result.block()).isNull();
	}

	@Test
	public void applyWhenEmptyAuthorizationHeaderThenEmpty() {
		Mono<Authentication> result = apply(this.request.header(HttpHeaders.AUTHORIZATION, ""));
		assertThat(result.block()).isNull();
	}

	@Test
	public void applyWhenOnlyBasicAuthorizationHeaderThenEmpty() {
		Mono<Authentication> result = apply(this.request.header(HttpHeaders.AUTHORIZATION, "Basic "));
		assertThat(result.block()).isNull();
	}

	@Test
	public void applyWhenNotBase64ThenEmpty() {
		Mono<Authentication> result = apply(this.request.header(HttpHeaders.AUTHORIZATION, "Basic z"));
		assertThat(result.block()).isNull();
	}

	@Test
	public void applyWhenNoColonThenEmpty() {
		Mono<Authentication> result = apply(this.request.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcg=="));
		assertThat(result.block()).isNull();
	}

	@Test
	public void applyWhenUserPasswordThenAuthentication() {
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA=="));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
				.block();
		assertThat(authentication.getPrincipal()).isEqualTo("user");
		assertThat(authentication.getCredentials()).isEqualTo("password");
	}

	@Test
	public void applyWhenUserPasswordHasColonThenAuthentication() {
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzOndvcmQ="));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
				.block();
		assertThat(authentication.getPrincipal()).isEqualTo("user");
		assertThat(authentication.getCredentials()).isEqualTo("pass:word");
	}

	@Test
	public void applyWhenLowercaseSchemeThenAuthentication() {
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "basic dXNlcjpwYXNzd29yZA=="));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
				.block();
		assertThat(authentication.getPrincipal()).isEqualTo("user");
		assertThat(authentication.getCredentials()).isEqualTo("password");
	}

	@Test
	public void applyWhenWrongSchemeThenEmpty() {
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "token dXNlcjpwYXNzd29yZA=="));
		assertThat(result.block()).isNull();
	}

	@Test
	public void applyWhenNonAsciiThenAuthentication() {
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "Basic w7xzZXI6cGFzc3fDtnJk"));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
				.block();
		assertThat(authentication.getPrincipal()).isEqualTo("üser");
		assertThat(authentication.getCredentials()).isEqualTo("passwörd");
	}

	@Test
	public void applyWhenIsoOnlyAsciiThenAuthentication() {
		this.converter.setCredentialsCharset(StandardCharsets.ISO_8859_1);
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA=="));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
				.block();
		assertThat(authentication.getPrincipal()).isEqualTo("user");
		assertThat(authentication.getCredentials()).isEqualTo("password");
	}

	@Test
	public void applyWhenIsoNonAsciiThenAuthentication() {
		this.converter.setCredentialsCharset(StandardCharsets.ISO_8859_1);
		Mono<Authentication> result = apply(
				this.request.header(HttpHeaders.AUTHORIZATION, "Basic /HNlcjpwYXNzd/ZyZA=="));
		UsernamePasswordAuthenticationToken authentication = result.cast(UsernamePasswordAuthenticationToken.class)
				.block();
		assertThat(authentication.getPrincipal()).isEqualTo("üser");
		assertThat(authentication.getCredentials()).isEqualTo("passwörd");
	}

	private Mono<Authentication> apply(MockServerHttpRequest.BaseBuilder<?> request) {
		return this.converter.convert(MockServerWebExchange.from(this.request.build()));
	}

}
