/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.server.csrf;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>
 * Applies
 * <a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)" >CSRF</a>
 * protection using a synchronizer token pattern. Developers are required to ensure that
 * {@link CsrfWebFilter} is invoked for any request that allows state to change. Typically
 * this just means that they should ensure their web application follows proper REST
 * semantics (i.e. do not change state with the HTTP methods GET, HEAD, TRACE, OPTIONS).
 * </p>
 *
 * <p>
 * Typically the {@link ServerCsrfTokenRepository} implementation chooses to store the
 * {@link CsrfToken} in {@link org.springframework.web.server.WebSession} with
 * {@link WebSessionServerCsrfTokenRepository}. This is preferred to storing the token in
 * a cookie which can be modified by a client application.
 * </p>
 *
 * @author Rob Winch
 * @since 5.0
 */
public class CsrfWebFilter implements WebFilter {

	private ServerWebExchangeMatcher requireCsrfProtectionMatcher = new DefaultRequireCsrfProtectionMatcher();

	private ServerCsrfTokenRepository serverCsrfTokenRepository = new WebSessionServerCsrfTokenRepository();

	private ServerAccessDeniedHandler serverAccessDeniedHandler = new HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN);

	public void setServerAccessDeniedHandler(
		ServerAccessDeniedHandler serverAccessDeniedHandler) {
		Assert.notNull(serverAccessDeniedHandler, "serverAccessDeniedHandler");
		this.serverAccessDeniedHandler = serverAccessDeniedHandler;
	}

	public void setServerCsrfTokenRepository(
		ServerCsrfTokenRepository serverCsrfTokenRepository) {
		Assert.notNull(serverCsrfTokenRepository, "serverCsrfTokenRepository cannot be null");
		this.serverCsrfTokenRepository = serverCsrfTokenRepository;
	}

	public void setRequireCsrfProtectionMatcher(
		ServerWebExchangeMatcher requireCsrfProtectionMatcher) {
		Assert.notNull(requireCsrfProtectionMatcher, "requireCsrfProtectionMatcher cannot be null");
		this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requireCsrfProtectionMatcher.matches(exchange)
			.filter( matchResult -> matchResult.isMatch())
			.filter( matchResult -> !exchange.getAttributes().containsKey(CsrfToken.class.getName()))
			.flatMap(m -> validateToken(exchange))
			.flatMap(m -> continueFilterChain(exchange, chain))
			.switchIfEmpty(continueFilterChain(exchange, chain).then(Mono.empty()))
			.onErrorResume(CsrfException.class, e -> this.serverAccessDeniedHandler.handle(exchange, e));
	}

	private Mono<Void> validateToken(ServerWebExchange exchange) {
		return this.serverCsrfTokenRepository.loadToken(exchange)
			.switchIfEmpty(Mono.error(new CsrfException("CSRF Token has been associated to this client")))
			.filterWhen(expected -> containsValidCsrfToken(exchange, expected))
			.switchIfEmpty(Mono.error(new CsrfException("Invalid CSRF Token")))
			.then();
	}

	private Mono<Boolean> containsValidCsrfToken(ServerWebExchange exchange, CsrfToken expected) {
		return exchange.getFormData()
			.flatMap(data -> Mono.justOrEmpty(data.getFirst(expected.getParameterName())))
			.switchIfEmpty(Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(expected.getHeaderName())))
			.map(actual -> actual.equals(expected.getToken()));
	}

	private Mono<Void> continueFilterChain(ServerWebExchange exchange, WebFilterChain chain) {
		return csrfToken(exchange)
			.doOnSuccess(csrfToken -> exchange.getAttributes().put(CsrfToken.class.getName(), csrfToken))
			.doOnSuccess(csrfToken -> exchange.getAttributes().put(csrfToken.getParameterName(), csrfToken))
			.flatMap( t -> chain.filter(exchange))
			.then();
	}

	private Mono<CsrfToken> csrfToken(ServerWebExchange exchange) {
		return this.serverCsrfTokenRepository.loadToken(exchange)
			.switchIfEmpty(generateToken(exchange));
	}

	private Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
		return this.serverCsrfTokenRepository.generateToken(exchange)
			.flatMap(token -> this.serverCsrfTokenRepository.saveToken(exchange, token));
	}

	private static class DefaultRequireCsrfProtectionMatcher implements ServerWebExchangeMatcher {
		private static final Set<HttpMethod> ALLOWED_METHODS = new HashSet<>(
			Arrays.asList(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.TRACE, HttpMethod.OPTIONS));

		@Override
		public Mono<MatchResult> matches(ServerWebExchange exchange) {
			return Mono.just(exchange.getRequest())
				.map(r -> r.getMethod())
				.filter(m -> ALLOWED_METHODS.contains(m))
				.flatMap(m -> MatchResult.notMatch())
				.switchIfEmpty(MatchResult.match());
		}
	}
}
