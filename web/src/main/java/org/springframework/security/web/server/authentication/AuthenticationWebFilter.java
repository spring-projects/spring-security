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
package org.springframework.security.web.server.authentication;

import java.util.function.Function;

import org.springframework.security.core.AuthenticationException;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
public class AuthenticationWebFilter implements WebFilter {

	private final ReactiveAuthenticationManager authenticationManager;

	private ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler = new WebFilterChainServerAuthenticationSuccessHandler();

	private Function<ServerWebExchange,Mono<Authentication>> authenticationConverter = new ServerHttpBasicAuthenticationConverter();

	private ServerAuthenticationFailureHandler serverAuthenticationFailureHandler = new ServerAuthenticationEntryPointFailureHandler(new HttpBasicServerAuthenticationEntryPoint());

	private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository.getInstance();

	private ServerWebExchangeMatcher requiresAuthenticationMatcher = ServerWebExchangeMatchers.anyExchange();

	public AuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requiresAuthenticationMatcher.matches(exchange)
			.filter( matchResult -> matchResult.isMatch())
			.flatMap( matchResult -> this.authenticationConverter.apply(exchange))
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.flatMap( token -> authenticate(exchange, chain, token));
	}

	private Mono<Void> authenticate(ServerWebExchange exchange,
		WebFilterChain chain, Authentication token) {
		WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);
		return this.authenticationManager.authenticate(token)
			.flatMap(authentication -> onAuthenticationSuccess(authentication, webFilterExchange))
			.onErrorResume(AuthenticationException.class, e -> this.serverAuthenticationFailureHandler
				.onAuthenticationFailure(webFilterExchange, e));
	}

	private Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
		ServerWebExchange exchange = webFilterExchange.getExchange();
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		return this.securityContextRepository.save(exchange, securityContext)
			.then(this.serverAuthenticationSuccessHandler
				.onAuthenticationSuccess(webFilterExchange, authentication));
	}

	public void setSecurityContextRepository(
		ServerSecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	public void setServerAuthenticationSuccessHandler(ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler) {
		this.serverAuthenticationSuccessHandler = serverAuthenticationSuccessHandler;
	}

	public void setAuthenticationConverter(Function<ServerWebExchange,Mono<Authentication>> authenticationConverter) {
		this.authenticationConverter = authenticationConverter;
	}

	public void setServerAuthenticationFailureHandler(
		ServerAuthenticationFailureHandler serverAuthenticationFailureHandler) {
		Assert.notNull(serverAuthenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.serverAuthenticationFailureHandler = serverAuthenticationFailureHandler;
	}

	public void setRequiresAuthenticationMatcher(
		ServerWebExchangeMatcher requiresAuthenticationMatcher) {
		Assert.notNull(requiresAuthenticationMatcher, "requiresAuthenticationMatcher cannot be null");
		this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
	}
}
