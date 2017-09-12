/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package org.springframework.security.web.server.authentication;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.security.web.server.HttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.www.HttpBasicAuthenticationEntryPoint;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.context.SecurityContextRepositoryServerWebExchange;
import org.springframework.security.web.server.context.ServerWebExchangeAttributeSecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.function.Function;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
public class AuthenticationWebFilter implements WebFilter {

	private final ReactiveAuthenticationManager authenticationManager;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new WebFilterChainAuthenticationSuccessHandler();

	private Function<ServerWebExchange,Mono<Authentication>> authenticationConverter = new HttpBasicAuthenticationConverter();

	private AuthenticationEntryPoint entryPoint = new HttpBasicAuthenticationEntryPoint();

	private SecurityContextRepository securityContextRepository = new ServerWebExchangeAttributeSecurityContextRepository();

	public AuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		ServerWebExchange wrappedExchange = wrap(exchange);
		return this.authenticationConverter.apply(wrappedExchange)
			.switchIfEmpty(Mono.defer(() -> chain.filter(wrappedExchange).cast(Authentication.class)))
			.flatMap( token -> this.authenticationManager.authenticate(token)
				.flatMap(authentication -> onAuthenticationSuccess(authentication, wrappedExchange, chain))
				.onErrorResume( AuthenticationException.class, t -> this.entryPoint.commence(wrappedExchange, t))
			);
	}

	private ServerWebExchange wrap(ServerWebExchange exchange) {
		return new SecurityContextRepositoryServerWebExchange(exchange, this.securityContextRepository);
	}

	private Mono<Void> onAuthenticationSuccess(Authentication authentication, ServerWebExchange exchange, WebFilterChain chain) {
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		return this.securityContextRepository.save(exchange, securityContext)
			.flatMap( wrappedExchange -> this.authenticationSuccessHandler.success(authentication, wrappedExchange, chain));
	}

	public void setSecurityContextRepository(
		SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	public void setAuthenticationConverter(Function<ServerWebExchange,Mono<Authentication>> authenticationConverter) {
		this.authenticationConverter = authenticationConverter;
	}

	public void setEntryPoint(AuthenticationEntryPoint entryPoint) {
		this.entryPoint = entryPoint;
	}
}
