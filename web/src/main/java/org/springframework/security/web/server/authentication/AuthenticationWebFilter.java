/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * A {@link WebFilter} that performs authentication of a particular request. An outline of the logic:
 *
 * <ul>
 * <li>
 *     A request comes in and if it does not match {@link #setRequiresAuthenticationMatcher(ServerWebExchangeMatcher)},
 *     then this filter does nothing and the {@link WebFilterChain} is continued. If it does match then...
 * </li>
 * <li>
 *     An attempt to convert the {@link ServerWebExchange} into an {@link Authentication} is made. If the result is
 *     empty, then the filter does nothing more and the {@link WebFilterChain} is continued. If it does create an
 *     {@link Authentication}...
 * </li>
 * <li>
 *     The {@link ReactiveAuthenticationManager} specified in
 *     {@link #AuthenticationWebFilter(ReactiveAuthenticationManager)} is used to perform authentication.
 * </li>
 *<li>
 *     The {@link ReactiveAuthenticationManagerResolver} specified in
 *     {@link #AuthenticationWebFilter(ReactiveAuthenticationManagerResolver)} is used to resolve the appropriate
 *     authentication manager from context to perform authentication.
 * </li>
 * <li>
 *     If authentication is successful, {@link ServerAuthenticationSuccessHandler} is invoked and the authentication
 *     is set on {@link ReactiveSecurityContextHolder}, else {@link ServerAuthenticationFailureHandler} is invoked
 * </li>
 * </ul>
 *
 * @author Rob Winch
 * @author Rafiullah Hamedy
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class AuthenticationWebFilter implements WebFilter {
	private static final Log logger = LogFactory.getLog(AuthenticationWebFilter.class);
	private final ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver;

	private ServerAuthenticationSuccessHandler authenticationSuccessHandler = new WebFilterChainServerAuthenticationSuccessHandler();

	private ServerAuthenticationConverter authenticationConverter = new ServerHttpBasicAuthenticationConverter();

	private ServerAuthenticationFailureHandler authenticationFailureHandler = new ServerAuthenticationEntryPointFailureHandler(new HttpBasicServerAuthenticationEntryPoint());

	private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository.getInstance();

	private ServerWebExchangeMatcher requiresAuthenticationMatcher = ServerWebExchangeMatchers.anyExchange();

	/**
	 * Creates an instance
	 * @param authenticationManager the authentication manager to use
	 */
	public AuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManagerResolver = request -> Mono.just(authenticationManager);
	}

	/**
	 * Creates an instance
	 * @param authenticationManagerResolver the authentication manager resolver to use
	 * @since 5.3
	 */
	public AuthenticationWebFilter(ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver) {
		Assert.notNull(authenticationManagerResolver, "authenticationResolverManager cannot be null");
		this.authenticationManagerResolver = authenticationManagerResolver;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requiresAuthenticationMatcher.matches(exchange)
			.filter( matchResult -> matchResult.isMatch())
			.flatMap( matchResult -> this.authenticationConverter.convert(exchange))
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.flatMap( token -> authenticate(exchange, chain, token))
			.onErrorResume(AuthenticationException.class, e -> this.authenticationFailureHandler
					.onAuthenticationFailure(new WebFilterExchange(exchange, chain), e));
	}

	private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain, Authentication token) {
		return this.authenticationManagerResolver.resolve(exchange)
			.flatMap(authenticationManager -> authenticationManager.authenticate(token))
			.switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalStateException("No provider found for " + token.getClass()))))
			.flatMap(authentication -> onAuthenticationSuccess(authentication, new WebFilterExchange(exchange, chain)))
			.doOnError(AuthenticationException.class, e -> {
				if (logger.isDebugEnabled()) {
					logger.debug("Authentication failed: " + e.getMessage());
				}
			});
	}

	protected Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
		ServerWebExchange exchange = webFilterExchange.getExchange();
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		return this.securityContextRepository.save(exchange, securityContext)
			.then(this.authenticationSuccessHandler
				.onAuthenticationSuccess(webFilterExchange, authentication))
			.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
	}

	/**
	 * Sets the repository for persisting the SecurityContext. Default is {@link NoOpServerSecurityContextRepository}
	 * @param securityContextRepository the repository to use
	 */
	public void setSecurityContextRepository(
		ServerSecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	/**
	 * Sets the authentication success handler. Default is {@link WebFilterChainServerAuthenticationSuccessHandler}
	 * @param authenticationSuccessHandler the success handler to use
	 */
	public void setAuthenticationSuccessHandler(ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the strategy used for converting from a {@link ServerWebExchange} to an {@link Authentication} used for
	 * authenticating with the provided {@link ReactiveAuthenticationManager}. If the result is empty, then it signals
	 * that no authentication attempt should be made. The default converter is
	 * {@link ServerHttpBasicAuthenticationConverter}
	 * @param authenticationConverter the converter to use
	 * @deprecated As of 5.1 in favor of {@link #setServerAuthenticationConverter(ServerAuthenticationConverter)}
	 * @see #setServerAuthenticationConverter(ServerAuthenticationConverter)
	 */
	@Deprecated
	public void setAuthenticationConverter(Function<ServerWebExchange, Mono<Authentication>> authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		setServerAuthenticationConverter(authenticationConverter::apply);
	}

	/**
	 * Sets the strategy used for converting from a {@link ServerWebExchange} to an {@link Authentication} used for
	 * authenticating with the provided {@link ReactiveAuthenticationManager}. If the result is empty, then it signals
	 * that no authentication attempt should be made. The default converter is
	 * {@link ServerHttpBasicAuthenticationConverter}
	 * @param authenticationConverter the converter to use
	 * @since 5.1
	 */
	public void setServerAuthenticationConverter(
			ServerAuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the failure handler used when authentication fails. The default is to prompt for basic authentication.
	 * @param authenticationFailureHandler the handler to use. Cannot be null.
	 */
	public void setAuthenticationFailureHandler(
		ServerAuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Sets the matcher used to determine when creating an {@link Authentication} from
	 * {@link #setServerAuthenticationConverter(ServerAuthenticationConverter)} to be authentication. If the converter returns an empty
	 * result, then no authentication is attempted. The default is any request
	 * @param requiresAuthenticationMatcher the matcher to use. Cannot be null.
	 */
	public void setRequiresAuthenticationMatcher(
		ServerWebExchangeMatcher requiresAuthenticationMatcher) {
		Assert.notNull(requiresAuthenticationMatcher, "requiresAuthenticationMatcher cannot be null");
		this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
	}
}
