/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.web.server;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.SecurityContextRepositoryWebFilter;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.WebFilter;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class HttpSecurity {
	private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

	private AuthorizeExchangeBuilder authorizeExchangeBuilder;

	private HeaderBuilder headers = new HeaderBuilder();
	private HttpBasicBuilder httpBasic;
	private ReactiveAuthenticationManager authenticationManager;

	private Optional<SecurityContextRepository> securityContextRepository = Optional.empty();

	/**
	 * The ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *
	 * @param matcher the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *                Default is all requests.
	 */
	public HttpSecurity securityMatcher(ServerWebExchangeMatcher matcher) {
		Assert.notNull(matcher, "matcher cannot be null");
		this.securityMatcher = matcher;
		return this;
	}

	/**
	 * Gets the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 * @return the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 */
	private ServerWebExchangeMatcher getSecurityMatcher() {
		return this.securityMatcher;
	}

	public HttpSecurity securityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = Optional.of(securityContextRepository);
		return this;
	}

	public HttpBasicBuilder httpBasic() {
		if(httpBasic == null) {
			httpBasic = new HttpBasicBuilder();
		}
		return httpBasic;
	}

	public HeaderBuilder headers() {
		return headers;
	}

	public AuthorizeExchangeBuilder authorizeExchange() {
		if(authorizeExchangeBuilder == null) {
			authorizeExchangeBuilder = new AuthorizeExchangeBuilder();
		}
		return authorizeExchangeBuilder;
	}

	public HttpSecurity authenticationManager(ReactiveAuthenticationManager manager) {
		this.authenticationManager = manager;
		return this;
	}

	public SecurityWebFilterChain build() {
		List<WebFilter> filters = new ArrayList<>();
		if(headers != null) {
			filters.add(headers.build());
		}
		securityContextRepositoryWebFilter().ifPresent( f-> filters.add(f));
		if(httpBasic != null) {
			httpBasic.authenticationManager(authenticationManager);
			securityContextRepository.ifPresent( scr -> httpBasic.securityContextRepository(scr)) ;
			filters.add(httpBasic.build());
		}
		if(authorizeExchangeBuilder != null) {
			filters.add(new ExceptionTranslationWebFilter());
			filters.add(authorizeExchangeBuilder.build());
		}
		return new MatcherSecurityWebFilterChain(getSecurityMatcher(), filters);
	}

	public static HttpSecurity http() {
		return new HttpSecurity();
	}

	private Optional<SecurityContextRepositoryWebFilter> securityContextRepositoryWebFilter() {
		return securityContextRepository
			.flatMap( r -> Optional.of(new SecurityContextRepositoryWebFilter(r)));
	}

	public class HttpBasicSpec extends HttpBasicBuilder {
		public HttpSecurity disable() {
			httpBasic = null;
			return HttpSecurity.this;
		}
	}

	private HttpSecurity() {}
}
