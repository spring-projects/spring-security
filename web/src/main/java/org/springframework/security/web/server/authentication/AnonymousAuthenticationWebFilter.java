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

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Detects if there is no {@code Authentication} object in the
 * {@code ReactiveSecurityContextHolder}, and populates it with one if needed.
 *
 * @author Ankur Pathak
 * @author Mathieu Ouellet
 * @since 5.2.0
 */
public class AnonymousAuthenticationWebFilter implements WebFilter {

	private static final Log logger = LogFactory.getLog(AnonymousAuthenticationWebFilter.class);

	private String key;

	private Object principal;

	private List<GrantedAuthority> authorities;

	/**
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 * @param key the key to identify tokens created by this filter
	 */
	public AnonymousAuthenticationWebFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * @param key key the key to identify tokens created by this filter
	 * @param principal the principal which will be used to represent anonymous users
	 * @param authorities the authority list for anonymous users
	 */
	public AnonymousAuthenticationWebFilter(String key, Object principal, List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext().switchIfEmpty(Mono.defer(() -> {
			Authentication authentication = createAuthentication(exchange);
			SecurityContext securityContext = new SecurityContextImpl(authentication);
			logger.debug(LogMessage.format("Populated SecurityContext with anonymous token: '%s'", authentication));
			return chain.filter(exchange)
					.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
					.then(Mono.empty());
		})).flatMap((securityContext) -> {
			logger.debug(LogMessage.format("SecurityContext contains anonymous token: '%s'",
					securityContext.getAuthentication()));
			return chain.filter(exchange);
		});
	}

	protected Authentication createAuthentication(ServerWebExchange exchange) {
		return new AnonymousAuthenticationToken(this.key, this.principal, this.authorities);
	}

}
