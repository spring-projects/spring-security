/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.authentication;

import org.springframework.core.Ordered;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptor;

import java.util.List;

/**
 * If {@link ReactiveSecurityContextHolder} is empty populates an
 * {@code AnonymousAuthenticationToken}
 *
 * @author Rob Winch
 * @since 5.2
 */
public class AnonymousPayloadInterceptor implements PayloadInterceptor, Ordered {

	private String key;
	private Object principal;
	private List<GrantedAuthority> authorities;

	private int order;

	/**
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 *
	 * @param key the key to identify tokens created by this filter
	 */
	public AnonymousPayloadInterceptor(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * @param key         key the key to identify tokens created by this filter
	 * @param principal   the principal which will be used to represent anonymous users
	 * @param authorities the authority list for anonymous users
	 */
	public AnonymousPayloadInterceptor(String key, Object principal,
			List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	@Override
	public Mono<Void> intercept(PayloadExchange exchange, PayloadInterceptorChain chain) {
		return ReactiveSecurityContextHolder.getContext()
				.switchIfEmpty(Mono.defer(() -> {
					AnonymousAuthenticationToken authentication = new AnonymousAuthenticationToken(
							this.key, this.principal, this.authorities);
					return chain.next(exchange)
							.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
							.then(Mono.empty());
				}))
				.flatMap(securityContext -> chain.next(exchange));
	}
}
