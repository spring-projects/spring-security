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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.context.ServerWebExchangeAttributeSecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class DefaultAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	private SecurityContextRepository securityContextRepository = new ServerWebExchangeAttributeSecurityContextRepository();

	private AuthenticationSuccessHandler delegate = new WebFilterChainAuthenticationSuccessHandler();

	@Override
	public Mono<Void> success(Authentication authentication, ServerWebExchange exchange, WebFilterChain chain) {
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		return securityContextRepository.save(exchange, securityContext)
			.flatMap( wrappedExchange -> delegate.success(authentication, wrappedExchange, chain));
	}

	public void setDelegate(AuthenticationSuccessHandler delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}
}
