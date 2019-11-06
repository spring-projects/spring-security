/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.server.authentication.logout;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * A {@link ServerLogoutHandler} which removes the SecurityContext using the provided
 * {@link ServerSecurityContextRepository}
 *
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityContextServerLogoutHandler implements ServerLogoutHandler {
	private ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();

	@Override
	public Mono<Void> logout(WebFilterExchange exchange,
		Authentication authentication) {
		return this.securityContextRepository.save(exchange.getExchange(), null);
	}

	/**
	 * Sets the {@link ServerSecurityContextRepository} that should be used for logging
	 * out. Default is {@link WebSessionServerSecurityContextRepository}
	 *
	 * @param securityContextRepository the {@link ServerSecurityContextRepository}
	 * to use.
	 */
	public void setSecurityContextRepository(
		ServerSecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository,
			"securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}
}
