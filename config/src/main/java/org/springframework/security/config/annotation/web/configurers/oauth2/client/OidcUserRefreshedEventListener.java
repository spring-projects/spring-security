/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.oidc.authentication.event.OidcUserRefreshedEvent;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * An {@link ApplicationListener} that listens for events of type
 * {@link OidcUserRefreshedEvent} and refreshes the {@link SecurityContext}.
 *
 * @author Steve Riesenberg
 * @since 6.5
 * @see org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizedClientRefreshedEventListener
 */
final class OidcUserRefreshedEventListener implements ApplicationListener<OidcUserRefreshedEvent> {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

	@Override
	public void onApplicationEvent(OidcUserRefreshedEvent event) {
		SecurityContext securityContext = this.securityContextHolderStrategy.createEmptyContext();
		securityContext.setAuthentication(event.getAuthentication());
		this.securityContextHolderStrategy.setContext(securityContext);

		RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
		if (!(requestAttributes instanceof ServletRequestAttributes servletRequestAttributes)) {
			return;
		}

		HttpServletRequest request = servletRequestAttributes.getRequest();
		HttpServletResponse response = servletRequestAttributes.getResponse();
		this.securityContextRepository.saveContext(securityContext, request, response);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 * @param securityContextHolderStrategy the {@link SecurityContextHolderStrategy} to
	 * use
	 */
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Sets the {@link SecurityContextRepository} to save the {@link SecurityContext} upon
	 * receiving an {@link OidcUserRefreshedEvent}.
	 * @param securityContextRepository the {@link SecurityContextRepository} to use
	 */
	void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

}
