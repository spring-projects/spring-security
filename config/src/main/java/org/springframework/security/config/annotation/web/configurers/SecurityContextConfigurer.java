/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.ForceEagerSessionCreationFilter;

/**
 * Allows persisting and restoring of the {@link SecurityContext} found on the
 * {@link SecurityContextHolder} for each request by configuring the
 * {@link SecurityContextPersistenceFilter}. All properties have reasonable defaults, so
 * no additional configuration is required other than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link SecurityContextPersistenceFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>If {@link SessionManagementConfigurer}, is provided and set to always, then the
 * {@link SecurityContextPersistenceFilter#setForceEagerSessionCreation(boolean)} will be
 * set to true.</li>
 * <li>{@link SecurityContextRepository} must be set and is used on
 * {@link SecurityContextPersistenceFilter}.</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class SecurityContextConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<SecurityContextConfigurer<H>, H> {

	private boolean requireExplicitSave = true;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#securityContext()
	 */
	public SecurityContextConfigurer() {
	}

	/**
	 * Specifies the shared {@link SecurityContextRepository} that is to be used
	 * @param securityContextRepository the {@link SecurityContextRepository} to use
	 * @return the {@link HttpSecurity} for further customizations
	 */
	public SecurityContextConfigurer<H> securityContextRepository(SecurityContextRepository securityContextRepository) {
		getBuilder().setSharedObject(SecurityContextRepository.class, securityContextRepository);
		return this;
	}

	public SecurityContextConfigurer<H> requireExplicitSave(boolean requireExplicitSave) {
		this.requireExplicitSave = requireExplicitSave;
		return this;
	}

	boolean isRequireExplicitSave() {
		return this.requireExplicitSave;
	}

	SecurityContextRepository getSecurityContextRepository() {
		SecurityContextRepository securityContextRepository = getBuilder()
				.getSharedObject(SecurityContextRepository.class);
		if (securityContextRepository == null) {
			securityContextRepository = new DelegatingSecurityContextRepository(
					new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());
		}
		return securityContextRepository;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void configure(H http) {
		SecurityContextRepository securityContextRepository = getSecurityContextRepository();
		if (this.requireExplicitSave) {
			SecurityContextHolderFilter securityContextHolderFilter = postProcess(
					new SecurityContextHolderFilter(securityContextRepository));
			securityContextHolderFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
			http.addFilter(securityContextHolderFilter);
		}
		else {
			SecurityContextPersistenceFilter securityContextFilter = new SecurityContextPersistenceFilter(
					securityContextRepository);
			securityContextFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
			SessionManagementConfigurer<?> sessionManagement = http.getConfigurer(SessionManagementConfigurer.class);
			SessionCreationPolicy sessionCreationPolicy = (sessionManagement != null)
					? sessionManagement.getSessionCreationPolicy() : null;
			if (SessionCreationPolicy.ALWAYS == sessionCreationPolicy) {
				securityContextFilter.setForceEagerSessionCreation(true);
				http.addFilter(postProcess(new ForceEagerSessionCreationFilter()));
			}
			securityContextFilter = postProcess(securityContextFilter);
			http.addFilter(securityContextFilter);
		}
	}

}
