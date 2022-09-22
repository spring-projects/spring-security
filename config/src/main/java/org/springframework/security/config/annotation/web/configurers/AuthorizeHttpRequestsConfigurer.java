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

import java.util.List;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;

/**
 * Adds a URL based authorization using {@link AuthorizationManager}.
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthorizeHttpRequestsConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<AuthorizeHttpRequestsConfigurer<H>, H> {

	static final AuthorizationManager<RequestAuthorizationContext> permitAllAuthorizationManager = (a,
			o) -> new AuthorizationDecision(true);

	private final AuthorizationManagerRequestMatcherRegistry registry;

	private final AuthorizationEventPublisher publisher;

	/**
	 * Creates an instance.
	 * @param context the {@link ApplicationContext} to use
	 */
	public AuthorizeHttpRequestsConfigurer(ApplicationContext context) {
		this.registry = new AuthorizationManagerRequestMatcherRegistry(context);
		if (context.getBeanNamesForType(AuthorizationEventPublisher.class).length > 0) {
			this.publisher = context.getBean(AuthorizationEventPublisher.class);
		}
		else {
			this.publisher = new SpringAuthorizationEventPublisher(context);
		}
	}

	/**
	 * The {@link AuthorizationManagerRequestMatcherRegistry} is what users will interact
	 * with after applying the {@link AuthorizeHttpRequestsConfigurer}.
	 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
	 * customizations
	 */
	public AuthorizationManagerRequestMatcherRegistry getRegistry() {
		return this.registry;
	}

	@Override
	public void configure(H http) {
		AuthorizationManager<HttpServletRequest> authorizationManager = this.registry.createAuthorizationManager();
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		authorizationFilter.setAuthorizationEventPublisher(this.publisher);
		authorizationFilter.setShouldFilterAllDispatcherTypes(this.registry.shouldFilterAllDispatcherTypes);
		authorizationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		http.addFilter(postProcess(authorizationFilter));
	}

	private AuthorizationManagerRequestMatcherRegistry addMapping(List<? extends RequestMatcher> matchers,
			AuthorizationManager<RequestAuthorizationContext> manager) {
		for (RequestMatcher matcher : matchers) {
			this.registry.addMapping(matcher, manager);
		}
		return this.registry;
	}

	AuthorizationManagerRequestMatcherRegistry addFirst(RequestMatcher matcher,
			AuthorizationManager<RequestAuthorizationContext> manager) {
		this.registry.addFirst(matcher, manager);
		return this.registry;
	}

	private ObservationRegistry getObservationRegistry() {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(ObservationRegistry.class);
		if (names.length == 1) {
			return context.getBean(ObservationRegistry.class);
		}
		else {
			return ObservationRegistry.NOOP;
		}
	}

	/**
	 * Registry for mapping a {@link RequestMatcher} to an {@link AuthorizationManager}.
	 *
	 * @author Evgeniy Cheban
	 */
	public final class AuthorizationManagerRequestMatcherRegistry
			extends AbstractRequestMatcherRegistry<AuthorizedUrl> {

		private final RequestMatcherDelegatingAuthorizationManager.Builder managerBuilder = RequestMatcherDelegatingAuthorizationManager
				.builder();

		private List<RequestMatcher> unmappedMatchers;

		private int mappingCount;

		private boolean shouldFilterAllDispatcherTypes = true;

		private AuthorizationManagerRequestMatcherRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		private void addMapping(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			this.unmappedMatchers = null;
			this.managerBuilder.add(matcher, manager);
			this.mappingCount++;
		}

		private void addFirst(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			this.unmappedMatchers = null;
			this.managerBuilder.mappings((m) -> m.add(0, new RequestMatcherEntry<>(matcher, manager)));
			this.mappingCount++;
		}

		private AuthorizationManager<HttpServletRequest> createAuthorizationManager() {
			Assert.state(this.unmappedMatchers == null,
					() -> "An incomplete mapping was found for " + this.unmappedMatchers
							+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
			Assert.state(this.mappingCount > 0,
					"At least one mapping is required (for example, authorizeHttpRequests().anyRequest().authenticated())");
			ObservationRegistry registry = getObservationRegistry();
			RequestMatcherDelegatingAuthorizationManager manager = postProcess(this.managerBuilder.build());
			if (registry.isNoop()) {
				return manager;
			}
			return new ObservationAuthorizationManager<>(registry, manager);
		}

		@Override
		protected AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			this.unmappedMatchers = requestMatchers;
			return new AuthorizedUrl(requestMatchers);
		}

		/**
		 * Adds an {@link ObjectPostProcessor} for this class.
		 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry withObjectPostProcessor(
				ObjectPostProcessor<?> objectPostProcessor) {
			addObjectPostProcessor(objectPostProcessor);
			return this;
		}

		/**
		 * Sets whether all dispatcher types should be filtered.
		 * @param shouldFilter should filter all dispatcher types. Default is {@code true}
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 * @since 5.7
		 */
		public AuthorizationManagerRequestMatcherRegistry shouldFilterAllDispatcherTypes(boolean shouldFilter) {
			this.shouldFilterAllDispatcherTypes = shouldFilter;
			return this;
		}

		/**
		 * Return the {@link HttpSecurityBuilder} when done using the
		 * {@link AuthorizeHttpRequestsConfigurer}. This is useful for method chaining.
		 * @return the {@link HttpSecurityBuilder} for further customizations
		 */
		public H and() {
			return AuthorizeHttpRequestsConfigurer.this.and();
		}

	}

	/**
	 * An object that allows configuring the {@link AuthorizationManager} for
	 * {@link RequestMatcher}s.
	 *
	 * @author Evgeniy Cheban
	 */
	public class AuthorizedUrl {

		private final List<? extends RequestMatcher> matchers;

		/**
		 * Creates an instance.
		 * @param matchers the {@link RequestMatcher} instances to map
		 */
		AuthorizedUrl(List<? extends RequestMatcher> matchers) {
			this.matchers = matchers;
		}

		protected List<? extends RequestMatcher> getMatchers() {
			return this.matchers;
		}

		/**
		 * Specify that URLs are allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry permitAll() {
			return access(permitAllAuthorizationManager);
		}

		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry denyAll() {
			return access((a, o) -> new AuthorizationDecision(false));
		}

		/**
		 * Specifies a user requires a role.
		 * @param role the role that should be required which is prepended with ROLE_
		 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
		 * @return {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasRole(String role) {
			return access(AuthorityAuthorizationManager.hasRole(role));
		}

		/**
		 * Specifies that a user requires one of many roles.
		 * @param roles the roles that the user should have at least one of (i.e. ADMIN,
		 * USER, etc). Each role should not start with ROLE_ since it is automatically
		 * prepended already
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAnyRole(String... roles) {
			return access(AuthorityAuthorizationManager.hasAnyRole(roles));
		}

		/**
		 * Specifies a user requires an authority.
		 * @param authority the authority that should be required
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAuthority(String authority) {
			return access(AuthorityAuthorizationManager.hasAuthority(authority));
		}

		/**
		 * Specifies that a user requires one of many authorities.
		 * @param authorities the authorities that the user should have at least one of
		 * (i.e. ROLE_USER, ROLE_ADMIN, etc)
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAnyAuthority(String... authorities) {
			return access(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
		}

		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry authenticated() {
			return access(AuthenticatedAuthorizationManager.authenticated());
		}

		/**
		 * Specify that URLs are allowed by users who have authenticated and were not
		 * "remembered".
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		public AuthorizationManagerRequestMatcherRegistry fullyAuthenticated() {
			return access(AuthenticatedAuthorizationManager.fullyAuthenticated());
		}

		/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		public AuthorizationManagerRequestMatcherRegistry rememberMe() {
			return access(AuthenticatedAuthorizationManager.rememberMe());
		}

		/**
		 * Specify that URLs are allowed by anonymous users.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 */
		public AuthorizationManagerRequestMatcherRegistry anonymous() {
			return access(AuthenticatedAuthorizationManager.anonymous());
		}

		/**
		 * Allows specifying a custom {@link AuthorizationManager}.
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry access(
				AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.notNull(manager, "manager cannot be null");
			return AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, manager);
		}

	}

}
