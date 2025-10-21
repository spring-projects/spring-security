/*
 * Copyright 2004-present the original author or authors.
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
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
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
 * @author Steve Riesenberg
 * @since 5.5
 */
public final class AuthorizeHttpRequestsConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<AuthorizeHttpRequestsConfigurer<H>, H> {

	private final AuthorizationManagerRequestMatcherRegistry registry;

	private final AuthorizationEventPublisher publisher;

	private final AuthorizationManagerFactory<? super RequestAuthorizationContext> authorizationManagerFactory;

	private ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> postProcessor = ObjectPostProcessor
		.identity();

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
		this.authorizationManagerFactory = getAuthorizationManagerFactory(context);
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class,
				ResolvableType.forClassWithGenerics(AuthorizationManager.class, HttpServletRequest.class));
		ObjectProvider<ObjectPostProcessor<AuthorizationManager<HttpServletRequest>>> provider = context
			.getBeanProvider(type);
		provider.ifUnique((postProcessor) -> this.postProcessor = postProcessor);
	}

	private AuthorizationManagerFactory<? super RequestAuthorizationContext> getAuthorizationManagerFactory(
			ApplicationContext context) {
		ResolvableType authorizationManagerFactoryType = ResolvableType
			.forClassWithGenerics(AuthorizationManagerFactory.class, RequestAuthorizationContext.class);

		// Handle fallback to generic type
		if (context.getBeanNamesForType(authorizationManagerFactoryType).length == 0) {
			authorizationManagerFactoryType = ResolvableType.forClassWithGenerics(AuthorizationManagerFactory.class,
					Object.class);
		}

		ObjectProvider<AuthorizationManagerFactory<RequestAuthorizationContext>> authorizationManagerFactoryProvider = context
			.getBeanProvider(authorizationManagerFactoryType);

		return authorizationManagerFactoryProvider.getIfAvailable(() -> {
			RoleHierarchy roleHierarchy = context.getBeanProvider(RoleHierarchy.class)
				.getIfAvailable(NullRoleHierarchy::new);
			GrantedAuthorityDefaults grantedAuthorityDefaults = context.getBeanProvider(GrantedAuthorityDefaults.class)
				.getIfAvailable();
			String rolePrefix = (grantedAuthorityDefaults != null) ? grantedAuthorityDefaults.getRolePrefix() : "ROLE_";

			DefaultAuthorizationManagerFactory<RequestAuthorizationContext> authorizationManagerFactory = new DefaultAuthorizationManagerFactory<>();
			authorizationManagerFactory.setRoleHierarchy(roleHierarchy);
			authorizationManagerFactory.setRolePrefix(rolePrefix);

			return authorizationManagerFactory;
		});
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
		authorizationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		http.addFilter(postProcess(authorizationFilter));
	}

	private AuthorizationManagerRequestMatcherRegistry addMapping(List<? extends RequestMatcher> matchers,
			AuthorizationManager<? super RequestAuthorizationContext> manager) {
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

		private AuthorizationManagerRequestMatcherRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		private void addMapping(RequestMatcher matcher,
				AuthorizationManager<? super RequestAuthorizationContext> manager) {
			this.unmappedMatchers = null;
			this.managerBuilder.add(matcher, manager);
			this.mappingCount++;
		}

		private void addFirst(RequestMatcher matcher,
				AuthorizationManager<? super RequestAuthorizationContext> manager) {
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
			AuthorizationManager<HttpServletRequest> manager = postProcess(
					(AuthorizationManager<HttpServletRequest>) this.managerBuilder.build());
			return AuthorizeHttpRequestsConfigurer.this.postProcessor.postProcess(manager);
		}

		@Override
		protected AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			this.unmappedMatchers = requestMatchers;
			return new AuthorizedUrl(requestMatchers, AuthorizeHttpRequestsConfigurer.this.authorizationManagerFactory);
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

	}

	/**
	 * An object that allows configuring the {@link AuthorizationManager} for
	 * {@link RequestMatcher}s.
	 *
	 * @author Evgeniy Cheban
	 * @author Josh Cummings
	 */
	public class AuthorizedUrl {

		private final List<? extends RequestMatcher> matchers;

		private AuthorizationManagerFactory<? super RequestAuthorizationContext> authorizationManagerFactory;

		private boolean not;

		/**
		 * Creates an instance.
		 * @param matchers the {@link RequestMatcher} instances to map
		 * @param authorizationManagerFactory the {@link AuthorizationManagerFactory} for
		 * creating instances of {@link AuthorizationManager}
		 */
		AuthorizedUrl(List<? extends RequestMatcher> matchers,
				AuthorizationManagerFactory<? super RequestAuthorizationContext> authorizationManagerFactory) {
			this.matchers = matchers;
			this.authorizationManagerFactory = authorizationManagerFactory;
		}

		protected List<? extends RequestMatcher> getMatchers() {
			return this.matchers;
		}

		void setAuthorizationManagerFactory(
				AuthorizationManagerFactory<? super RequestAuthorizationContext> authorizationManagerFactory) {
			this.authorizationManagerFactory = authorizationManagerFactory;
		}

		/**
		 * Negates the following authorization rule.
		 * @return the {@link AuthorizedUrl} for further customization
		 * @since 6.3
		 */
		public AuthorizedUrl not() {
			this.not = true;
			return this;
		}

		/**
		 * Specify that URLs are allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry permitAll() {
			return access(this.authorizationManagerFactory.permitAll());
		}

		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry denyAll() {
			return access(this.authorizationManagerFactory.denyAll());
		}

		/**
		 * Specifies a user requires a role.
		 * @param role the role that should be required which is prepended with ROLE_
		 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
		 * @return {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasRole(String role) {
			return access(this.authorizationManagerFactory.hasRole(role));
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
			return access(this.authorizationManagerFactory.hasAnyRole(roles));
		}

		/**
		 * Specifies that a user requires all the provided roles.
		 * @param roles the roles that the user should have (i.e. ADMIN, USER, etc). Each
		 * role should not start with ROLE_ since it is automatically prepended already
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAllRoles(String... roles) {
			return access(this.authorizationManagerFactory.hasAllRoles(roles));
		}

		/**
		 * Specifies a user requires an authority.
		 * @param authority the authority that should be required
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAuthority(String authority) {
			return access(this.authorizationManagerFactory.hasAuthority(authority));
		}

		/**
		 * Specifies that a user requires one of many authorities.
		 * @param authorities the authorities that the user should have at least one of
		 * (i.e. ROLE_USER, ROLE_ADMIN, etc)
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAnyAuthority(String... authorities) {
			return access(this.authorizationManagerFactory.hasAnyAuthority(authorities));
		}

		/**
		 * Specifies that a user requires all the provided authorities.
		 * @param authorities the authorities that the user should have (i.e. ROLE_USER,
		 * ROLE_ADMIN, etc)
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAllAuthorities(String... authorities) {
			return access(this.authorizationManagerFactory.hasAllAuthorities(authorities));
		}

		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry authenticated() {
			return access(this.authorizationManagerFactory.authenticated());
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
			return access(this.authorizationManagerFactory.fullyAuthenticated());
		}

		/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		public AuthorizationManagerRequestMatcherRegistry rememberMe() {
			return access(this.authorizationManagerFactory.rememberMe());
		}

		/**
		 * Specify that URLs are allowed by anonymous users.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 */
		public AuthorizationManagerRequestMatcherRegistry anonymous() {
			return access(this.authorizationManagerFactory.anonymous());
		}

		/**
		 * Specify that a path variable in URL to be compared.
		 *
		 * <p>
		 * For example, <pre>
		 * requestMatchers("/user/{username}").hasVariable("username").equalTo(Authentication::getName)
		 * </pre>
		 * @param variable the variable in URL template to compare.
		 * @return {@link AuthorizedUrlVariable} for further customization.
		 * @since 6.3
		 */
		public AuthorizedUrlVariable hasVariable(String variable) {
			return new AuthorizedUrlVariable(variable);
		}

		/**
		 * Allows specifying a custom {@link AuthorizationManager}.
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry access(
				AuthorizationManager<? super RequestAuthorizationContext> manager) {
			Assert.notNull(manager, "manager cannot be null");
			return (this.not)
					? AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, AuthorizationManagers.not(manager))
					: AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, manager);
		}

		/**
		 * An object that allows configuring {@link RequestMatcher}s with URI path
		 * variables
		 *
		 * @author Taehong Kim
		 * @since 6.3
		 */
		public final class AuthorizedUrlVariable {

			private final String variable;

			private AuthorizedUrlVariable(String variable) {
				this.variable = variable;
			}

			/**
			 * Compares the value of a path variable in the URI with an `Authentication`
			 * attribute
			 * <p>
			 * For example, <pre>
			 * requestMatchers("/user/{username}").hasVariable("username").equalTo(Authentication::getName));
			 * </pre>
			 * @param function a function to get value from {@link Authentication}.
			 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
			 * customization.
			 */
			public AuthorizationManagerRequestMatcherRegistry equalTo(Function<Authentication, String> function) {
				return access((auth, requestContext) -> {
					String value = requestContext.getVariables().get(this.variable);
					return new AuthorizationDecision(function.apply(auth.get()).equals(value));
				});
			}

		}

	}

}
