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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
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
import org.springframework.util.function.SingletonSupplier;

/**
 * Adds a URL based authorization using {@link AuthorizationManager}.
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthorizeHttpRequestsConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<AuthorizeHttpRequestsConfigurer<H>, H> {

	private final AuthorizationManagerRequestMatcherRegistry registry;

	private final AuthorizationEventPublisher publisher;

	private final Supplier<RoleHierarchy> roleHierarchy;

	private String rolePrefix = "ROLE_";

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
		this.roleHierarchy = SingletonSupplier.of(() -> (context.getBeanNamesForType(RoleHierarchy.class).length > 0)
				? context.getBean(RoleHierarchy.class) : new NullRoleHierarchy());
		String[] grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults.class);
		if (grantedAuthorityDefaultsBeanNames.length > 0) {
			GrantedAuthorityDefaults grantedAuthorityDefaults = context.getBean(GrantedAuthorityDefaults.class);
			this.rolePrefix = grantedAuthorityDefaults.getRolePrefix();
		}
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class,
				ResolvableType.forClassWithGenerics(AuthorizationManager.class, HttpServletRequest.class));
		ObjectProvider<ObjectPostProcessor<AuthorizationManager<HttpServletRequest>>> provider = context
			.getBeanProvider(type);
		provider.ifUnique((postProcessor) -> this.postProcessor = postProcessor);
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

	/**
	 * Registry for mapping a {@link RequestMatcher} to an {@link AuthorizationManager}.
	 *
	 * @author Evgeniy Cheban
	 */
	public final class AuthorizationManagerRequestMatcherRegistry
			extends AbstractRequestMatcherRegistry<AuthorizedUrl> {

		private final RequestMatcherDelegatingAuthorizationManager.Builder managerBuilder = RequestMatcherDelegatingAuthorizationManager
			.builder();

		private final HasAllAuthoritiesAuthorizationManager<RequestAuthorizationContext> hasAuthority = new HasAllAuthoritiesAuthorizationManager<>();

		private List<RequestMatcher> unmappedMatchers;

		private int mappingCount;

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
			this.hasAuthority.setRoleHierarchy(AuthorizeHttpRequestsConfigurer.this.roleHierarchy.get());
			AuthorizationManager<HttpServletRequest> manager = postProcess(
					(AuthorizationManager<HttpServletRequest>) this.managerBuilder.build());
			return AuthorizeHttpRequestsConfigurer.this.postProcessor.postProcess(manager);
		}

		@Override
		protected AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			this.unmappedMatchers = requestMatchers;
			return new AuthorizedUrl(this, requestMatchers);
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

		void hasAuthority(String authority) {
			this.hasAuthority.add(authority);
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

		private final AuthorizationManagerRequestMatcherRegistry registry;

		private final List<? extends RequestMatcher> matchers;

		private boolean not;

		/**
		 * Creates an instance.
		 * @param matchers the {@link RequestMatcher} instances to map
		 */
		AuthorizedUrl(AuthorizationManagerRequestMatcherRegistry registry, List<? extends RequestMatcher> matchers) {
			this.registry = registry;
			this.matchers = matchers;
		}

		protected List<? extends RequestMatcher> getMatchers() {
			return this.matchers;
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
			return access(SingleResultAuthorizationManager.permitAll());
		}

		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry denyAll() {
			return access(SingleResultAuthorizationManager.denyAll());
		}

		/**
		 * Specifies a user requires a role.
		 * @param role the role that should be required which is prepended with ROLE_
		 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
		 * @return {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasRole(String role) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager
				.hasAnyRole(AuthorizeHttpRequestsConfigurer.this.rolePrefix, new String[] { role })));
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
			return access(withRoleHierarchy(
					AuthorityAuthorizationManager.hasAnyRole(AuthorizeHttpRequestsConfigurer.this.rolePrefix, roles)));
		}

		/**
		 * Specifies a user requires an authority.
		 * @param authority the authority that should be required
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAuthority(String authority) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager.hasAuthority(authority)));
		}

		/**
		 * Specifies that a user requires one of many authorities.
		 * @param authorities the authorities that the user should have at least one of
		 * (i.e. ROLE_USER, ROLE_ADMIN, etc)
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry hasAnyAuthority(String... authorities) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager.hasAnyAuthority(authorities)));
		}

		private AuthorizationManager<RequestAuthorizationContext> withRoleHierarchy(
				AuthorityAuthorizationManager<RequestAuthorizationContext> manager) {
			manager.setRoleHierarchy(AuthorizeHttpRequestsConfigurer.this.roleHierarchy.get());
			return withAuthentication(manager);
		}

		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry authenticated() {
			return access(withAuthentication(AuthenticatedAuthorizationManager.authenticated()));
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
			return access(withAuthentication(AuthenticatedAuthorizationManager.fullyAuthenticated()));
		}

		/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		public AuthorizationManagerRequestMatcherRegistry rememberMe() {
			return access(withAuthentication(AuthenticatedAuthorizationManager.rememberMe()));
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
				AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.notNull(manager, "manager cannot be null");
			return (this.not)
					? AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, AuthorizationManagers.not(manager))
					: AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, manager);
		}

		private AuthorizationManager<RequestAuthorizationContext> withAuthentication(
				AuthorizationManager<RequestAuthorizationContext> manager) {
			return AuthorizationManagers.allOf(this.registry.hasAuthority, manager);
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

	private static final class HasAllAuthoritiesAuthorizationManager<T> implements AuthorizationManager<T> {

		private final AuthoritiesAuthorizationManager delegate = AuthoritiesAuthorizationManager.hasAllAuthorities();

		private final Collection<String> authorities = new ArrayList<>();

		@Override
		public AuthorizationResult authorize(Supplier<Authentication> authentication, T object) {
			return this.delegate.authorize(authentication, this.authorities);
		}

		private void setRoleHierarchy(RoleHierarchy hierarchy) {
			this.delegate.setRoleHierarchy(hierarchy);
		}

		private void add(String authority) {
			this.authorities.add(authority);
		}

	}

}
