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

package org.springframework.security.config.annotation.web.configurers;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.DelegatingAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
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

	private final AuthorizationManagerRequestMatcherRegistry registry;

	/**
	 * Creates an instance.
	 * @param context the {@link ApplicationContext} to use
	 */
	public AuthorizeHttpRequestsConfigurer(ApplicationContext context) {
		this.registry = new AuthorizationManagerRequestMatcherRegistry(context);
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
		http.addFilter(postProcess(authorizationFilter));
	}

	private AuthorizationManagerRequestMatcherRegistry addMapping(List<? extends RequestMatcher> matchers,
			AuthorizationManager<RequestAuthorizationContext> manager) {
		for (RequestMatcher matcher : matchers) {
			this.registry.addMapping(matcher, manager);
		}
		return this.registry;
	}

	/**
	 * Registry for mapping a {@link RequestMatcher} to an {@link AuthorizationManager}.
	 *
	 * @author Evgeniy Cheban
	 */
	public final class AuthorizationManagerRequestMatcherRegistry
			extends AbstractRequestMatcherRegistry<AuthorizedUrl> {

		private final DelegatingAuthorizationManager.Builder managerBuilder = DelegatingAuthorizationManager.builder();

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

		private AuthorizationManager<HttpServletRequest> createAuthorizationManager() {
			Assert.state(this.unmappedMatchers == null,
					() -> "An incomplete mapping was found for " + this.unmappedMatchers
							+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
			Assert.state(this.mappingCount > 0,
					"At least one mapping is required (for example, authorizeHttpRequests().anyRequest().authenticated())");
			return postProcess(this.managerBuilder.build());
		}

		@Override
		public MvcMatchersAuthorizedUrl mvcMatchers(String... mvcPatterns) {
			return mvcMatchers(null, mvcPatterns);
		}

		@Override
		public MvcMatchersAuthorizedUrl mvcMatchers(HttpMethod method, String... mvcPatterns) {
			return new MvcMatchersAuthorizedUrl(createMvcMatchers(method, mvcPatterns));
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
		 * Return the {@link HttpSecurityBuilder} when done using the
		 * {@link AuthorizeHttpRequestsConfigurer}. This is useful for method chaining.
		 * @return the {@link HttpSecurityBuilder} for further customizations
		 */
		public H and() {
			return AuthorizeHttpRequestsConfigurer.this.and();
		}

	}

	/**
	 * An {@link AuthorizeHttpRequestsConfigurer.AuthorizedUrl} that allows optionally
	 * configuring the {@link MvcRequestMatcher#setServletPath(String)}.
	 *
	 * @author Evgeniy Cheban
	 */
	public final class MvcMatchersAuthorizedUrl extends AuthorizedUrl {

		private MvcMatchersAuthorizedUrl(List<MvcRequestMatcher> matchers) {
			super(matchers);
		}

		/**
		 * Configures <code>servletPath</code> to {@link MvcRequestMatcher}s.
		 * @param servletPath the servlet path
		 * @return the {@link MvcMatchersAuthorizedUrl} for further customizations
		 */
		@SuppressWarnings("unchecked")
		public MvcMatchersAuthorizedUrl servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : (List<MvcRequestMatcher>) getMatchers()) {
				matcher.setServletPath(servletPath);
			}
			return this;
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
			return access((a, o) -> new AuthorizationDecision(true));
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
