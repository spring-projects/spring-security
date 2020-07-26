/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds URL based authorization using
 * {@link DefaultFilterInvocationSecurityMetadataSource}. At least one
 * {@link org.springframework.web.bind.annotation.RequestMapping} needs to be mapped to
 * {@link ConfigAttribute}'s for this {@link SecurityContextConfigurer} to have meaning.
 * <h2>Security Filters</h2>
 *
 * <p>
 * Usage includes applying the {@link UrlAuthorizationConfigurer} and then modifying the
 * StandardInterceptUrlRegistry. For example:
 * </p>
 *
 * <pre>
 * protected void configure(HttpSecurity http) throws Exception {
 * 	http.apply(new UrlAuthorizationConfigurer&lt;HttpSecurity&gt;()).getRegistry()
 * 			.antMatchers(&quot;/users**&quot;, &quot;/sessions/**&quot;).hasRole(&quot;USER&quot;)
 * 			.antMatchers(&quot;/signup&quot;).hasRole(&quot;ANONYMOUS&quot;).anyRequest().hasRole(&quot;USER&quot;);
 * }
 * </pre>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated to allow other
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}'s to
 * customize:
 * <ul>
 * <li>
 * {@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>AuthenticationManager</li>
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 * @author Rob Winch
 * @since 3.2
 * @see ExpressionUrlAuthorizationConfigurer
 */
public final class UrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractInterceptUrlConfigurer<UrlAuthorizationConfigurer<H>, H> {

	private final StandardInterceptUrlRegistry REGISTRY;

	public UrlAuthorizationConfigurer(ApplicationContext context) {
		this.REGISTRY = new StandardInterceptUrlRegistry(context);
	}

	/**
	 * The StandardInterceptUrlRegistry is what users will interact with after applying
	 * the {@link UrlAuthorizationConfigurer}.
	 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
	 */
	public StandardInterceptUrlRegistry getRegistry() {
		return this.REGISTRY;
	}

	/**
	 * Adds an {@link ObjectPostProcessor} for this class.
	 * @param objectPostProcessor
	 * @return the {@link UrlAuthorizationConfigurer} for further customizations
	 */
	public UrlAuthorizationConfigurer<H> withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		addObjectPostProcessor(objectPostProcessor);
		return this;
	}

	public final class StandardInterceptUrlRegistry extends
			ExpressionUrlAuthorizationConfigurer<H>.AbstractInterceptUrlRegistry<StandardInterceptUrlRegistry, AuthorizedUrl> {

		/**
		 * @param context
		 */
		private StandardInterceptUrlRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		public MvcMatchersAuthorizedUrl mvcMatchers(HttpMethod method, String... mvcPatterns) {
			return new MvcMatchersAuthorizedUrl(createMvcMatchers(method, mvcPatterns));
		}

		@Override
		public MvcMatchersAuthorizedUrl mvcMatchers(String... patterns) {
			return mvcMatchers(null, patterns);
		}

		@Override
		protected AuthorizedUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
			return new AuthorizedUrl(requestMatchers);
		}

		/**
		 * Adds an {@link ObjectPostProcessor} for this class.
		 * @param objectPostProcessor
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customizations
		 */
		public StandardInterceptUrlRegistry withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
			addObjectPostProcessor(objectPostProcessor);
			return this;
		}

		public H and() {
			return UrlAuthorizationConfigurer.this.and();
		}

	}

	/**
	 * Creates the default {@link AccessDecisionVoter} instances used if an
	 * {@link AccessDecisionManager} was not specified.
	 * @param http the builder to use
	 */
	@Override
	@SuppressWarnings("rawtypes")
	List<AccessDecisionVoter<?>> getDecisionVoters(H http) {
		List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
		decisionVoters.add(new RoleVoter());
		decisionVoters.add(new AuthenticatedVoter());
		return decisionVoters;
	}

	/**
	 * Creates the {@link FilterInvocationSecurityMetadataSource} to use. The
	 * implementation is a {@link DefaultFilterInvocationSecurityMetadataSource}.
	 * @param http the builder to use
	 */
	@Override
	FilterInvocationSecurityMetadataSource createMetadataSource(H http) {
		return new DefaultFilterInvocationSecurityMetadataSource(this.REGISTRY.createRequestMap());
	}

	/**
	 * Adds a mapping of the {@link RequestMatcher} instances to the
	 * {@link ConfigAttribute} instances.
	 * @param requestMatchers the {@link RequestMatcher} instances that should map to the
	 * provided {@link ConfigAttribute} instances
	 * @param configAttributes the {@link ConfigAttribute} instances that should be mapped
	 * by the {@link RequestMatcher} instances
	 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
	 */
	private StandardInterceptUrlRegistry addMapping(Iterable<? extends RequestMatcher> requestMatchers,
			Collection<ConfigAttribute> configAttributes) {
		for (RequestMatcher requestMatcher : requestMatchers) {
			this.REGISTRY.addMapping(
					new AbstractConfigAttributeRequestMatcherRegistry.UrlMapping(requestMatcher, configAttributes));
		}
		return this.REGISTRY;
	}

	/**
	 * Creates a String for specifying a user requires a role.
	 * @param role the role that should be required which is prepended with ROLE_
	 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
	 * @return the {@link ConfigAttribute} expressed as a String
	 */
	private static String hasRole(String role) {
		Assert.isTrue(!role.startsWith("ROLE_"), () -> role
				+ " should not start with ROLE_ since ROLE_ is automatically prepended when using hasRole. Consider using hasAuthority or access instead.");
		return "ROLE_" + role;
	}

	/**
	 * Creates a String for specifying that a user requires one of many roles.
	 * @param roles the roles that the user should have at least one of (i.e. ADMIN, USER,
	 * etc). Each role should not start with ROLE_ since it is automatically prepended
	 * already.
	 * @return the {@link ConfigAttribute} expressed as a String
	 */
	private static String[] hasAnyRole(String... roles) {
		for (int i = 0; i < roles.length; i++) {
			roles[i] = "ROLE_" + roles[i];
		}
		return roles;
	}

	/**
	 * Creates a String for specifying that a user requires one of many authorities
	 * @param authorities the authorities that the user should have at least one of (i.e.
	 * ROLE_USER, ROLE_ADMIN, etc).
	 * @return the {@link ConfigAttribute} expressed as a String.
	 */
	private static String[] hasAnyAuthority(String... authorities) {
		return authorities;
	}

	/**
	 * An {@link AuthorizedUrl} that allows optionally configuring the
	 * {@link MvcRequestMatcher#setMethod(HttpMethod)}
	 *
	 * @author Rob Winch
	 */
	public final class MvcMatchersAuthorizedUrl extends AuthorizedUrl {

		/**
		 * Creates a new instance
		 * @param requestMatchers the {@link RequestMatcher} instances to map
		 */
		private MvcMatchersAuthorizedUrl(List<MvcRequestMatcher> requestMatchers) {
			super(requestMatchers);
		}

		@SuppressWarnings("unchecked")
		public AuthorizedUrl servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : (List<MvcRequestMatcher>) getMatchers()) {
				matcher.setServletPath(servletPath);
			}
			return this;
		}

	}

	/**
	 * Maps the specified {@link RequestMatcher} instances to {@link ConfigAttribute}
	 * instances.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public class AuthorizedUrl {

		private final List<? extends RequestMatcher> requestMatchers;

		/**
		 * Creates a new instance
		 * @param requestMatchers the {@link RequestMatcher} instances to map to some
		 * {@link ConfigAttribute} instances.
		 */
		AuthorizedUrl(List<? extends RequestMatcher> requestMatchers) {
			Assert.notEmpty(requestMatchers, "requestMatchers must contain at least one value");
			this.requestMatchers = requestMatchers;
		}

		/**
		 * Specifies a user requires a role.
		 * @param role the role that should be required which is prepended with ROLE_
		 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_ the
		 * {@link UrlAuthorizationConfigurer} for further customization
		 */
		public StandardInterceptUrlRegistry hasRole(String role) {
			return access(UrlAuthorizationConfigurer.hasRole(role));
		}

		/**
		 * Specifies that a user requires one of many roles.
		 * @param roles the roles that the user should have at least one of (i.e. ADMIN,
		 * USER, etc). Each role should not start with ROLE_ since it is automatically
		 * prepended already.
		 * @return the {@link UrlAuthorizationConfigurer} for further customization
		 */
		public StandardInterceptUrlRegistry hasAnyRole(String... roles) {
			return access(UrlAuthorizationConfigurer.hasAnyRole(roles));
		}

		/**
		 * Specifies a user requires an authority.
		 * @param authority the authority that should be required
		 * @return the {@link UrlAuthorizationConfigurer} for further customization
		 */
		public StandardInterceptUrlRegistry hasAuthority(String authority) {
			return access(authority);
		}

		/**
		 * Specifies that a user requires one of many authorities
		 * @param authorities the authorities that the user should have at least one of
		 * (i.e. ROLE_USER, ROLE_ADMIN, etc).
		 * @return the {@link UrlAuthorizationConfigurer} for further customization
		 */
		public StandardInterceptUrlRegistry hasAnyAuthority(String... authorities) {
			return access(UrlAuthorizationConfigurer.hasAnyAuthority(authorities));
		}

		/**
		 * Specifies that an anonymous user is allowed access
		 * @return the {@link UrlAuthorizationConfigurer} for further customization
		 */
		public StandardInterceptUrlRegistry anonymous() {
			return hasRole("ANONYMOUS");
		}

		/**
		 * Specifies that the user must have the specified {@link ConfigAttribute}'s
		 * @param attributes the {@link ConfigAttribute}'s that restrict access to a URL
		 * @return the {@link UrlAuthorizationConfigurer} for further customization
		 */
		public StandardInterceptUrlRegistry access(String... attributes) {
			addMapping(this.requestMatchers, SecurityConfig.createList(attributes));
			return UrlAuthorizationConfigurer.this.REGISTRY;
		}

		protected List<? extends RequestMatcher> getMatchers() {
			return this.requestMatchers;
		}

	}

}
