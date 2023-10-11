/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.servlet.DispatcherServlet;

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

	private final Supplier<RoleHierarchy> roleHierarchy;

	private String rolePrefix = "ROLE_";

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
			extends AbstractRequestMatcherBuilderRegistry<AuthorizedUrl<AuthorizationManagerRequestMatcherRegistry>> {

		private final RequestMatcherDelegatingAuthorizationManager.Builder managerBuilder = RequestMatcherDelegatingAuthorizationManager
			.builder();

		List<RequestMatcher> unmappedMatchers;

		private int mappingCount;

		private boolean shouldFilterAllDispatcherTypes = true;

		private final Map<String, AuthorizationManagerServletRequestMatcherRegistry> servletPattern = new LinkedHashMap<>();

		AuthorizationManagerRequestMatcherRegistry(ApplicationContext context) {
			super(context);
		}

		private void addMapping(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.isTrue(this.servletPattern.isEmpty(),
					"Since you have used forServletPattern, all request matchers must be configured using forServletPattern; alternatively, you can use requestMatchers(RequestMatcher) for all requests.");
			this.unmappedMatchers = null;
			this.managerBuilder.add(matcher, manager);
			this.mappingCount++;
		}

		private void addFirst(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.isTrue(this.servletPattern.isEmpty(),
					"Since you have used forServletPattern, all request matchers must be configured using forServletPattern; alternatively, you can use requestMatchers(RequestMatcher) for all requests.");
			this.unmappedMatchers = null;
			this.managerBuilder.mappings((m) -> m.add(0, new RequestMatcherEntry<>(matcher, manager)));
			this.mappingCount++;
		}

		private AuthorizationManager<HttpServletRequest> servletAuthorizationManager() {
			for (Map.Entry<String, AuthorizationManagerServletRequestMatcherRegistry> entry : this.servletPattern
				.entrySet()) {
				AuthorizationManagerServletRequestMatcherRegistry registry = entry.getValue();
				this.managerBuilder.add(new ServletPatternRequestMatcher(entry.getKey()),
						registry.authorizationManager());
			}
			return postProcess(this.managerBuilder.build());
		}

		private AuthorizationManager<HttpServletRequest> authorizationManager() {
			Assert.state(this.unmappedMatchers == null,
					() -> "An incomplete mapping was found for " + this.unmappedMatchers
							+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
			Assert.state(this.mappingCount > 0,
					"At least one mapping is required (for example, authorizeHttpRequests().anyRequest().authenticated())");
			return postProcess(this.managerBuilder.build());
		}

		private AuthorizationManager<HttpServletRequest> createAuthorizationManager() {
			AuthorizationManager<HttpServletRequest> manager = (this.servletPattern.isEmpty()) ? authorizationManager()
					: servletAuthorizationManager();
			ObservationRegistry registry = getObservationRegistry();
			if (registry.isNoop()) {
				return manager;
			}
			return new ObservationAuthorizationManager<>(registry, manager);
		}

		@Override
		protected AuthorizedUrl<AuthorizationManagerRequestMatcherRegistry> chainRequestMatchers(
				List<RequestMatcher> requestMatchers) {
			this.unmappedMatchers = requestMatchers;
			return new AuthorizedUrl<>(
					(manager) -> AuthorizeHttpRequestsConfigurer.this.addMapping(requestMatchers, manager));
		}

		/**
		 * Begin registering {@link RequestMatcher}s based on the type of the servlet
		 * mapped to {@code pattern}. Each registered request matcher will additionally
		 * check {@link HttpServletMapping#getPattern} against the provided
		 * {@code pattern}.
		 *
		 * <p>
		 * If the corresponding servlet is of type {@link DispatcherServlet}, then use a
		 * {@link AuthorizationManagerServletRequestMatcherRegistry} that registers
		 * {@link MvcRequestMatcher}s.
		 *
		 * <p>
		 * Otherwise, use a configurer that registers {@link AntPathRequestMatcher}s.
		 *
		 * <p>
		 * When doing a path-based pattern, like `/path/*`, registered URIs should leave
		 * out the matching path. For example, if the target URI is `/path/resource/3`,
		 * then the configuration should look like this: <code>
		 *	.forServletPattern("/path/*", (path) -> path
		 *      .requestMatchers("/resource/3").hasAuthority(...)
		 *  )
		 * </code>
		 *
		 * <p>
		 * Or, if the pattern is `/path/subpath/*`, and the URI is
		 * `/path/subpath/resource/3`, then the configuration should look like this:
		 * <code>
		 *	.forServletPattern("/path/subpath/*", (path) -> path
		 *      .requestMatchers("/resource/3").hasAuthority(...)
		 *  )
		 * </code>
		 *
		 * <p>
		 * For all other patterns, please supply the URI in absolute terms. For example,
		 * if the target URI is `/js/**` and it matches to the default servlet, then the
		 * configuration should look like this: <code>
		 * 	.forServletPattern("/", (root) -> root
		 * 	    .requestMatchers("/js/**").hasAuthority(...)
		 * 	)
		 * </code>
		 *
		 * <p>
		 * Or, if the target URI is `/views/**`, and it matches to a `*.jsp` extension
		 * servlet, then the configuration should look like this: <code>
		 * 	.forServletPattern("*.jsp", (jsp) -> jsp
		 * 	    .requestMatchers("/views/**").hasAuthority(...)
		 * 	)
		 * </code>
		 * @param customizer a customizer that uses a
		 * {@link AuthorizationManagerServletRequestMatcherRegistry} for URIs mapped to
		 * the provided servlet
		 * @return an {@link AuthorizationManagerServletRequestMatcherRegistry} for
		 * further configurations
		 * @since 6.2
		 */
		public AuthorizationManagerRequestMatcherRegistry forServletPattern(String pattern,
				Customizer<AuthorizationManagerServletRequestMatcherRegistry> customizer) {
			ApplicationContext context = getApplicationContext();
			RequestMatcherBuilder builder = RequestMatcherBuilders.createForServletPattern(context, pattern);
			AuthorizationManagerServletRequestMatcherRegistry registry = new AuthorizationManagerServletRequestMatcherRegistry(
					builder);
			customizer.customize(registry);
			this.servletPattern.put(pattern, registry);
			return this;
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
		 * @deprecated Permit access to the {@link jakarta.servlet.DispatcherType}
		 * instead. <pre>
		 * &#064;Configuration
		 * &#064;EnableWebSecurity
		 * public class SecurityConfig {
		 *
		 * 	&#064;Bean
		 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		 * 		http
		 * 		 	.authorizeHttpRequests((authorize) -&gt; authorize
		 * 				.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
		 * 			 	// ...
		 * 		 	);
		 * 		return http.build();
		 * 	}
		 * }
		 * </pre>
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public AuthorizationManagerRequestMatcherRegistry shouldFilterAllDispatcherTypes(boolean shouldFilter) {
			this.shouldFilterAllDispatcherTypes = shouldFilter;
			return this;
		}

		/**
		 * Return the {@link HttpSecurityBuilder} when done using the
		 * {@link AuthorizeHttpRequestsConfigurer}. This is useful for method chaining.
		 * @return the {@link HttpSecurityBuilder} for further customizations
		 * @deprecated For removal in 7.0. Use the lambda based configuration instead.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public H and() {
			return AuthorizeHttpRequestsConfigurer.this.and();
		}

		/**
		 * A decorator class for registering {@link RequestMatcher} instances based on the
		 * type of servlet. If the servlet is {@link DispatcherServlet}, then it will use
		 * a {@link MvcRequestMatcher}; otherwise, it will use a
		 * {@link AntPathRequestMatcher}.
		 *
		 * <p>
		 * This class is designed primarily for use with the {@link HttpSecurity} DSL. For
		 * that reason, please use {@link HttpSecurity#authorizeHttpRequests} instead as
		 * it exposes this class fluently alongside related DSL configurations.
		 *
		 * <p>
		 * NOTE: In many cases, which kind of request matcher is needed is apparent by the
		 * servlet configuration, and so you should generally use the methods found in
		 * {@link AbstractRequestMatcherRegistry} instead of this these. Use this class
		 * when you want or need to indicate which request matcher URIs belong to which
		 * servlet.
		 *
		 * <p>
		 * In all cases, though, you may arrange your request matchers by servlet pattern
		 * with the {@link AuthorizationManagerRequestMatcherRegistry#forServletPattern}
		 * method in the {@link HttpSecurity#authorizeHttpRequests} DSL.
		 *
		 * <p>
		 * Consider, for example, the circumstance where you have Spring MVC configured
		 * and also Spring Boot H2 Console. Spring MVC registers a servlet of type
		 * {@link DispatcherServlet} as the default servlet and Spring Boot registers a
		 * servlet of its own as well at `/h2-console/*`.
		 *
		 * <p>
		 * Such might have a configuration like this in Spring Security: <code>
		 * 	http
		 * 		.authorizeHttpRequests((authorize) -> authorize
		 * 			.requestMatchers("/js/**", "/css/**").permitAll()
		 * 			.requestMatchers("/my/controller/**").hasAuthority("CONTROLLER")
		 * 			.requestMatchers("/h2-console/**").hasAuthority("H2")
		 * 		)
		 * 		// ...
		 * </code>
		 *
		 * <p>
		 * Spring Security by default addresses the above configuration on its own.
		 *
		 * <p>
		 * However, consider the same situation, but where {@link DispatcherServlet} is
		 * mapped to a path like `/mvc/*`. In this case, the above configuration is
		 * ambiguous, and you should use this class to clarify the rest of each MVC URI
		 * like so: <code>
		 * 	http
		 * 		.authorizeHttpRequests((authorize) -> authorize
		 * 			.forServletPattern("/", (root) -> root
		 * 				.requestMatchers("/js/**", "/css/**").permitAll()
		 * 			)
		 * 			.forServletPattern("/mvc/*", (mvc) -> mvc
		 * 				.requestMatchers("/my/controller/**").hasAuthority("CONTROLLER")
		 * 			)
		 * 			.forServletPattern("/h2-console/*", (h2) -> h2
		 * 				.anyRequest().hasAuthority("OTHER")
		 * 			)
		 * 		)
		 * 		// ...
		 * </code>
		 *
		 * <p>
		 * In the above configuration, it's now clear to Spring Security that the
		 * following matchers map to these corresponding URIs:
		 *
		 * <ul>
		 * <li>&lt;default&gt; + <strong>`/js/**`</strong> ==> `/js/**`</li>
		 * <li>&lt;default&gt; + <strong>`/css/**`</strong> ==> `/css/**`</li>
		 * <li>`/mvc` + <strong>`/my/controller/**`</strong> ==>
		 * `/mvc/my/controller/**`</li>
		 * <li>`/h2-console` + <strong>&lt;any request&gt;</strong> ==>
		 * `/h2-console/**`</li>
		 * </ul>
		 *
		 * @author Josh Cummings
		 * @since 6.2
		 * @see AbstractRequestMatcherRegistry
		 * @see AuthorizeHttpRequestsConfigurer
		 */
		public final class AuthorizationManagerServletRequestMatcherRegistry extends
				AbstractRequestMatcherBuilderRegistry<AuthorizedUrl<AuthorizationManagerServletRequestMatcherRegistry>> {

			private final RequestMatcherDelegatingAuthorizationManager.Builder managerBuilder = RequestMatcherDelegatingAuthorizationManager
				.builder();

			private List<RequestMatcher> unmappedMatchers;

			AuthorizationManagerServletRequestMatcherRegistry(RequestMatcherBuilder builder) {
				super(AuthorizationManagerRequestMatcherRegistry.this.getApplicationContext(), builder);
			}

			AuthorizationManager<RequestAuthorizationContext> authorizationManager() {
				Assert.state(this.unmappedMatchers == null,
						() -> "An incomplete mapping was found for " + this.unmappedMatchers
								+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
				AuthorizationManager<HttpServletRequest> request = this.managerBuilder.build();
				return (authentication, context) -> request.check(authentication, context.getRequest());
			}

			@Override
			protected AuthorizedUrl<AuthorizationManagerServletRequestMatcherRegistry> chainRequestMatchers(
					List<RequestMatcher> requestMatchers) {
				this.unmappedMatchers = requestMatchers;
				return new AuthorizedUrl<>((manager) -> addMapping(requestMatchers, manager));
			}

			private AuthorizationManagerServletRequestMatcherRegistry addMapping(List<RequestMatcher> matchers,
					AuthorizationManager<RequestAuthorizationContext> manager) {
				this.unmappedMatchers = null;
				for (RequestMatcher matcher : matchers) {
					this.managerBuilder.add(matcher, manager);
				}
				return this;
			}

		}

	}

	/**
	 * An object that allows configuring the {@link AuthorizationManager} for
	 * {@link RequestMatcher}s.
	 *
	 * @author Evgeniy Cheban
	 */
	public class AuthorizedUrl<R> {

		private final Function<AuthorizationManager<RequestAuthorizationContext>, R> registrar;

		AuthorizedUrl(Function<AuthorizationManager<RequestAuthorizationContext>, R> registrar) {
			this.registrar = registrar;
		}

		/**
		 * Specify that URLs are allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R permitAll() {
			return access(permitAllAuthorizationManager);
		}

		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R denyAll() {
			return access((a, o) -> new AuthorizationDecision(false));
		}

		/**
		 * Specifies a user requires a role.
		 * @param role the role that should be required which is prepended with ROLE_
		 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
		 * @return {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R hasRole(String role) {
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
		public R hasAnyRole(String... roles) {
			return access(withRoleHierarchy(
					AuthorityAuthorizationManager.hasAnyRole(AuthorizeHttpRequestsConfigurer.this.rolePrefix, roles)));
		}

		/**
		 * Specifies a user requires an authority.
		 * @param authority the authority that should be required
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R hasAuthority(String authority) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager.hasAuthority(authority)));
		}

		/**
		 * Specifies that a user requires one of many authorities.
		 * @param authorities the authorities that the user should have at least one of
		 * (i.e. ROLE_USER, ROLE_ADMIN, etc)
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R hasAnyAuthority(String... authorities) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager.hasAnyAuthority(authorities)));
		}

		private AuthorityAuthorizationManager<RequestAuthorizationContext> withRoleHierarchy(
				AuthorityAuthorizationManager<RequestAuthorizationContext> manager) {
			manager.setRoleHierarchy(AuthorizeHttpRequestsConfigurer.this.roleHierarchy.get());
			return manager;
		}

		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R authenticated() {
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
		public R fullyAuthenticated() {
			return access(AuthenticatedAuthorizationManager.fullyAuthenticated());
		}

		/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		public R rememberMe() {
			return access(AuthenticatedAuthorizationManager.rememberMe());
		}

		/**
		 * Specify that URLs are allowed by anonymous users.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 */
		public R anonymous() {
			return access(AuthenticatedAuthorizationManager.anonymous());
		}

		/**
		 * Allows specifying a custom {@link AuthorizationManager}.
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public R access(AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.notNull(manager, "manager cannot be null");
			return this.registrar.apply(manager);
		}

	}

}
