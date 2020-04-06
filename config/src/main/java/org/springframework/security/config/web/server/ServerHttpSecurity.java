/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.web.server;

import static org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerFormLoginAuthenticationConverter;
import org.springframework.security.web.server.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ReactorContextWebFilter;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.header.CacheControlServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.ServerHttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.ServerRequestCacheWebFilter;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.server.ui.LogoutPageGeneratingWebFilter;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;


/**
 * A {@link ServerHttpSecurity} is similar to Spring Security's {@code HttpSecurity} but for WebFlux.
 * It allows configuring web based security for specific http requests. By default it will be applied
 * to all requests, but can be restricted using {@link #securityMatcher(ServerWebExchangeMatcher)} or
 * other similar methods.
 *
 * A minimal configuration can be found below:
 *
 * <pre class="code">
 * &#064;EnableWebFluxSecurity
 * public class MyMinimalSecurityConfiguration {
 *
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *          UserDetails user = User.withDefaultPasswordEncoder()
 *               .username("user")
 *               .password("password")
 *               .roles("USER")
 *               .build();
 *          return new MapReactiveUserDetailsService(user);
 *     }
 * }
 *
 * Below is the same as our minimal configuration, but explicitly declaring the
 * {@code ServerHttpSecurity}.
 *
 * <pre class="code">
 * &#064;EnableWebFluxSecurity
 * public class MyExplicitSecurityConfiguration {
 *     &#064;Bean
 *     public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
 *          http
 *               .authorizeExchange()
 *                    .anyExchange().authenticated()
 *                         .and()
 *                    .httpBasic().and()
 *                    .formLogin();
 *          return http.build();
 *     }
 *
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *          UserDetails user = User.withDefaultPasswordEncoder()
 *               .username("user")
 *               .password("password")
 *               .roles("USER")
 *               .build();
 *          return new MapReactiveUserDetailsService(user);
 *     }
 * }
 *
 * @author Rob Winch
 * @since 5.0
 */
public class ServerHttpSecurity {
	private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

	private AuthorizeExchangeSpec authorizeExchange;

	private HeaderSpec headers = new HeaderSpec();

	private CsrfSpec csrf = new CsrfSpec();

	private ExceptionHandlingSpec exceptionHandling = new ExceptionHandlingSpec();

	private HttpBasicSpec httpBasic;

	private final RequestCacheSpec requestCache = new RequestCacheSpec();

	private FormLoginSpec formLogin;

	private LogoutSpec logout = new LogoutSpec();

	private ReactiveAuthenticationManager authenticationManager;

	private ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();

	private ServerAuthenticationEntryPoint authenticationEntryPoint;

	private List<DelegateEntry> defaultEntryPoints = new ArrayList<>();

	private ServerAccessDeniedHandler accessDeniedHandler;

	private List<WebFilter> webFilters = new ArrayList<>();

	private Throwable built;

	/**
	 * The ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *
	 * @param matcher the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *                Default is all requests.
	 */
	public ServerHttpSecurity securityMatcher(ServerWebExchangeMatcher matcher) {
		Assert.notNull(matcher, "matcher cannot be null");
		this.securityMatcher = matcher;
		return this;
	}

	/**
	 * Adds a {@link WebFilter} at a specific position.
	 * @param webFilter the {@link WebFilter} to add
	 * @param order the place to insert the {@link WebFilter}
	 * @return the {@link ServerHttpSecurity} to continue configuring
	 */
	public ServerHttpSecurity addFilterAt(WebFilter webFilter, SecurityWebFiltersOrder order) {
		this.webFilters.add(new OrderedWebFilter(webFilter, order.getOrder()));
		return this;
	}

	/**
	 * Gets the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 * @return the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 */
	private ServerWebExchangeMatcher getSecurityMatcher() {
		return this.securityMatcher;
	}

	/**
	 * The strategy used with {@code ReactorContextWebFilter}. It does not impact how the {@code SecurityContext} is
	 * saved which is configured on a per {@link AuthenticationWebFilter} basis.
	 * @param securityContextRepository the repository to use
	 * @return the {@link ServerHttpSecurity} to continue configuring
	 */
	public ServerHttpSecurity securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
		return this;
	}

	/**
	 * Configures <a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet">CSRF Protection</a>
	 * which is enabled by default. You can disable it using:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .csrf().disabled();
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * Additional configuration options can be seen below:
	 *
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .csrf()
	 *              // Handle CSRF failures
	 *              .accessDeniedHandler(accessDeniedHandler)
	 *              // Custom persistence of CSRF Token
	 *              .csrfTokenRepository(csrfTokenRepository)
	 *              // custom matching when CSRF protection is enabled
	 *              .requireCsrfProtectionMatcher(matcher);
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link CsrfSpec} to customize
	 */
	public CsrfSpec csrf() {
		if(this.csrf == null) {
			this.csrf = new CsrfSpec();
		}
		return this.csrf;
	}

	/**
	 * Configures HTTP Basic authentication. An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .httpBasic()
	 *              // used for authenticating the credentials
	 *              .authenticationManager(authenticationManager)
	 *              // Custom persistence of the authentication
	 *              .securityContextRepository(securityContextRepository);
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link HttpBasicSpec} to customize
	 */
	public HttpBasicSpec httpBasic() {
		if(this.httpBasic == null) {
			this.httpBasic = new HttpBasicSpec();
		}
		return this.httpBasic;
	}

	/**
	 * Configures form based authentication. An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .formLogin()
	 *              // used for authenticating the credentials
	 *              .authenticationManager(authenticationManager)
	 *              // Custom persistence of the authentication
	 *              .securityContextRepository(securityContextRepository)
	 *              // expect a log in page at "/authenticate"
	 *              // a POST "/authenticate" is where authentication occurs
	 *              // error page at "/authenticate?error"
	 *              .formLogin("/authenticate");
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link FormLoginSpec} to customize
	 */
	public FormLoginSpec formLogin() {
		if(this.formLogin == null) {
			this.formLogin = new FormLoginSpec();
		}
		return this.formLogin;
	}

	/**
	 * Configures HTTP Response Headers. The default headers are:
	 *
	 * <pre>
	 * Cache-Control: no-cache, no-store, max-age=0, must-revalidate
	 * Pragma: no-cache
	 * Expires: 0
	 * X-Content-Type-Options: nosniff
	 * Strict-Transport-Security: max-age=31536000 ; includeSubDomains
	 * X-Frame-Options: DENY
	 * X-XSS-Protection: 1; mode=block
	 * </pre>
	 *
	 * such that "Strict-Transport-Security" is only added on secure requests.
	 *
	 * An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .headers()
	 *              // customize frame options to be same origin
	 *              .frameOptions()
	 *                  .mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN)
	 *                  .and()
	 *              // disable cache control
	 *              .cache().disable();
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link HeaderSpec} to customize
	 */
	public HeaderSpec headers() {
		if(this.headers == null) {
			this.headers = new HeaderSpec();
		}
		return this.headers;
	}

	/**
	 * Configures exception handling (i.e. handles when authentication is requested). An example configuration can
	 * be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .exceptionHandling()
	 *              // customize how to request for authentication
	 *              .authenticationEntryPoint(entryPoint);
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link ExceptionHandlingSpec} to customize
	 */
	public ExceptionHandlingSpec exceptionHandling() {
		if(this.exceptionHandling == null) {
			this.exceptionHandling = new ExceptionHandlingSpec();
		}
		return this.exceptionHandling;
	}

	/**
	 * Configures authorization. An example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .authorizeExchange()
	 *              // any URL that starts with /admin/ requires the role "ROLE_ADMIN"
	 *              .pathMatchers("/admin/**").hasRole("ADMIN")
	 *              // a POST to /users requires the role "USER_POST"
	 *              .pathMatchers(HttpMethod.POST, "/users").hasAuthority("USER_POST")
	 *              // a request to /users/{username} requires the current authentication's username
	 *              // to be equal to the {username}
	 *              .pathMatchers("/users/{username}").access((authentication, context) ->
	 *                  authentication
	 *                      .map(Authentication::getName)
	 *                      .map(username -> username.equals(context.getVariables().get("username")))
	 *                      .map(AuthorizationDecision::new)
	 *              )
	 *              // allows providing a custom matching strategy that requires the role "ROLE_CUSTOM"
	 *              .matchers(customMatcher).hasRole("CUSTOM")
	 *              // any other request requires the user to be authenticated
	 *              .anyExchange().authenticated();
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link AuthorizeExchangeSpec} to customize
	 */
	public AuthorizeExchangeSpec authorizeExchange() {
		if(this.authorizeExchange == null) {
			this.authorizeExchange = new AuthorizeExchangeSpec();
		}
		return this.authorizeExchange;
	}

	/**
	 * Configures log out. An example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .logout()
	 *              // configures how log out is done
	 *              .logoutHandler(logoutHandler)
	 *              // log out will be performed on POST /signout
	 *              .logoutUrl("/signout")
	 *              // configure what is done on logout success
	 *              .logoutSuccessHandler(successHandler);
	 *      return http.build();
	 *  }
	 * </pre>
	 * @return the {@link LogoutSpec} to customize
	 */
	public LogoutSpec logout() {
		if (this.logout == null) {
			this.logout = new LogoutSpec();
		}
		return this.logout;
	}

	/**
	 * Configures the request cache which is used when a flow is interrupted (i.e. due to requesting credentials) so
	 * that the request can be replayed after authentication. An example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .requestCache()
	 *              // configures how the request is cached
	 *              .requestCache(requestCache);
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * @return the {@link RequestCacheSpec} to customize
	 */
	public RequestCacheSpec requestCache() {
		return this.requestCache;
	}

	/**
	 * Configure the default authentication manager.
	 * @param manager the authentication manager to use
	 * @return the {@code ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity authenticationManager(ReactiveAuthenticationManager manager) {
		this.authenticationManager = manager;
		return this;
	}

	/**
	 * Builds the {@link SecurityWebFilterChain}
	 * @return the {@link SecurityWebFilterChain
	 */
	public SecurityWebFilterChain build() {
		if(this.built != null) {
			throw new IllegalStateException("This has already been built with the following stacktrace. " + buildToString());
		}
		this.built = new RuntimeException("First Build Invocation").fillInStackTrace();
		if(this.headers != null) {
			this.headers.configure(this);
		}
		WebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
		if(securityContextRepositoryWebFilter != null) {
			this.webFilters.add(securityContextRepositoryWebFilter);
		}
		if(this.csrf != null) {
			this.csrf.configure(this);
		}
		if(this.httpBasic != null) {
			this.httpBasic.authenticationManager(this.authenticationManager);
			this.httpBasic.configure(this);
		}
		if(this.formLogin != null) {
			this.formLogin.authenticationManager(this.authenticationManager);
			if(this.securityContextRepository != null) {
				this.formLogin.securityContextRepository(this.securityContextRepository);
			}
			if(this.formLogin.authenticationEntryPoint == null) {
				this.webFilters.add(new OrderedWebFilter(new LoginPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING.getOrder()));
				this.webFilters.add(new OrderedWebFilter(new LogoutPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGOUT_PAGE_GENERATING.getOrder()));
			}
			this.formLogin.configure(this);
		}
		if(this.logout != null) {
			this.logout.configure(this);
		}
		this.requestCache.configure(this);
		this.addFilterAt(new SecurityContextServerWebExchangeWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE);
		if(this.authorizeExchange != null) {
			ServerAuthenticationEntryPoint authenticationEntryPoint = getAuthenticationEntryPoint();
			ExceptionTranslationWebFilter exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
			if(authenticationEntryPoint != null) {
				exceptionTranslationWebFilter.setAuthenticationEntryPoint(
					authenticationEntryPoint);
			}
			if(accessDeniedHandler != null) {
				exceptionTranslationWebFilter.setAccessDeniedHandler(accessDeniedHandler);
			}
			this.addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
			this.authorizeExchange.configure(this);
		}
		AnnotationAwareOrderComparator.sort(this.webFilters);
		List<WebFilter> sortedWebFilters = new ArrayList<>();
		this.webFilters.forEach( f -> {
			if(f instanceof OrderedWebFilter) {
				f = ((OrderedWebFilter) f).webFilter;
			}
			sortedWebFilters.add(f);
		});
		return new MatcherSecurityWebFilterChain(getSecurityMatcher(), sortedWebFilters);
	}

	private String buildToString() {
		try(StringWriter writer = new StringWriter()) {
			try(PrintWriter printer = new PrintWriter(writer)) {
				printer.println();
				printer.println();
				this.built.printStackTrace(printer);
				printer.println();
				printer.println();
				return writer.toString();
			}
		} catch(IOException e) {
			throw new RuntimeException(e);
		}
	}

	private ServerAuthenticationEntryPoint getAuthenticationEntryPoint() {
		if(this.authenticationEntryPoint != null || this.defaultEntryPoints.isEmpty()) {
			return this.authenticationEntryPoint;
		}
		if(this.defaultEntryPoints.size() == 1) {
			return this.defaultEntryPoints.get(0).getEntryPoint();
		}
		DelegatingServerAuthenticationEntryPoint result = new DelegatingServerAuthenticationEntryPoint(this.defaultEntryPoints);
		result.setDefaultEntryPoint(this.defaultEntryPoints.get(this.defaultEntryPoints.size() - 1).getEntryPoint());
		return result;
	}

	/**
	 * Creates a new instance.
	 * @return the new {@link ServerHttpSecurity} instance
	 */
	public static ServerHttpSecurity http() {
		return new ServerHttpSecurity();
	}

	private WebFilter securityContextRepositoryWebFilter() {
		ServerSecurityContextRepository repository = this.securityContextRepository;
		if(repository == null) {
			return null;
		}
		WebFilter result = new ReactorContextWebFilter(repository);
		return new OrderedWebFilter(result, SecurityWebFiltersOrder.REACTOR_CONTEXT.getOrder());
	}

	private ServerHttpSecurity() {}

	/**
	 * Configures authorization
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #authorizeExchange()
	 */
	public class AuthorizeExchangeSpec
		extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeSpec.Access> {
		private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager.builder();
		private ServerWebExchangeMatcher matcher;
		private boolean anyExchangeRegistered;

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables authorization.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		@Override
		public Access anyExchange() {
			Access result = super.anyExchange();
			this.anyExchangeRegistered = true;
			return result;
		}

		@Override
		protected Access registerMatcher(ServerWebExchangeMatcher matcher) {
			if(this.anyExchangeRegistered) {
				throw new IllegalStateException("Cannot register " + matcher + " which would be unreachable because anyExchange() has already been registered.");
			}
			if(this.matcher != null) {
				throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
			}
			this.matcher = matcher;
			return new Access();
		}

		protected void configure(ServerHttpSecurity http) {
			if(this.matcher != null) {
				throw new IllegalStateException("The matcher " + this.matcher + " does not have an access rule defined");
			}
			AuthorizationWebFilter result = new AuthorizationWebFilter(this.managerBldr.build());
			http.addFilterAt(result, SecurityWebFiltersOrder.AUTHORIZATION);
		}

		/**
		 * Configures the access for a particular set of exchanges.
		 */
		public final class Access {

			/**
			 * Allow access for anyone
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec permitAll() {
				return access( (a, e) -> Mono.just(new AuthorizationDecision(true)));
			}

			/**
			 * Deny access for everyone
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec denyAll() {
				return access( (a, e) -> Mono.just(new AuthorizationDecision(false)));
			}

			/**
			 * Require a specific role. This is a shorcut for {@link #hasAuthority(String)}
			 * @param role the role (i.e. "USER" would require "ROLE_USER")
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasRole(String role) {
				return access(AuthorityReactiveAuthorizationManager.hasRole(role));
			}

			/**
			 * Require a specific authority.
			 * @param authority the authority to require (i.e. "USER" would require authority of "USER").
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasAuthority(String authority) {
				return access(AuthorityReactiveAuthorizationManager.hasAuthority(authority));
			}

			/**
			 * Require an authenticated user
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec authenticated() {
				return access(AuthenticatedReactiveAuthorizationManager.authenticated());
			}

			/**
			 * Allows plugging in a custom authorization strategy
			 * @param manager the authorization manager to use
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
				AuthorizeExchangeSpec.this.managerBldr
					.add(new ServerWebExchangeMatcherEntry<>(
						AuthorizeExchangeSpec.this.matcher, manager));
				AuthorizeExchangeSpec.this.matcher = null;
				return AuthorizeExchangeSpec.this;
			}
		}
	}

	/**
	 * Configures <a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet">CSRF Protection</a>
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #csrf()
	 */
	public class CsrfSpec {
		private CsrfWebFilter filter = new CsrfWebFilter();

		/**
		 * Configures the {@link ServerAccessDeniedHandler} used when a CSRF token is invalid. Default is
		 * to send an {@link org.springframework.http.HttpStatus#FORBIDDEN}.
		 *
		 * @param accessDeniedHandler the access denied handler.
		 * @return the {@link CsrfSpec} for additional configuration
		 */
		public CsrfSpec accessDeniedHandler(
			ServerAccessDeniedHandler accessDeniedHandler) {
			this.filter.setAccessDeniedHandler(accessDeniedHandler);
			return this;
		}

		/**
		 * Configures the {@link ServerCsrfTokenRepository} used to persist the CSRF Token. Default is
		 * {@link org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository}.
		 *
		 * @param csrfTokenRepository the repository to use
		 * @return the {@link CsrfSpec} for additional configuration
		 */
		public CsrfSpec csrfTokenRepository(
			ServerCsrfTokenRepository csrfTokenRepository) {
			this.filter.setCsrfTokenRepository(csrfTokenRepository);
			return this;
		}

		/**
		 * Configures the {@link ServerWebExchangeMatcher} used to determine when CSRF protection is enabled. Default is
		 * PUT, POST, DELETE requests.
		 *
		 * @param requireCsrfProtectionMatcher the matcher to use
		 * @return the {@link CsrfSpec} for additional configuration
		 */
		public CsrfSpec requireCsrfProtectionMatcher(
			ServerWebExchangeMatcher requireCsrfProtectionMatcher) {
			this.filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables CSRF Protection. Disabling CSRF Protection is only recommended when the application is never used
		 * within a browser.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.csrf = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			http.addFilterAt(this.filter, SecurityWebFiltersOrder.CSRF);
		}

		private CsrfSpec() {}
	}

	/**
	 * Configures exception handling
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #exceptionHandling()
	 */
	public class ExceptionHandlingSpec {

		/**
		 * Configures what to do when the application request authentication
		 * @param authenticationEntryPoint the entry point to use
		 * @return the {@link ExceptionHandlingSpec} to configure
		 */
		public ExceptionHandlingSpec authenticationEntryPoint(ServerAuthenticationEntryPoint authenticationEntryPoint) {
			ServerHttpSecurity.this.authenticationEntryPoint = authenticationEntryPoint;
			return this;
		}

		/**
		 * Configures what to do when an authenticated user does not hold a required authority
		 * @param accessDeniedHandler the access denied handler to use
		 * @return the {@link ExceptionHandlingSpec} to configure
		 *
		 * @since 5.0.5
		 */
		public ExceptionHandlingSpec accessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
			ServerHttpSecurity.this.accessDeniedHandler = accessDeniedHandler;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		private ExceptionHandlingSpec() {}
	}

	/**
	 * Configures the request cache which is used when a flow is interrupted (i.e. due to requesting credentials) so
	 * that the request can be replayed after authentication.
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #requestCache()
	 */
	public class RequestCacheSpec {
		private ServerRequestCache requestCache = new WebSessionServerRequestCache();

		/**
		 * Configures the cache used
		 * @param requestCache the request cache
		 * @return the {@link RequestCacheSpec} to configure
		 */
		public RequestCacheSpec requestCache(ServerRequestCache requestCache) {
			Assert.notNull(requestCache, "requestCache cannot be null");
			this.requestCache = requestCache;
			return this;
		}

		protected void configure(ServerHttpSecurity http) {
			ServerRequestCacheWebFilter filter = new ServerRequestCacheWebFilter();
			filter.setRequestCache(this.requestCache);
			http.addFilterAt(filter, SecurityWebFiltersOrder.SERVER_REQUEST_CACHE);
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables the {@link RequestCacheSpec}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			this.requestCache = NoOpServerRequestCache.getInstance();
			return and();
		}

		private RequestCacheSpec() {}
	}

	/**
	 * Configures HTTP Basic Authentication
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #httpBasic()
	 */
	public class HttpBasicSpec {
		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository.getInstance();

		private ServerAuthenticationEntryPoint entryPoint = new HttpBasicServerAuthenticationEntryPoint();

		/**
		 * The {@link ReactiveAuthenticationManager} used to authenticate. Defaults to
		 * {@link ServerHttpSecurity#authenticationManager(ReactiveAuthenticationManager)}.
		 *
		 * @param authenticationManager the authentication manager to use
		 * @return the {@link HttpBasicSpec} to continue configuring
		 */
		public HttpBasicSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * The {@link ServerSecurityContextRepository} used to save the {@code Authentication}. Defaults to
		 * {@link NoOpServerSecurityContextRepository}. For the {@code SecurityContext} to be loaded on subsequent
		 * requests the {@link ReactorContextWebFilter} must be configured to be able to load the value (they are not
		 * implicitly linked).
		 *
		 * @param securityContextRepository the repository to use
		 * @return the {@link HttpBasicSpec} to continue configuring
		 */
		public HttpBasicSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables HTTP Basic authentication.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.httpBasic = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			MediaTypeServerWebExchangeMatcher restMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.APPLICATION_ATOM_XML,
				MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML,
				MediaType.MULTIPART_FORM_DATA, MediaType.TEXT_XML);
			restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerHttpSecurity.this.defaultEntryPoints.add(new DelegateEntry(restMatcher, this.entryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(this.entryPoint));
			authenticationFilter.setAuthenticationConverter(new ServerHttpBasicAuthenticationConverter());
			if(this.securityContextRepository != null) {
				authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			}
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);
		}

		private HttpBasicSpec() {}
	}

	/**
	 * Configures Form Based authentication
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #formLogin()
	 */
	public class FormLoginSpec {
		private final RedirectServerAuthenticationSuccessHandler defaultSuccessHandler = new RedirectServerAuthenticationSuccessHandler("/");

		private RedirectServerAuthenticationEntryPoint defaultEntryPoint;

		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();

		private ServerAuthenticationEntryPoint authenticationEntryPoint;

		private ServerWebExchangeMatcher requiresAuthenticationMatcher;

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private ServerAuthenticationSuccessHandler authenticationSuccessHandler = this.defaultSuccessHandler;

		/**
		 * The {@link ReactiveAuthenticationManager} used to authenticate. Defaults to
		 * {@link ServerHttpSecurity#authenticationManager(ReactiveAuthenticationManager)}.
		 *
		 * @param authenticationManager the authentication manager to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 */
		public FormLoginSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * The {@link ServerAuthenticationSuccessHandler} used after authentication success. Defaults to
		 * {@link RedirectServerAuthenticationSuccessHandler}.
		 * @param authenticationSuccessHandler the success handler to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 */
		public FormLoginSpec authenticationSuccessHandler(
			ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
			Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
			this.authenticationSuccessHandler = authenticationSuccessHandler;
			return this;
		}

		/**
		 * Configures the log in page to redirect to, the authentication failure page, and when authentication is
		 * performed. The default is that Spring Security will generate a log in page at "/login" and a log out page at
		 * "/logout". If this is customized:
		 * <ul>
		 * <li>The default log in & log out page are no longer provided</li>
		 * <li>The application must render a log in page at the provided URL</li>
		 * <li>The application must render an authentication error page at the provided URL + "?error"</li>
		 * <li>Authentication will occur for POST to the provided URL</li>
		 * </ul>
		 * @param loginPage the url to redirect to which provides a form to log in (i.e. "/login")
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @see #authenticationEntryPoint(ServerAuthenticationEntryPoint)
		 * @see #requiresAuthenticationMatcher(ServerWebExchangeMatcher)
		 * @see #authenticationFailureHandler(ServerAuthenticationFailureHandler)
		 */
		public FormLoginSpec loginPage(String loginPage) {
			this.defaultEntryPoint = new RedirectServerAuthenticationEntryPoint(loginPage);
			this.authenticationEntryPoint = this.defaultEntryPoint;
			this.requiresAuthenticationMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, loginPage);
			this.authenticationFailureHandler = new RedirectServerAuthenticationFailureHandler(loginPage + "?error");
			return this;
		}

		/**
		 * How to request for authentication. The default is that Spring Security will
		 * generate a log in page at "/login".
		 * @param authenticationEntryPoint the entry point to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @see #loginPage(String)
		 */
		public FormLoginSpec authenticationEntryPoint(ServerAuthenticationEntryPoint authenticationEntryPoint) {
			this.authenticationEntryPoint = authenticationEntryPoint;
			return this;
		}

		/**
		 * Configures when authentication is performed. The default is a POST to "/login".
		 * @param requiresAuthenticationMatcher the matcher to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @see #loginPage(String)
		 */
		public FormLoginSpec requiresAuthenticationMatcher(ServerWebExchangeMatcher requiresAuthenticationMatcher) {
			this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
			return this;
		}

		/**
		 * Configures how a failed authentication is handled. The default is to redirect to "/login?error".
		 * @param authenticationFailureHandler the handler to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @see #loginPage(String)
		 */
		public FormLoginSpec authenticationFailureHandler(ServerAuthenticationFailureHandler authenticationFailureHandler) {
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		/**
		 * The {@link ServerSecurityContextRepository} used to save the {@code Authentication}. Defaults to
		 * {@link NoOpServerSecurityContextRepository}. For the {@code SecurityContext} to be loaded on subsequent
		 * requests the {@link ReactorContextWebFilter} must be configured to be able to load the value (they are not
		 * implicitly linked).
		 *
		 * @param securityContextRepository the repository to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 */
		public FormLoginSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables HTTP Basic authentication.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.formLogin = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			if(this.authenticationEntryPoint == null) {
				loginPage("/login");
			}
			if(http.requestCache != null) {
				ServerRequestCache requestCache = http.requestCache.requestCache;
				this.defaultSuccessHandler.setRequestCache(requestCache);
				if(this.defaultEntryPoint != null) {
					this.defaultEntryPoint.setRequestCache(requestCache);
				}
			}
			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.TEXT_HTML);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerHttpSecurity.this.defaultEntryPoints.add(0, new DelegateEntry(htmlMatcher, this.authenticationEntryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setRequiresAuthenticationMatcher(this.requiresAuthenticationMatcher);
			authenticationFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
			authenticationFilter.setAuthenticationConverter(new ServerFormLoginAuthenticationConverter());
			authenticationFilter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
			authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.FORM_LOGIN);
		}

		private FormLoginSpec() {
		}
	}

	/**
	 * Configures HTTP Response Headers.
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #headers()
	 */
	public class HeaderSpec {
		private final List<ServerHttpHeadersWriter> writers;

		private CacheControlServerHttpHeadersWriter cacheControl = new CacheControlServerHttpHeadersWriter();

		private ContentTypeOptionsServerHttpHeadersWriter contentTypeOptions = new ContentTypeOptionsServerHttpHeadersWriter();

		private StrictTransportSecurityServerHttpHeadersWriter hsts = new StrictTransportSecurityServerHttpHeadersWriter();

		private XFrameOptionsServerHttpHeadersWriter frameOptions = new XFrameOptionsServerHttpHeadersWriter();

		private XXssProtectionServerHttpHeadersWriter xss = new XXssProtectionServerHttpHeadersWriter();

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables http response headers
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.headers = null;
			return ServerHttpSecurity.this;
		}

		/**
		 * Configures cache control headers
		 * @return the {@link CacheSpec} to configure
		 */
		public CacheSpec cache() {
			return new CacheSpec();
		}

		/**
		 * Configures content type response headers
		 * @return the {@link ContentTypeOptionsSpec} to configure
		 */
		public ContentTypeOptionsSpec contentTypeOptions() {
			return new ContentTypeOptionsSpec();
		}

		/**
		 * Configures frame options response headers
		 * @return the {@link FrameOptionsSpec} to configure
		 */
		public FrameOptionsSpec frameOptions() {
			return new FrameOptionsSpec();
		}

		/**
		 * Configures the Strict Transport Security response headers
		 * @return the {@link HstsSpec} to configure
		 */
		public HstsSpec hsts() {
			return new HstsSpec();
		}

		protected void configure(ServerHttpSecurity http) {
			ServerHttpHeadersWriter writer = new CompositeServerHttpHeadersWriter(this.writers);
			HttpHeaderWriterWebFilter result = new HttpHeaderWriterWebFilter(writer);
			http.addFilterAt(result, SecurityWebFiltersOrder.HTTP_HEADERS_WRITER);
		}

		/**
		 * Configures x-xss-protection response header.
		 * @return the {@link XssProtectionSpec} to configure
		 */
		public XssProtectionSpec xssProtection() {
			return new XssProtectionSpec();
		}

		/**
		 * Configures cache control headers
		 * @see #cache()
		 */
		public class CacheSpec {
			/**
			 * Disables cache control response headers
			 * @return the {@link HeaderSpec} to configure
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.cacheControl);
				return HeaderSpec.this;
			}

			private CacheSpec() {}
		}

		/**
		 * The content type headers
		 * @see #contentTypeOptions()
		 */
		public class ContentTypeOptionsSpec {
			/**
			 * Disables the content type options response header
			 * @return the {@link HeaderSpec} to configure
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.contentTypeOptions);
				return HeaderSpec.this;
			}

			private ContentTypeOptionsSpec() {}
		}

		/**
		 * Configures frame options response header
		 * @see #frameOptions()
		 */
		public class FrameOptionsSpec {
			/**
			 * The mode to configure. Default is
			 * {@link org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode#DENY}
			 * @param mode the mode to use
			 * @return the {@link FrameOptionsSpec} to configure
			 */
			public FrameOptionsSpec mode(XFrameOptionsServerHttpHeadersWriter.Mode mode) {
				HeaderSpec.this.frameOptions.setMode(mode);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

			/**
			 * Disables frame options response header
			 * @return the {@link ServerHttpSecurity} to continue configuring
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.frameOptions);
				return HeaderSpec.this;
			}

			private FrameOptionsSpec() {}
		}

		/**
		 * Configures Strict Transport Security response header
		 * @see #hsts()
		 */
		public class HstsSpec {
			/**
			 * Configures the max age. Default is one year.
			 * @param maxAge the max age
			 */
			public void maxAge(Duration maxAge) {
				HeaderSpec.this.hsts.setMaxAge(maxAge);
			}

			/**
			 * Configures if subdomains should be included. Default is true
			 * @param includeSubDomains if subdomains should be included
			 */
			public void includeSubdomains(boolean includeSubDomains) {
				HeaderSpec.this.hsts.setIncludeSubDomains(includeSubDomains);
			}

			/**
			 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

			/**
			 * Disables strict transport security response header
			 * @return the {@link ServerHttpSecurity} to continue configuring
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.hsts);
				return HeaderSpec.this;
			}

			private HstsSpec() {}
		}

		/**
		 * Configures x-xss-protection response header
		 * @see #xssProtection()
		 */
		public class XssProtectionSpec {
			/**
			 * Disables the x-xss-protection response header
			 * @return
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.xss);
				return HeaderSpec.this;
			}

			private XssProtectionSpec() {}
		}

		private HeaderSpec() {
			this.writers = new ArrayList<>(
				Arrays.asList(this.cacheControl, this.contentTypeOptions, this.hsts,
					this.frameOptions, this.xss));
		}
	}

	/**
	 * Configures log out
	 * @author Shazin Sadakath
	 * @since 5.0
	 * @see #logout()
	 */
	public final class LogoutSpec {
		private LogoutWebFilter logoutWebFilter = new LogoutWebFilter();

		/**
		 * Configures the logout handler. Default is {@code SecurityContextServerLogoutHandler}
		 * @param logoutHandler
		 * @return
		 */
		public LogoutSpec logoutHandler(ServerLogoutHandler logoutHandler) {
			this.logoutWebFilter.setLogoutHandler(logoutHandler);
			return this;
		}

		/**
		 * Configures what URL a POST to will trigger a log out.
		 * @param logoutUrl the url to trigger a log out (i.e. "/signout" would mean a POST to "/signout" would trigger
		 * log out)
		 * @return the {@link LogoutSpec} to configure
		 */
		public LogoutSpec logoutUrl(String logoutUrl) {
			Assert.notNull(logoutUrl, "logoutUrl must not be null");
			ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, logoutUrl);
			return requiresLogout(requiresLogout);
		}

		/**
		 * Configures when the log out will be triggered.
		 * @param requiresLogout the matcher to determine when log out is triggered
		 * @return the {@link LogoutSpec} to configure
		 */
		public LogoutSpec requiresLogout(ServerWebExchangeMatcher requiresLogout) {
			this.logoutWebFilter.setRequiresLogoutMatcher(requiresLogout);
			return this;
		}

		public LogoutSpec logoutSuccessHandler(ServerLogoutSuccessHandler handler) {
			this.logoutWebFilter.setLogoutSuccessHandler(handler);
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables log out
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.logout = null;
			return and();
		}

		protected void configure(ServerHttpSecurity http) {
			http.addFilterAt(this.logoutWebFilter, SecurityWebFiltersOrder.LOGOUT);
		}

		private LogoutSpec() {}
	}

	private static class OrderedWebFilter implements WebFilter, Ordered {
		private final WebFilter webFilter;
		private final int order;

		public OrderedWebFilter(WebFilter webFilter, int order) {
			this.webFilter = webFilter;
			this.order = order;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange,
			WebFilterChain chain) {
			return this.webFilter.filter(exchange, chain);
		}

		@Override
		public int getOrder() {
			return this.order;
		}

		@Override
		public String toString() {
			return "OrderedWebFilter{" + "webFilter=" + this.webFilter + ", order=" + this.order
				+ '}';
		}
	}
}
