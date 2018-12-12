/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.web.server;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationCodeGrantWebFilter;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AnonymousAuthenticationWebFilter;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerFormLoginAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ReactorContextWebFilter;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfServerLogoutHandler;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository;
import org.springframework.security.web.server.header.CacheControlServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.FeaturePolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.header.ServerHttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.ServerRequestCacheWebFilter;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.transport.HttpsRedirectWebFilter;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.server.ui.LogoutPageGeneratingWebFilter;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsProcessor;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.DefaultCorsProcessor;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult.match;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult.notMatch;

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
 * @author Vedran Pavic
 * @since 5.0
 */
public class ServerHttpSecurity {
	private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

	private AuthorizeExchangeSpec authorizeExchange;

	private HttpsRedirectSpec httpsRedirectSpec;

	private HeaderSpec headers = new HeaderSpec();

	private CsrfSpec csrf = new CsrfSpec();

	private CorsSpec cors = new CorsSpec();

	private ExceptionHandlingSpec exceptionHandling = new ExceptionHandlingSpec();

	private HttpBasicSpec httpBasic;

	private final RequestCacheSpec requestCache = new RequestCacheSpec();

	private FormLoginSpec formLogin;

	private OAuth2LoginSpec oauth2Login;

	private OAuth2ResourceServerSpec resourceServer;

	private OAuth2ClientSpec client;

	private LogoutSpec logout = new LogoutSpec();

	private LoginPageSpec loginPage = new LoginPageSpec();

	private ReactiveAuthenticationManager authenticationManager;

	private ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();

	private ServerAuthenticationEntryPoint authenticationEntryPoint;

	private List<DelegateEntry> defaultEntryPoints = new ArrayList<>();

	private ServerAccessDeniedHandler accessDeniedHandler;

	private List<ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry>
			defaultAccessDeniedHandlers = new ArrayList<>();

	private List<WebFilter> webFilters = new ArrayList<>();

	private ApplicationContext context;

	private Throwable built;

	private AnonymousSpec anonymous;

	/**
	 * The ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *
	 * @param matcher the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *                Default is all requests.
	 * @return the {@link ServerHttpSecurity} to continue configuring
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
	 * Adds a {@link WebFilter} before specific position.
	 * @param webFilter the {@link WebFilter} to add
	 * @param order the place before which to insert the {@link WebFilter}
	 * @return the {@link ServerHttpSecurity} to continue configuring
	 * @since 5.2.0
	 * @author Ankur Pathak
	 */
	public ServerHttpSecurity addFilterBefore(WebFilter webFilter, SecurityWebFiltersOrder order) {
		this.webFilters.add(new OrderedWebFilter(webFilter, order.getOrder() - 1));
		return this;
	}

	/**
	 * Adds a {@link WebFilter} after specific position.
	 * @param webFilter the {@link WebFilter} to add
	 * @param order the place after which to insert the {@link WebFilter}
	 * @return the {@link ServerHttpSecurity} to continue configuring
	 * @since 5.2.0
	 * @author Ankur Pathak
	 */
	public ServerHttpSecurity addFilterAfter(WebFilter webFilter, SecurityWebFiltersOrder order) {
		this.webFilters.add(new OrderedWebFilter(webFilter, order.getOrder() + 1));
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
	 * Configures HTTPS redirection rules. If the default is used:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 * 	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 * 	    http
	 * 	        // ...
	 * 	        .redirectToHttps();
	 * 	    return http.build();
	 * 	}
	 * </pre>
	 *
	 * Then all non-HTTPS requests will be redirected to HTTPS.
	 *
	 * Typically, all requests should be HTTPS; however, the focus for redirection can also be narrowed:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 * 	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 * 	    http
	 * 	        // ...
	 * 	        .redirectToHttps()
	 * 	            .httpsRedirectWhen(serverWebExchange ->
	 * 	            	serverWebExchange.getRequest().getHeaders().containsKey("X-Requires-Https"))
	 * 	    return http.build();
	 * 	}
	 * </pre>
	 *
	 * @return the {@link HttpsRedirectSpec} to customize
	 */
	public HttpsRedirectSpec redirectToHttps() {
		this.httpsRedirectSpec = new HttpsRedirectSpec();
		return this.httpsRedirectSpec;
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
		if (this.csrf == null) {
			this.csrf = new CsrfSpec();
		}
		return this.csrf;
	}

	/**
	 * Configures CORS headers. By default if a {@link CorsConfigurationSource} Bean is found, it will be used
	 * to create a {@link CorsWebFilter}. If {@link CorsSpec#configurationSource(CorsConfigurationSource)} is invoked
	 * it will be used instead. If neither has been configured, the Cors configuration will do nothing.
	 * @return the {@link CorsSpec} to customize
	 */
	public CorsSpec cors() {
		if (this.cors == null) {
			this.cors = new CorsSpec();
		}
		return this.cors;
	}

	/**
	 * @since 5.2.0
	 * @author Ankur Pathak
	 * Enables and Configures annonymous authentication. Anonymous Authentication is disabled by default.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .anonymous().key("key")
	 *          .authorities("ROLE_ANONYMOUS");
	 *      return http.build();
	 *  }
	 * </pre>
	 */
	public AnonymousSpec anonymous(){
		if (this.anonymous == null) {
			this.anonymous = new AnonymousSpec();
		}
		return this.anonymous;
	}

	/**
	 * Configures CORS support within Spring Security. This ensures that the {@link CorsWebFilter} is place in the
	 * correct order.
	 */
	public class CorsSpec {
		private CorsWebFilter corsFilter;

		/**
		 * Configures the {@link CorsConfigurationSource} to be used
		 * @param source the source to use
		 * @return the {@link CorsSpec} for additional configuration
		 */
		public CorsSpec configurationSource(CorsConfigurationSource source) {
			this.corsFilter = new CorsWebFilter(source);
			return this;
		}

		/**
		 * Disables CORS support within Spring Security.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.cors = null;
			return ServerHttpSecurity.this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			CorsWebFilter corsFilter = getCorsFilter();
			if (corsFilter != null) {
				http.addFilterAt(this.corsFilter, SecurityWebFiltersOrder.CORS);
			}
		}

		private CorsWebFilter getCorsFilter() {
			if (this.corsFilter != null) {
				return this.corsFilter;
			}

			CorsConfigurationSource source = getBeanOrNull(CorsConfigurationSource.class);
			if (source == null) {
				return null;
			}
			CorsProcessor processor = getBeanOrNull(CorsProcessor.class);
			if (processor == null) {
				processor = new DefaultCorsProcessor();
			}
			this.corsFilter = new CorsWebFilter(source, processor);
			return this.corsFilter;
		}

		private CorsSpec() {}
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
		if (this.httpBasic == null) {
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
		if (this.formLogin == null) {
			this.formLogin = new FormLoginSpec();
		}
		return this.formLogin;
	}

	public OAuth2LoginSpec oauth2Login() {
		if (this.oauth2Login == null) {
			this.oauth2Login = new OAuth2LoginSpec();
		}
		return this.oauth2Login;
	}

	public class OAuth2LoginSpec {
		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

		private ReactiveAuthenticationManager authenticationManager;

		private ServerAuthenticationConverter authenticationConverter;

		/**
		 * Configures the {@link ReactiveAuthenticationManager} to use. The default is
		 * {@link OAuth2AuthorizationCodeReactiveAuthenticationManager}
		 * @param authenticationManager the manager to use
		 * @return the {@link OAuth2LoginSpec} to customize
		 */
		public OAuth2LoginSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * Gets the {@link ReactiveAuthenticationManager} to use. First tries an explicitly configured manager, and
		 * defaults to {@link OAuth2AuthorizationCodeReactiveAuthenticationManager}
		 *
		 * @return the {@link ReactiveAuthenticationManager} to use
		 */
		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				this.authenticationManager = createDefault();
			}
			return this.authenticationManager;
		}

		private ReactiveAuthenticationManager createDefault() {
			WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
			ReactiveAuthenticationManager result = new OAuth2LoginReactiveAuthenticationManager(client, getOauth2UserService());

			boolean oidcAuthenticationProviderEnabled = ClassUtils.isPresent(
					"org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());
			if (oidcAuthenticationProviderEnabled) {
				OidcAuthorizationCodeReactiveAuthenticationManager oidc =
						new OidcAuthorizationCodeReactiveAuthenticationManager(client, getOidcUserService());
				ResolvableType type = ResolvableType.forClassWithGenerics(
						ReactiveJwtDecoderFactory.class, ClientRegistration.class);
				ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory = getBeanOrNull(type);
				if (jwtDecoderFactory != null) {
					oidc.setJwtDecoderFactory(jwtDecoderFactory);
				}
				result = new DelegatingReactiveAuthenticationManager(oidc, result);
			}
			return result;
		}

		/**
		 * Sets the converter to use
		 * @param authenticationConverter the converter to use
		 * @return the {@link OAuth2LoginSpec} to customize
		 */
		public OAuth2LoginSpec authenticationConverter(ServerAuthenticationConverter authenticationConverter) {
			this.authenticationConverter = authenticationConverter;
			return this;
		}

		private ServerAuthenticationConverter getAuthenticationConverter(ReactiveClientRegistrationRepository clientRegistrationRepository) {
			if (this.authenticationConverter == null) {
				this.authenticationConverter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(clientRegistrationRepository);
			}
			return this.authenticationConverter;
		}

		public OAuth2LoginSpec clientRegistrationRepository(ReactiveClientRegistrationRepository clientRegistrationRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
			return this;
		}

		public OAuth2LoginSpec authorizedClientService(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
			this.authorizedClientRepository = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(authorizedClientService);
			return this;
		}

		public OAuth2LoginSpec authorizedClientRepository(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.authorizedClientRepository = authorizedClientRepository;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}


		protected void configure(ServerHttpSecurity http) {
			ReactiveClientRegistrationRepository clientRegistrationRepository = getClientRegistrationRepository();
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository = getAuthorizedClientRepository();
			OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter = new OAuth2AuthorizationRequestRedirectWebFilter(clientRegistrationRepository);

			ReactiveAuthenticationManager manager = getAuthenticationManager();

			AuthenticationWebFilter authenticationFilter = new OAuth2LoginAuthenticationWebFilter(manager, authorizedClientRepository);
			authenticationFilter.setRequiresAuthenticationMatcher(createAttemptAuthenticationRequestMatcher());
			authenticationFilter.setServerAuthenticationConverter(getAuthenticationConverter(clientRegistrationRepository));
			RedirectServerAuthenticationSuccessHandler redirectHandler = new RedirectServerAuthenticationSuccessHandler();

			authenticationFilter.setAuthenticationSuccessHandler(redirectHandler);
			authenticationFilter.setAuthenticationFailureHandler(new ServerAuthenticationFailureHandler() {
				@Override
				public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange,
						AuthenticationException exception) {
					return Mono.error(exception);
				}
			});
			authenticationFilter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());

			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
					MediaType.TEXT_HTML);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			Map<String, String> urlToText = http.oauth2Login.getLinks();
			if (urlToText.size() == 1) {
				http.defaultEntryPoints.add(new DelegateEntry(htmlMatcher, new RedirectServerAuthenticationEntryPoint(urlToText.keySet().iterator().next())));
			} else {
				http.defaultEntryPoints.add(new DelegateEntry(htmlMatcher, new RedirectServerAuthenticationEntryPoint("/login")));
			}

			http.addFilterAt(oauthRedirectFilter, SecurityWebFiltersOrder.HTTP_BASIC);
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);
		}

		private ServerWebExchangeMatcher createAttemptAuthenticationRequestMatcher() {
			PathPatternParserServerWebExchangeMatcher loginPathMatcher = new PathPatternParserServerWebExchangeMatcher("/login/oauth2/code/{registrationId}");
			ServerWebExchangeMatcher notAuthenticatedMatcher = e  -> ReactiveSecurityContextHolder.getContext()
					.flatMap(p -> ServerWebExchangeMatcher.MatchResult.notMatch())
					.switchIfEmpty(ServerWebExchangeMatcher.MatchResult.match());
			return new AndServerWebExchangeMatcher(loginPathMatcher, notAuthenticatedMatcher);
		}

		private ReactiveOAuth2UserService<OidcUserRequest, OidcUser> getOidcUserService() {
			ResolvableType type = ResolvableType.forClassWithGenerics(ReactiveOAuth2UserService.class, OidcUserRequest.class, OidcUser.class);
			ReactiveOAuth2UserService<OidcUserRequest, OidcUser> bean = getBeanOrNull(type);
			if (bean == null) {
				return new OidcReactiveOAuth2UserService();
			}

			return bean;
		}

		private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> getOauth2UserService() {
			ResolvableType type = ResolvableType.forClassWithGenerics(ReactiveOAuth2UserService.class, OAuth2UserRequest.class, OAuth2User.class);
			ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> bean = getBeanOrNull(type);
			if (bean == null) {
				return new DefaultReactiveOAuth2UserService();
			}

			return bean;
		}

		private Map<String, String> getLinks() {
			Iterable<ClientRegistration> registrations = getBeanOrNull(ResolvableType.forClassWithGenerics(Iterable.class, ClientRegistration.class));
			if (registrations == null) {
				return Collections.emptyMap();
			}
			Map<String, String> result = new HashMap<>();
			registrations.iterator().forEachRemaining(r -> {
				result.put("/oauth2/authorization/" + r.getRegistrationId(), r.getClientName());
			});
			return result;
		}

		private ReactiveClientRegistrationRepository getClientRegistrationRepository() {
			if (this.clientRegistrationRepository == null) {
				this.clientRegistrationRepository = getBeanOrNull(ReactiveClientRegistrationRepository.class);
			}
			return this.clientRegistrationRepository;
		}

		private ServerOAuth2AuthorizedClientRepository getAuthorizedClientRepository() {
			ServerOAuth2AuthorizedClientRepository result = this.authorizedClientRepository;
			if (result == null) {
				result = getBeanOrNull(ServerOAuth2AuthorizedClientRepository.class);
			}
			if (result == null) {
				ReactiveOAuth2AuthorizedClientService authorizedClientService = getAuthorizedClientService();
				if (authorizedClientService != null) {
					result = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
							authorizedClientService);
				}
			}
			return result;
		}

		private ReactiveOAuth2AuthorizedClientService getAuthorizedClientService() {
			ReactiveOAuth2AuthorizedClientService service = getBeanOrNull(ReactiveOAuth2AuthorizedClientService.class);
			if (service == null) {
				service = new InMemoryReactiveOAuth2AuthorizedClientService(getClientRegistrationRepository());
			}
			return service;
		}

		private OAuth2LoginSpec() {}
	}

	/**
	 * Configures the OAuth2 client.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oauth2Client()
	 *              .clientRegistrationRepository(clientRegistrationRepository)
	 *              .authorizedClientRepository(authorizedClientRepository);
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 *
	 * @return the {@link OAuth2ClientSpec} to customize
	 */
	public OAuth2ClientSpec oauth2Client() {
		if (this.client == null) {
			this.client = new OAuth2ClientSpec();
		}
		return this.client;
	}

	public class OAuth2ClientSpec {
		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ServerAuthenticationConverter authenticationConverter;

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

		private ReactiveAuthenticationManager authenticationManager;

		/**
		 * Sets the converter to use
		 * @param authenticationConverter the converter to use
		 * @return the {@link OAuth2ClientSpec} to customize
		 */
		public OAuth2ClientSpec authenticationConverter(ServerAuthenticationConverter authenticationConverter) {
			this.authenticationConverter = authenticationConverter;
			return this;
		}

		private ServerAuthenticationConverter getAuthenticationConverter() {
			if (this.authenticationConverter == null) {
				this.authenticationConverter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(getClientRegistrationRepository());
			}
			return this.authenticationConverter;
		}

		/**
		 * Configures the {@link ReactiveAuthenticationManager} to use. The default is
		 * {@link OAuth2AuthorizationCodeReactiveAuthenticationManager}
		 * @param authenticationManager the manager to use
		 * @return the {@link OAuth2ClientSpec} to customize
		 */
		public OAuth2ClientSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * Gets the {@link ReactiveAuthenticationManager} to use. First tries an explicitly configured manager, and
		 * defaults to {@link OAuth2AuthorizationCodeReactiveAuthenticationManager}
		 *
		 * @return the {@link ReactiveAuthenticationManager} to use
		 */
		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				this.authenticationManager = new OAuth2AuthorizationCodeReactiveAuthenticationManager(new WebClientReactiveAuthorizationCodeTokenResponseClient());
			}
			return this.authenticationManager;
		}

		/**
		 * Configures the {@link ReactiveClientRegistrationRepository}. Default is to look the value up as a Bean.
		 * @param clientRegistrationRepository the repository to use
		 * @return the {@link OAuth2ClientSpec} to customize
		 */
		public OAuth2ClientSpec clientRegistrationRepository(ReactiveClientRegistrationRepository clientRegistrationRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
			return this;
		}

		/**
		 * Configures the {@link ReactiveClientRegistrationRepository}. Default is to look the value up as a Bean.
		 * @param authorizedClientRepository the repository to use
		 * @return the {@link OAuth2ClientSpec} to customize
		 */
		public OAuth2ClientSpec authorizedClientRepository(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.authorizedClientRepository = authorizedClientRepository;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			ReactiveClientRegistrationRepository clientRegistrationRepository = getClientRegistrationRepository();
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository = getAuthorizedClientRepository();
			ServerAuthenticationConverter authenticationConverter = getAuthenticationConverter();
			ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
			OAuth2AuthorizationCodeGrantWebFilter codeGrantWebFilter = new OAuth2AuthorizationCodeGrantWebFilter(authenticationManager,
					authenticationConverter,
					authorizedClientRepository);

			OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter = new OAuth2AuthorizationRequestRedirectWebFilter(
					clientRegistrationRepository);
			http.addFilterAt(codeGrantWebFilter, SecurityWebFiltersOrder.OAUTH2_AUTHORIZATION_CODE);
			http.addFilterAt(oauthRedirectFilter, SecurityWebFiltersOrder.HTTP_BASIC);
		}

		private ReactiveClientRegistrationRepository getClientRegistrationRepository() {
			if (this.clientRegistrationRepository != null) {
				return this.clientRegistrationRepository;
			}
			return getBeanOrNull(ReactiveClientRegistrationRepository.class);
		}

		private ServerOAuth2AuthorizedClientRepository getAuthorizedClientRepository() {
			if (this.authorizedClientRepository != null) {
				return this.authorizedClientRepository;
			}
			ServerOAuth2AuthorizedClientRepository result = getBeanOrNull(ServerOAuth2AuthorizedClientRepository.class);
			if (result == null) {
				ReactiveOAuth2AuthorizedClientService authorizedClientService = getAuthorizedClientService();
				if (authorizedClientService != null) {
					result = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
							authorizedClientService);
				}
			}
			return result;
		}

		private ReactiveOAuth2AuthorizedClientService getAuthorizedClientService() {
			ReactiveOAuth2AuthorizedClientService service = getBeanOrNull(ReactiveOAuth2AuthorizedClientService.class);
			if (service == null) {
				service = new InMemoryReactiveOAuth2AuthorizedClientService(getClientRegistrationRepository());
			}
			return service;
		}

		private OAuth2ClientSpec() {}
	}

	public OAuth2ResourceServerSpec oauth2ResourceServer() {
		if (this.resourceServer == null) {
			this.resourceServer = new OAuth2ResourceServerSpec();
		}
		return this.resourceServer;
	}

	/**
	 * Configures OAuth2 Resource Server Support
	 */
	public class OAuth2ResourceServerSpec {
		private ServerAuthenticationEntryPoint entryPoint = new BearerTokenServerAuthenticationEntryPoint();
		private ServerAccessDeniedHandler accessDeniedHandler = new BearerTokenServerAccessDeniedHandler();
		private ServerAuthenticationConverter bearerTokenConverter = new ServerBearerTokenAuthenticationConverter();

		private JwtSpec jwt;

		/**
		 * Configures the {@link ServerAccessDeniedHandler} to use for requests authenticating with
		 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s.
		 * requests.
		 *
		 * @param accessDeniedHandler the {@link ServerAccessDeniedHandler} to use
		 * @return the {@link OAuth2ResourceServerSpec} for additional configuration
		 * @since 5.2
		 */
		public OAuth2ResourceServerSpec accessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
			Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
			this.accessDeniedHandler = accessDeniedHandler;
			return this;
		}

		/**
		 * Configures the {@link ServerAuthenticationEntryPoint} to use for requests authenticating with
		 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s.
		 *
		 * @param entryPoint the {@link ServerAuthenticationEntryPoint} to use
		 * @return the {@link OAuth2ResourceServerSpec} for additional configuration
		 * @since 5.2
		 */
		public OAuth2ResourceServerSpec authenticationEntryPoint(ServerAuthenticationEntryPoint entryPoint) {
			Assert.notNull(entryPoint, "entryPoint cannot be null");
			this.entryPoint = entryPoint;
			return this;
		}

		/**
		 * Configures the {@link ServerAuthenticationConverter} to use for requests authenticating with
		 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s.
		 *
		 * @param bearerTokenConverter The {@link ServerAuthenticationConverter} to use
		 * @return The {@link OAuth2ResourceServerSpec} for additional configuration
		 * @since 5.2
		 */
		public OAuth2ResourceServerSpec bearerTokenConverter(ServerAuthenticationConverter bearerTokenConverter) {
			Assert.notNull(bearerTokenConverter, "bearerTokenConverter cannot be null");
			this.bearerTokenConverter = bearerTokenConverter;
			return this;
		}

		public JwtSpec jwt() {
			if (this.jwt == null) {
				this.jwt = new JwtSpec();
			}
			return this.jwt;
		}

		protected void configure(ServerHttpSecurity http) {
			if (this.jwt != null) {
				this.jwt.configure(http);
			}
		}

		/**
		 * Configures JWT Resource Server Support
		 */
		public class JwtSpec {
			private ReactiveAuthenticationManager authenticationManager;
			private ReactiveJwtDecoder jwtDecoder;
			private Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter
					= new ReactiveJwtAuthenticationConverterAdapter(new JwtAuthenticationConverter());

			private BearerTokenServerWebExchangeMatcher bearerTokenServerWebExchangeMatcher =
					new BearerTokenServerWebExchangeMatcher();

			/**
			 * Configures the {@link ReactiveAuthenticationManager} to use
			 * @param authenticationManager the authentication manager to use
			 * @return the {@code JwtSpec} for additional configuration
			 */
			public JwtSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
				Assert.notNull(authenticationManager, "authenticationManager cannot be null");
				this.authenticationManager = authenticationManager;
				return this;
			}

			/**
			 * Configures the {@link Converter} to use for converting a {@link Jwt} into
			 * an {@link AbstractAuthenticationToken}.
			 *
			 * @param jwtAuthenticationConverter the converter to use
			 * @return the {@code JwtSpec} for additional configuration
			 * @since 5.1.1
			 */
			public JwtSpec jwtAuthenticationConverter
					(Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
				Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null");
				this.jwtAuthenticationConverter = jwtAuthenticationConverter;
				return this;
			}

			/**
			 * Configures the {@link ReactiveJwtDecoder} to use
			 * @param jwtDecoder the decoder to use
			 * @return the {@code JwtSpec} for additional configuration
			 */
			public JwtSpec jwtDecoder(ReactiveJwtDecoder jwtDecoder) {
				this.jwtDecoder = jwtDecoder;
				return this;
			}

			/**
			 * Configures a {@link ReactiveJwtDecoder} that leverages the provided {@link RSAPublicKey}
			 *
			 * @param publicKey the public key to use.
			 * @return the {@code JwtSpec} for additional configuration
			 */
			public JwtSpec publicKey(RSAPublicKey publicKey) {
				this.jwtDecoder = new NimbusReactiveJwtDecoder(publicKey);
				return this;
			}

			/**
			 * Configures a {@link ReactiveJwtDecoder} using
			 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a> URL
			 * @param jwkSetUri the URL to use.
			 * @return the {@code JwtSpec} for additional configuration
			 */
			public JwtSpec jwkSetUri(String jwkSetUri) {
				this.jwtDecoder = new NimbusReactiveJwtDecoder(jwkSetUri);
				return this;
			}

			public OAuth2ResourceServerSpec and() {
				return OAuth2ResourceServerSpec.this;
			}

			protected void configure(ServerHttpSecurity http) {
				this.bearerTokenServerWebExchangeMatcher.setBearerTokenConverter(bearerTokenConverter);

				registerDefaultAccessDeniedHandler(http);
				registerDefaultAuthenticationEntryPoint(http);
				registerDefaultCsrfOverride(http);

				ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
				AuthenticationWebFilter oauth2 = new AuthenticationWebFilter(authenticationManager);
				oauth2.setServerAuthenticationConverter(bearerTokenConverter);
				oauth2.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(entryPoint));

				http
					.addFilterAt(oauth2, SecurityWebFiltersOrder.AUTHENTICATION);
			}

			protected ReactiveJwtDecoder getJwtDecoder() {
				if (this.jwtDecoder == null) {
					return getBean(ReactiveJwtDecoder.class);
				}
				return this.jwtDecoder;
			}

			protected Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>
					getJwtAuthenticationConverter() {

				return this.jwtAuthenticationConverter;
			}

			private ReactiveAuthenticationManager getAuthenticationManager() {
				if (this.authenticationManager != null) {
					return this.authenticationManager;
				}

				ReactiveJwtDecoder jwtDecoder = getJwtDecoder();
				Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter =
						getJwtAuthenticationConverter();
				JwtReactiveAuthenticationManager authenticationManager =
						new JwtReactiveAuthenticationManager(jwtDecoder);
				authenticationManager.setJwtAuthenticationConverter(jwtAuthenticationConverter);

				return authenticationManager;
			}

			private void registerDefaultAccessDeniedHandler(ServerHttpSecurity http) {
				if ( http.exceptionHandling != null ) {
					http.defaultAccessDeniedHandlers.add(
							new ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
									this.bearerTokenServerWebExchangeMatcher,
									OAuth2ResourceServerSpec.this.accessDeniedHandler
							)
					);
				}
			}

			private void registerDefaultAuthenticationEntryPoint(ServerHttpSecurity http) {
				if (http.exceptionHandling != null) {
					http.defaultEntryPoints.add(
							new DelegateEntry(
									this.bearerTokenServerWebExchangeMatcher,
									OAuth2ResourceServerSpec.this.entryPoint
							)
					);
				}
			}

			private void registerDefaultCsrfOverride(ServerHttpSecurity http) {
				if ( http.csrf != null && !http.csrf.specifiedRequireCsrfProtectionMatcher ) {
					http
						.csrf()
							.requireCsrfProtectionMatcher(
									new AndServerWebExchangeMatcher(
											CsrfWebFilter.DEFAULT_CSRF_MATCHER,
											new NegatedServerWebExchangeMatcher(
													this.bearerTokenServerWebExchangeMatcher)));
				}
			}

			private class BearerTokenServerWebExchangeMatcher implements ServerWebExchangeMatcher {
				ServerAuthenticationConverter bearerTokenConverter;

				@Override
				public Mono<MatchResult> matches(ServerWebExchange exchange) {
					return this.bearerTokenConverter.convert(exchange)
							.flatMap(this::nullAuthentication)
							.onErrorResume(e -> notMatch());
				}

				public void setBearerTokenConverter(ServerAuthenticationConverter bearerTokenConverter) {
					Assert.notNull(bearerTokenConverter, "bearerTokenConverter cannot be null");
					this.bearerTokenConverter = bearerTokenConverter;
				}

				private Mono<MatchResult> nullAuthentication(Authentication authentication) {
					return authentication == null ? notMatch() : match();
				}
			}
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}
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
		if (this.headers == null) {
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
		if (this.exceptionHandling == null) {
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
		if (this.authorizeExchange == null) {
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
		if (this.built != null) {
			throw new IllegalStateException("This has already been built with the following stacktrace. " + buildToString());
		}
		this.built = new RuntimeException("First Build Invocation").fillInStackTrace();
		if (this.headers != null) {
			this.headers.configure(this);
		}
		WebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
		if (securityContextRepositoryWebFilter != null) {
			this.webFilters.add(securityContextRepositoryWebFilter);
		}
		if (this.httpsRedirectSpec != null) {
			this.httpsRedirectSpec.configure(this);
		}
		if (this.csrf != null) {
			this.csrf.configure(this);
		}
		if (this.cors != null) {
			this.cors.configure(this);
		}
		if (this.httpBasic != null) {
			this.httpBasic.authenticationManager(this.authenticationManager);
			this.httpBasic.configure(this);
		}
		if (this.formLogin != null) {
			this.formLogin.authenticationManager(this.authenticationManager);
			if (this.securityContextRepository != null) {
				this.formLogin.securityContextRepository(this.securityContextRepository);
			}
			this.formLogin.configure(this);
		}
		if (this.oauth2Login != null) {
			this.oauth2Login.configure(this);
		}
		if (this.resourceServer != null) {
			this.resourceServer.configure(this);
		}
		if (this.client != null) {
			this.client.configure(this);
		}
		if (this.anonymous != null) {
			this.anonymous.configure(this);
		}
		this.loginPage.configure(this);
		if (this.logout != null) {
			this.logout.configure(this);
		}
		this.requestCache.configure(this);
		this.addFilterAt(new SecurityContextServerWebExchangeWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE);
		if (this.authorizeExchange != null) {
			ServerAuthenticationEntryPoint authenticationEntryPoint = getAuthenticationEntryPoint();
			ExceptionTranslationWebFilter exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
			if (authenticationEntryPoint != null) {
				exceptionTranslationWebFilter.setAuthenticationEntryPoint(
					authenticationEntryPoint);
			}
			ServerAccessDeniedHandler accessDeniedHandler = getAccessDeniedHandler();
			if (accessDeniedHandler != null) {
				exceptionTranslationWebFilter.setAccessDeniedHandler(
						accessDeniedHandler);
			}
			this.addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
			this.authorizeExchange.configure(this);
		}
		AnnotationAwareOrderComparator.sort(this.webFilters);
		List<WebFilter> sortedWebFilters = new ArrayList<>();
		this.webFilters.forEach( f -> {
			if (f instanceof OrderedWebFilter) {
				f = ((OrderedWebFilter) f).webFilter;
			}
			sortedWebFilters.add(f);
		});
		sortedWebFilters.add(0, new ServerWebExchangeReactorContextWebFilter());
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
		if (this.authenticationEntryPoint != null || this.defaultEntryPoints.isEmpty()) {
			return this.authenticationEntryPoint;
		}
		if (this.defaultEntryPoints.size() == 1) {
			return this.defaultEntryPoints.get(0).getEntryPoint();
		}
		DelegatingServerAuthenticationEntryPoint result = new DelegatingServerAuthenticationEntryPoint(this.defaultEntryPoints);
		result.setDefaultEntryPoint(this.defaultEntryPoints.get(this.defaultEntryPoints.size() - 1).getEntryPoint());
		return result;
	}

	private ServerAccessDeniedHandler getAccessDeniedHandler() {
		if (this.accessDeniedHandler != null || this.defaultAccessDeniedHandlers.isEmpty()) {
			return this.accessDeniedHandler;
		}
		if (this.defaultAccessDeniedHandlers.size() == 1) {
			return this.defaultAccessDeniedHandlers.get(0).getAccessDeniedHandler();
		}
		ServerWebExchangeDelegatingServerAccessDeniedHandler result =
				new ServerWebExchangeDelegatingServerAccessDeniedHandler(this.defaultAccessDeniedHandlers);
		result.setDefaultAccessDeniedHandler(this.defaultAccessDeniedHandlers
				.get(this.defaultAccessDeniedHandlers.size() - 1).getAccessDeniedHandler());
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
		if (repository == null) {
			return null;
		}
		WebFilter result = new ReactorContextWebFilter(repository);
		return new OrderedWebFilter(result, SecurityWebFiltersOrder.REACTOR_CONTEXT.getOrder());
	}

	protected ServerHttpSecurity() {}

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
		 * @return the {@link Access} to continue configuring
		 */
		@Override
		public Access anyExchange() {
			Access result = super.anyExchange();
			this.anyExchangeRegistered = true;
			return result;
		}

		@Override
		protected Access registerMatcher(ServerWebExchangeMatcher matcher) {
			if (this.anyExchangeRegistered) {
				throw new IllegalStateException("Cannot register " + matcher + " which would be unreachable because anyExchange() has already been registered.");
			}
			if (this.matcher != null) {
				throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
			}
			this.matcher = matcher;
			return new Access();
		}

		protected void configure(ServerHttpSecurity http) {
			if (this.matcher != null) {
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
			 * Require any specific role. This is a shortcut for {@link #hasAnyAuthority(String...)}
			 * @param roles the roles (i.e. "USER" would require "ROLE_USER")
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasAnyRole(String... roles) {
				return access(AuthorityReactiveAuthorizationManager.hasAnyRole(roles));
			}

			/**
			 * Require a specific authority.
			 * @param authority the authority to require (i.e. "USER" woudl require authority of "USER").
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasAuthority(String authority) {
				return access(AuthorityReactiveAuthorizationManager.hasAuthority(authority));
			}

			/**
			 * Require any authority
			 * @param authorities the authorities to require (i.e. "USER" would require authority of "USER").
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasAnyAuthority(String... authorities) {
				return access(AuthorityReactiveAuthorizationManager.hasAnyAuthority(authorities));
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
	 * Configures HTTPS redirection rules
	 *
	 * @author Josh Cummings
	 * @since 5.1
	 * @see #redirectToHttps()
	 */
	public class HttpsRedirectSpec {
		private ServerWebExchangeMatcher serverWebExchangeMatcher;
		private PortMapper portMapper;

		/**
		 * Configures when this filter should redirect to https
		 *
		 * By default, the filter will redirect whenever an exchange's scheme is not https
		 *
		 * @param matchers the list of conditions that, when any are met, the filter should redirect to https
		 * @return the {@link HttpsRedirectSpec} for additional configuration
		 */
		public HttpsRedirectSpec httpsRedirectWhen(ServerWebExchangeMatcher... matchers) {
			this.serverWebExchangeMatcher = new OrServerWebExchangeMatcher(matchers);
			return this;
		}

		/**
		 * Configures when this filter should redirect to https
		 *
		 * By default, the filter will redirect whenever an exchange's scheme is not https
		 *
		 * @param when determines when to redirect to https
		 * @return the {@link HttpsRedirectSpec} for additional configuration
		 */
		public HttpsRedirectSpec httpsRedirectWhen(
				Function<ServerWebExchange, Boolean> when) {
			ServerWebExchangeMatcher matcher = e -> when.apply(e) ?
					ServerWebExchangeMatcher.MatchResult.match() :
					ServerWebExchangeMatcher.MatchResult.notMatch();
			return httpsRedirectWhen(matcher);
		}

		/**
		 * Configures a custom HTTPS port to redirect to
		 *
		 * @param portMapper the {@link PortMapper} to use
		 * @return the {@link HttpsRedirectSpec} for additional configuration
		 */
		public HttpsRedirectSpec portMapper(PortMapper portMapper) {
			this.portMapper = portMapper;
			return this;
		}

		protected void configure(ServerHttpSecurity http) {
			HttpsRedirectWebFilter httpsRedirectWebFilter = new HttpsRedirectWebFilter();
			if (this.serverWebExchangeMatcher != null) {
				httpsRedirectWebFilter.setRequiresHttpsRedirectMatcher(this.serverWebExchangeMatcher);
			}
			if (this.portMapper != null) {
				httpsRedirectWebFilter.setPortMapper(this.portMapper);
			}
			http.addFilterAt(httpsRedirectWebFilter, SecurityWebFiltersOrder.HTTPS_REDIRECT);
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
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
		private ServerCsrfTokenRepository csrfTokenRepository = new WebSessionServerCsrfTokenRepository();

		private boolean specifiedRequireCsrfProtectionMatcher;

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
			this.csrfTokenRepository = csrfTokenRepository;
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
			this.specifiedRequireCsrfProtectionMatcher = true;
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
			Optional.ofNullable(this.csrfTokenRepository).ifPresent(serverCsrfTokenRepository -> {
				this.filter.setCsrfTokenRepository(serverCsrfTokenRepository);
				http.logout().addLogoutHandler(new CsrfServerLogoutHandler(serverCsrfTokenRepository));
			});
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
		 * Allows easily setting the entry point.
		 * @param authenticationEntryPoint the {@link ServerAuthenticationEntryPoint} to use
		 * @return {@link HttpBasicSpec} for additional customization
		 * @since 5.2.0
		 * @author Ankur Pathak
		 */
		public HttpBasicSpec authenticationEntryPoint(ServerAuthenticationEntryPoint authenticationEntryPoint){
			Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
			this.entryPoint = authenticationEntryPoint;
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
			if (this.securityContextRepository != null) {
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

		private boolean isEntryPointExplicit;

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
			if (this.authenticationEntryPoint == null) {
				this.isEntryPointExplicit = false;
				loginPage("/login");
			} else {
				this.isEntryPointExplicit = true;
			}
			if (http.requestCache != null) {
				ServerRequestCache requestCache = http.requestCache.requestCache;
				this.defaultSuccessHandler.setRequestCache(requestCache);
				if (this.defaultEntryPoint != null) {
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

	private class LoginPageSpec {
		protected void configure(ServerHttpSecurity http) {
			if (http.authenticationEntryPoint != null) {
				return;
			}
			if (http.formLogin != null && http.formLogin.isEntryPointExplicit) {
				return;
			}
			LoginPageGeneratingWebFilter loginPage = null;
			if (http.formLogin != null && !http.formLogin.isEntryPointExplicit) {
				loginPage = new LoginPageGeneratingWebFilter();
				loginPage.setFormLoginEnabled(true);
			}
			if (http.oauth2Login != null) {
				Map<String, String> urlToText = http.oauth2Login.getLinks();
				if (loginPage == null) {
					loginPage = new LoginPageGeneratingWebFilter();
				}
				loginPage.setOauth2AuthenticationUrlToClientName(urlToText);
			}
			if (loginPage != null) {
				http.addFilterAt(loginPage, SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING);
				http.addFilterAt(new LogoutPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGOUT_PAGE_GENERATING);
			}
		}

		private LoginPageSpec() {}
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

		private FeaturePolicyServerHttpHeadersWriter featurePolicy = new FeaturePolicyServerHttpHeadersWriter();

		private ContentSecurityPolicyServerHttpHeadersWriter contentSecurityPolicy = new ContentSecurityPolicyServerHttpHeadersWriter();

		private ReferrerPolicyServerHttpHeadersWriter referrerPolicy = new ReferrerPolicyServerHttpHeadersWriter();

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
		 * Configures {@code Content-Security-Policy} response header.
		 * @param policyDirectives the policy directive(s)
		 * @return the {@link ContentSecurityPolicySpec} to configure
		 */
		public ContentSecurityPolicySpec contentSecurityPolicy(String policyDirectives) {
			return new ContentSecurityPolicySpec(policyDirectives);
		}

		/**
		 * Configures {@code Feature-Policy} response header.
		 * @param policyDirectives the policy directive(s)
		 * @return the {@link FeaturePolicySpec} to configure
		 */
		public FeaturePolicySpec featurePolicy(String policyDirectives) {
			return new FeaturePolicySpec(policyDirectives);
		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 * @param referrerPolicy the policy to use
		 * @return the {@link ReferrerPolicySpec} to configure
		 */
		public ReferrerPolicySpec referrerPolicy(ReferrerPolicy referrerPolicy) {
			return new ReferrerPolicySpec(referrerPolicy);
		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 * @return the {@link ReferrerPolicySpec} to configure
		 */
		public ReferrerPolicySpec referrerPolicy() {
			return new ReferrerPolicySpec();
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
			 * @return the {@link HeaderSpec} to configure
			 */
			public HeaderSpec mode(XFrameOptionsServerHttpHeadersWriter.Mode mode) {
				HeaderSpec.this.frameOptions.setMode(mode);
				return and();
			}

			/**
			 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			private HeaderSpec and() {
				return HeaderSpec.this;
			}

			/**
			 * Disables frame options response header
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.frameOptions);
				return and();
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
			 * @return the {@link HstsSpec} to continue configuring
			 */
			public HstsSpec maxAge(Duration maxAge) {
				HeaderSpec.this.hsts.setMaxAge(maxAge);
				return this;
			}

			/**
			 * Configures if subdomains should be included. Default is true
			 * @param includeSubDomains if subdomains should be included
			 * @return the {@link HstsSpec} to continue configuring
			 */
			public HstsSpec includeSubdomains(boolean includeSubDomains) {
				HeaderSpec.this.hsts.setIncludeSubDomains(includeSubDomains);
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
			 * Disables strict transport security response header
			 * @return the {@link HeaderSpec} to continue configuring
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
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.xss);
				return HeaderSpec.this;
			}

			private XssProtectionSpec() {}
		}

		/**
		 * Configures {@code Content-Security-Policy} response header.
		 *
		 * @see #contentSecurityPolicy(String)
		 * @since 5.1
		 */
		public class ContentSecurityPolicySpec {

			/**
			 * Whether to include the {@code Content-Security-Policy-Report-Only} header in
			 * the response. Otherwise, defaults to the {@code Content-Security-Policy} header.
			 * @param reportOnly whether to only report policy violations
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec reportOnly(boolean reportOnly) {
				HeaderSpec.this.contentSecurityPolicy.setReportOnly(reportOnly);
				return HeaderSpec.this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

			private ContentSecurityPolicySpec(String policyDirectives) {
				HeaderSpec.this.contentSecurityPolicy.setPolicyDirectives(policyDirectives);
			}

		}

		/**
		 * Configures {@code Feature-Policy} response header.
		 *
		 * @see #featurePolicy(String)
		 * @since 5.1
		 */
		public class FeaturePolicySpec {

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

			private FeaturePolicySpec(String policyDirectives) {
				HeaderSpec.this.featurePolicy.setPolicyDirectives(policyDirectives);
			}

		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 *
		 * @see #referrerPolicy()
		 * @see #referrerPolicy(ReferrerPolicy)
		 * @since 5.1
		 */
		public class ReferrerPolicySpec {

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

			private ReferrerPolicySpec() {
			}

			private ReferrerPolicySpec(ReferrerPolicy referrerPolicy) {
				HeaderSpec.this.referrerPolicy.setPolicy(referrerPolicy);
			}

		}

		private HeaderSpec() {
			this.writers = new ArrayList<>(
					Arrays.asList(this.cacheControl, this.contentTypeOptions, this.hsts,
							this.frameOptions, this.xss, this.featurePolicy, this.contentSecurityPolicy,
							this.referrerPolicy));
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
		private List<ServerLogoutHandler> logoutHandlers = new ArrayList<>(Arrays.asList(new SecurityContextServerLogoutHandler()));

		/**
		 * Configures the logout handler. Default is {@code SecurityContextServerLogoutHandler}
		 * @param logoutHandler
		 * @return the {@link LogoutSpec} to configure
		 */
		public LogoutSpec logoutHandler(ServerLogoutHandler logoutHandler) {
			Assert.notNull(logoutHandler, "logoutHandler cannot be null");
			this.logoutHandlers.clear();
			return addLogoutHandler(logoutHandler);
		}

		private LogoutSpec addLogoutHandler(ServerLogoutHandler logoutHandler) {
			Assert.notNull(logoutHandler, "logoutHandler cannot be null");
			this.logoutHandlers.add(logoutHandler);
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

		private Optional<ServerLogoutHandler> createLogoutHandler() {
			if (this.logoutHandlers.isEmpty()) {
				return Optional.empty();
			}
			else if (this.logoutHandlers.size() == 1) {
				return Optional.of(this.logoutHandlers.get(0));
			}

			return Optional.of(new DelegatingServerLogoutHandler(this.logoutHandlers));
		}

		protected void configure(ServerHttpSecurity http) {
			createLogoutHandler().ifPresent(this.logoutWebFilter::setLogoutHandler);
			http.addFilterAt(this.logoutWebFilter, SecurityWebFiltersOrder.LOGOUT);
		}

		private LogoutSpec() {}
	}

	private <T> T getBean(Class<T> beanClass) {
		if (this.context == null) {
			return null;
		}
		return this.context.getBean(beanClass);
	}

	private <T> T getBeanOrNull(Class<T> beanClass) {
		return getBeanOrNull(ResolvableType.forClass(beanClass));
	}


	private <T> T getBeanOrNull(ResolvableType type) {
		if (this.context == null) {
			return null;
		}
		String[] names =  this.context.getBeanNamesForType(type);
		if (names.length == 1) {
			return (T) this.context.getBean(names[0]);
		}
		return null;
	}

	protected void setApplicationContext(ApplicationContext applicationContext)
			throws BeansException {
		this.context = applicationContext;
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

	/**
	 * Workaround https://jira.spring.io/projects/SPR/issues/SPR-17213
	 */
	static class ServerWebExchangeReactorContextWebFilter implements WebFilter {
		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange)
					.subscriberContext(Context.of(ServerWebExchange.class, exchange));
		}
	}

	/**
	 * Configures annonymous authentication
	 * @author Ankur Pathak
	 * @since 5.2.0
	 */
	public final class AnonymousSpec {
		private String key;
		private AnonymousAuthenticationWebFilter authenticationFilter;
		private Object principal = "anonymousUser";
		private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");

		/**
		 * Sets the key to identify tokens created for anonymous authentication. Default is a
		 * secure randomly generated key.
		 *
		 * @param key the key to identify tokens created for anonymous authentication. Default
		 * is a secure randomly generated key.
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec key(String key) {
			this.key = key;
			return this;
		}

		/**
		 * Sets the principal for {@link Authentication} objects of anonymous users
		 *
		 * @param principal used for the {@link Authentication} object of anonymous users
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec principal(Object principal) {
			this.principal = principal;
			return this;
		}

		/**
		 * Sets the {@link org.springframework.security.core.Authentication#getAuthorities()}
		 * for anonymous users
		 *
		 * @param authorities Sets the
		 * {@link org.springframework.security.core.Authentication#getAuthorities()} for
		 * anonymous users
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec authorities(List<GrantedAuthority> authorities) {
			this.authorities = authorities;
			return this;
		}

		/**
		 * Sets the {@link org.springframework.security.core.Authentication#getAuthorities()}
		 * for anonymous users
		 *
		 * @param authorities Sets the
		 * {@link org.springframework.security.core.Authentication#getAuthorities()} for
		 * anonymous users (i.e. "ROLE_ANONYMOUS")
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec authorities(String... authorities) {
			return authorities(AuthorityUtils.createAuthorityList(authorities));
		}

		/**
		 * Sets the {@link AnonymousAuthenticationWebFilter} used to populate an anonymous user.
		 * If this is set, no attributes on the {@link AnonymousSpec} will be set on the
		 * {@link AnonymousAuthenticationWebFilter}.
		 *
		 * @param authenticationFilter the {@link AnonymousAuthenticationWebFilter} used to
		 * populate an anonymous user.
		 *
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec authenticationFilter(
				AnonymousAuthenticationWebFilter authenticationFilter) {
			this.authenticationFilter = authenticationFilter;
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
		 * Disables anonymous authentication.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.anonymous = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			if (authenticationFilter == null) {
				authenticationFilter = new AnonymousAuthenticationWebFilter(getKey(), principal,
						authorities);
			}
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.ANONYMOUS_AUTHENTICATION);
		}

		private String getKey() {
			if (key == null) {
				key = UUID.randomUUID().toString();
			}
			return key;
		}


		private AnonymousSpec() {}

	}
}
