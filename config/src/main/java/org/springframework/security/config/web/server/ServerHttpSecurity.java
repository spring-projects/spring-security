/*
 * Copyright 2002-2024 the original author or authors.
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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.reactive.InMemoryReactiveOneTimeTokenService;
import org.springframework.security.authentication.ott.reactive.OneTimeTokenReactiveAuthenticationManager;
import org.springframework.security.authentication.ott.reactive.ReactiveOneTimeTokenService;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.server.session.InMemoryReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
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
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry;
import org.springframework.security.web.server.ExchangeMatcherRedirectWebFilter;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AnonymousAuthenticationWebFilter;
import org.springframework.security.web.server.authentication.AuthenticationConverterServerWebExchangeMatcher;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ConcurrentSessionControlServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.DelegatingServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.InvalidateLeastUsedServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.ReactivePreAuthenticatedAuthenticationManager;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.RegisterSessionServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerFormLoginAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.ServerX509AuthenticationConverter;
import org.springframework.security.web.server.authentication.SessionLimit;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.ott.GenerateOneTimeTokenWebFilter;
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.authorization.IpAddressReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ReactorContextWebFilter;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfServerLogoutHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository;
import org.springframework.security.web.server.header.CacheControlServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginEmbedderPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy;
import org.springframework.security.web.server.header.CrossOriginOpenerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.server.header.CrossOriginResourcePolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginResourcePolicyServerHttpHeadersWriter.CrossOriginResourcePolicy;
import org.springframework.security.web.server.header.FeaturePolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.PermissionsPolicyServerHttpHeadersWriter;
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
import org.springframework.security.web.server.ui.DefaultResourcesWebFilter;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.server.ui.LogoutPageGeneratingWebFilter;
import org.springframework.security.web.server.ui.OneTimeTokenSubmitPageGeneratingWebFilter;
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
import org.springframework.util.StringUtils;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsProcessor;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.DefaultCorsProcessor;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A {@link ServerHttpSecurity} is similar to Spring Security's {@code HttpSecurity} but
 * for WebFlux. It allows configuring web based security for specific http requests. By
 * default it will be applied to all requests, but can be restricted using
 * {@link #securityMatcher(ServerWebExchangeMatcher)} or other similar methods.
 *
 * A minimal configuration can be found below:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebFluxSecurity
 * public class MyMinimalSecurityConfiguration {
 *
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *         UserDetails user = User.withDefaultPasswordEncoder()
 *             .username("user")
 *             .password("password")
 *             .roles("USER")
 *             .build();
 *         return new MapReactiveUserDetailsService(user);
 *     }
 * }
 * </pre>
 *
 * Below is the same as our minimal configuration, but explicitly declaring the
 * {@code ServerHttpSecurity}.
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebFluxSecurity
 * public class MyExplicitSecurityConfiguration {
 *
 *     &#064;Bean
 *     public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
 *         http
 *             .authorizeExchange()
 *               .anyExchange().authenticated()
 *             .and()
 *               .httpBasic().and()
 *               .formLogin();
 *             return http.build();
 *     }
 *
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *         UserDetails user = User.withDefaultPasswordEncoder()
 *             .username("user")
 *             .password("password")
 *             .roles("USER")
 *             .build();
 *         return new MapReactiveUserDetailsService(user);
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @author Vedran Pavic
 * @author Rafiullah Hamedy
 * @author Eddú Meléndez
 * @author Joe Grandja
 * @author Parikshit Dutta
 * @author Ankur Pathak
 * @author Alexey Nesterov
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

	private PasswordManagementSpec passwordManagement;

	private X509Spec x509;

	private final RequestCacheSpec requestCache = new RequestCacheSpec();

	private FormLoginSpec formLogin;

	private OAuth2LoginSpec oauth2Login;

	private OAuth2ResourceServerSpec resourceServer;

	private OAuth2ClientSpec client;

	private OidcLogoutSpec oidcLogout;

	private LogoutSpec logout = new LogoutSpec();

	private LoginPageSpec loginPage = new LoginPageSpec();

	private SessionManagementSpec sessionManagement;

	private ReactiveAuthenticationManager authenticationManager;

	private ServerSecurityContextRepository securityContextRepository;

	private ServerAuthenticationEntryPoint authenticationEntryPoint;

	private List<DelegateEntry> defaultEntryPoints = new ArrayList<>();

	private ServerAccessDeniedHandler accessDeniedHandler;

	private List<ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry> defaultAccessDeniedHandlers = new ArrayList<>();

	private List<WebFilter> webFilters = new ArrayList<>();

	private ApplicationContext context;

	private Throwable built;

	private AnonymousSpec anonymous;

	private OneTimeTokenLoginSpec oneTimeTokenLogin;

	protected ServerHttpSecurity() {
	}

	/**
	 * The ServerExchangeMatcher that determines which requests apply to this HttpSecurity
	 * instance.
	 * @param matcher the ServerExchangeMatcher that determines which requests apply to
	 * this HttpSecurity instance. Default is all requests.
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
	 *
	 * Adds a {@link WebFilter} before specific position.
	 * @param webFilter the {@link WebFilter} to add
	 * @param order the place before which to insert the {@link WebFilter}
	 * @return the {@link ServerHttpSecurity} to continue configuring
	 * @since 5.2.0
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
	 */
	public ServerHttpSecurity addFilterAfter(WebFilter webFilter, SecurityWebFiltersOrder order) {
		this.webFilters.add(new OrderedWebFilter(webFilter, order.getOrder() + 1));
		return this;
	}

	/**
	 * Gets the ServerExchangeMatcher that determines which requests apply to this
	 * HttpSecurity instance.
	 * @return the ServerExchangeMatcher that determines which requests apply to this
	 * HttpSecurity instance.
	 */
	private ServerWebExchangeMatcher getSecurityMatcher() {
		return this.securityMatcher;
	}

	/**
	 * The strategy used with {@code ReactorContextWebFilter}. It does impact how the
	 * {@code SecurityContext} is saved which is configured on a per
	 * {@link AuthenticationWebFilter} basis.
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
	 * Typically, all requests should be HTTPS; however, the focus for redirection can
	 * also be narrowed:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 * 	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 * 	    http
	 * 	        // ...
	 * 	        .redirectToHttps()
	 * 	            .httpsRedirectWhen((serverWebExchange) -&gt;
	 * 	            	serverWebExchange.getRequest().getHeaders().containsKey("X-Requires-Https"))
	 * 	    return http.build();
	 * 	}
	 * </pre>
	 * @return the {@link HttpsRedirectSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #redirectToHttps(Customizer)} or
	 * {@code redirectToHttps(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public HttpsRedirectSpec redirectToHttps() {
		this.httpsRedirectSpec = new HttpsRedirectSpec();
		return this.httpsRedirectSpec;
	}

	/**
	 * Configures HTTPS redirection rules. If the default is used:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 * 	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 * 	    http
	 * 	        // ...
	 * 	        .redirectToHttps(withDefaults());
	 * 	    return http.build();
	 * 	}
	 * </pre>
	 *
	 * Then all non-HTTPS requests will be redirected to HTTPS.
	 *
	 * Typically, all requests should be HTTPS; however, the focus for redirection can
	 * also be narrowed:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 * 	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 * 	    http
	 * 	        // ...
	 * 	        .redirectToHttps((redirectToHttps) -&gt;
	 * 	        	redirectToHttps
	 * 	            	.httpsRedirectWhen((serverWebExchange) -&gt;
	 * 	            		serverWebExchange.getRequest().getHeaders().containsKey("X-Requires-Https"))
	 * 	            );
	 * 	    return http.build();
	 * 	}
	 * </pre>
	 * @param httpsRedirectCustomizer the {@link Customizer} to provide more options for
	 * the {@link HttpsRedirectSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity redirectToHttps(Customizer<HttpsRedirectSpec> httpsRedirectCustomizer) {
		this.httpsRedirectSpec = new HttpsRedirectSpec();
		httpsRedirectCustomizer.customize(this.httpsRedirectSpec);
		return this;
	}

	/**
	 * Configures <a href=
	 * "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet">CSRF
	 * Protection</a> which is enabled by default. You can disable it using:
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
	 * @return the {@link CsrfSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #csrf(Customizer)} or
	 * {@code csrf(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public CsrfSpec csrf() {
		if (this.csrf == null) {
			this.csrf = new CsrfSpec();
		}
		return this.csrf;
	}

	/**
	 * Configures <a href=
	 * "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet">CSRF
	 * Protection</a> which is enabled by default. You can disable it using:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .csrf((csrf) -&gt;
	 *              csrf.disabled()
	 *          );
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
	 *          .csrf((csrf) -&gt;
	 *              csrf
	 *                  // Handle CSRF failures
	 *                  .accessDeniedHandler(accessDeniedHandler)
	 *                  // Custom persistence of CSRF Token
	 *                  .csrfTokenRepository(csrfTokenRepository)
	 *                  // custom matching when CSRF protection is enabled
	 *                  .requireCsrfProtectionMatcher(matcher)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param csrfCustomizer the {@link Customizer} to provide more options for the
	 * {@link CsrfSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity csrf(Customizer<CsrfSpec> csrfCustomizer) {
		if (this.csrf == null) {
			this.csrf = new CsrfSpec();
		}
		csrfCustomizer.customize(this.csrf);
		return this;
	}

	/**
	 * Configures CORS headers. By default if a {@link CorsConfigurationSource} Bean is
	 * found, it will be used to create a {@link CorsWebFilter}. If
	 * {@link CorsSpec#configurationSource(CorsConfigurationSource)} is invoked it will be
	 * used instead. If neither has been configured, the Cors configuration will do
	 * nothing.
	 * @return the {@link CorsSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #cors(Customizer)} or
	 * {@code cors(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public CorsSpec cors() {
		if (this.cors == null) {
			this.cors = new CorsSpec();
		}
		return this.cors;
	}

	/**
	 * Configures CORS headers. By default if a {@link CorsConfigurationSource} Bean is
	 * found, it will be used to create a {@link CorsWebFilter}. If
	 * {@link CorsSpec#configurationSource(CorsConfigurationSource)} is invoked it will be
	 * used instead. If neither has been configured, the Cors configuration will do
	 * nothing.
	 * @param corsCustomizer the {@link Customizer} to provide more options for the
	 * {@link CorsSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity cors(Customizer<CorsSpec> corsCustomizer) {
		if (this.cors == null) {
			this.cors = new CorsSpec();
		}
		corsCustomizer.customize(this.cors);
		return this;
	}

	/**
	 * Enables and Configures anonymous authentication. Anonymous Authentication is
	 * disabled by default.
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
	 * @return the {@link AnonymousSpec} to customize
	 * @since 5.2.0
	 * @deprecated For removal in 7.0. Use {@link #anonymous(Customizer)} or
	 * {@code anonymous(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public AnonymousSpec anonymous() {
		if (this.anonymous == null) {
			this.anonymous = new AnonymousSpec();
		}
		return this.anonymous;
	}

	/**
	 * Enables and Configures anonymous authentication. Anonymous Authentication is
	 * disabled by default.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .anonymous((anonymous) -&gt;
	 *              anonymous
	 *                  .key("key")
	 *                  .authorities("ROLE_ANONYMOUS")
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param anonymousCustomizer the {@link Customizer} to provide more options for the
	 * {@link AnonymousSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity anonymous(Customizer<AnonymousSpec> anonymousCustomizer) {
		if (this.anonymous == null) {
			this.anonymous = new AnonymousSpec();
		}
		anonymousCustomizer.customize(this.anonymous);
		return this;
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
	 * @return the {@link HttpBasicSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #httpBasic(Customizer)} or
	 * {@code httpBasic(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public HttpBasicSpec httpBasic() {
		if (this.httpBasic == null) {
			this.httpBasic = new HttpBasicSpec();
		}
		return this.httpBasic;
	}

	/**
	 * Configures HTTP Basic authentication. An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .httpBasic((httpBasic) -&gt;
	 *              httpBasic
	 *                  // used for authenticating the credentials
	 *                  .authenticationManager(authenticationManager)
	 *                  // Custom persistence of the authentication
	 *                  .securityContextRepository(securityContextRepository)
	 *              );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param httpBasicCustomizer the {@link Customizer} to provide more options for the
	 * {@link HttpBasicSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity httpBasic(Customizer<HttpBasicSpec> httpBasicCustomizer) {
		if (this.httpBasic == null) {
			this.httpBasic = new HttpBasicSpec();
		}
		httpBasicCustomizer.customize(this.httpBasic);
		return this;
	}

	/**
	 * Configures Session Management. An example configuration is provided below:
	 * <pre class="code">
	 *  &#064;Bean
	 *  SecurityWebFilterChain filterChain(ServerHttpSecurity http, ReactiveSessionRegistry sessionRegistry) {
	 *      http
	 *          // ...
	 *          .sessionManagement((sessionManagement) -> sessionManagement
	 *              .concurrentSessions((concurrentSessions) -> concurrentSessions
	 *                  .maxSessions(1)
	 *                  .maxSessionsPreventsLogin(true)
	 *                  .sessionRegistry(sessionRegistry)
	 *              )
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param customizer the {@link Customizer} to provide more options for the
	 * {@link SessionManagementSpec}
	 * @return the {@link ServerHttpSecurity} to continue configuring
	 * @since 6.3
	 */
	public ServerHttpSecurity sessionManagement(Customizer<SessionManagementSpec> customizer) {
		if (this.sessionManagement == null) {
			this.sessionManagement = new SessionManagementSpec();
		}
		customizer.customize(this.sessionManagement);
		return this;
	}

	/**
	 * Configures password management. An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .passwordManagement();
	 *      return http.build();
	 *  }
	 * </pre>
	 * @return the {@link PasswordManagementSpec} to customize
	 * @since 5.6
	 * @deprecated For removal in 7.0. Use {@link #passwordManagement(Customizer)} or
	 * {@code passwordManagement(Customizer.withDefaults())} to stick with defaults. See
	 * the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public PasswordManagementSpec passwordManagement() {
		if (this.passwordManagement == null) {
			this.passwordManagement = new PasswordManagementSpec();
		}
		return this.passwordManagement;
	}

	/**
	 * Configures password management. An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .passwordManagement(passwordManagement -&gt;
	 *          	// Custom change password page.
	 *          	passwordManagement.changePasswordPage("/custom-change-password-page")
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param passwordManagementCustomizer the {@link Customizer} to provide more options
	 * for the {@link PasswordManagementSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 * @since 5.6
	 */
	public ServerHttpSecurity passwordManagement(Customizer<PasswordManagementSpec> passwordManagementCustomizer) {
		if (this.passwordManagement == null) {
			this.passwordManagement = new PasswordManagementSpec();
		}
		passwordManagementCustomizer.customize(this.passwordManagement);
		return this;
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
	 *              .loginPage("/authenticate");
	 *      return http.build();
	 *  }
	 * </pre>
	 * @return the {@link FormLoginSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #formLogin(Customizer)} or
	 * {@code formLogin(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public FormLoginSpec formLogin() {
		if (this.formLogin == null) {
			this.formLogin = new FormLoginSpec();
		}
		return this.formLogin;
	}

	/**
	 * Configures form based authentication. An example configuration is provided below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .formLogin((formLogin) -&gt;
	 *              formLogin
	 *              	// used for authenticating the credentials
	 *              	.authenticationManager(authenticationManager)
	 *              	// Custom persistence of the authentication
	 *              	.securityContextRepository(securityContextRepository)
	 *              	// expect a log in page at "/authenticate"
	 *              	// a POST "/authenticate" is where authentication occurs
	 *              	// error page at "/authenticate?error"
	 *              	.loginPage("/authenticate")
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param formLoginCustomizer the {@link Customizer} to provide more options for the
	 * {@link FormLoginSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity formLogin(Customizer<FormLoginSpec> formLoginCustomizer) {
		if (this.formLogin == null) {
			this.formLogin = new FormLoginSpec();
		}
		formLoginCustomizer.customize(this.formLogin);
		return this;
	}

	/**
	 * Configures x509 authentication using a certificate provided by a client.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          .x509()
	 *          	.authenticationManager(authenticationManager)
	 *              .principalExtractor(principalExtractor);
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * Note that if extractor is not specified, {@link SubjectDnX509PrincipalExtractor}
	 * will be used. If authenticationManager is not specified,
	 * {@link ReactivePreAuthenticatedAuthenticationManager} will be used.
	 * @return the {@link X509Spec} to customize
	 * @since 5.2
	 * @deprecated For removal in 7.0. Use {@link #x509(Customizer)} or
	 * {@code x509(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public X509Spec x509() {
		if (this.x509 == null) {
			this.x509 = new X509Spec();
		}

		return this.x509;
	}

	/**
	 * Configures x509 authentication using a certificate provided by a client.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          .x509((x509) -&gt;
	 *              x509
	 *          	    .authenticationManager(authenticationManager)
	 *                  .principalExtractor(principalExtractor)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 *
	 * Note that if extractor is not specified, {@link SubjectDnX509PrincipalExtractor}
	 * will be used. If authenticationManager is not specified,
	 * {@link ReactivePreAuthenticatedAuthenticationManager} will be used.
	 * @param x509Customizer the {@link Customizer} to provide more options for the
	 * {@link X509Spec}
	 * @return the {@link ServerHttpSecurity} to customize
	 * @since 5.2
	 */
	public ServerHttpSecurity x509(Customizer<X509Spec> x509Customizer) {
		if (this.x509 == null) {
			this.x509 = new X509Spec();
		}
		x509Customizer.customize(this.x509);
		return this;
	}

	/**
	 * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0
	 * Provider.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oauth2Login()
	 *              .authenticationConverter(authenticationConverter)
	 *              .authenticationManager(manager);
	 *      return http.build();
	 *  }
	 * </pre>
	 * @return the {@link OAuth2LoginSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #oauth2Login(Customizer)} or
	 * {@code oauth2Login(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public OAuth2LoginSpec oauth2Login() {
		if (this.oauth2Login == null) {
			this.oauth2Login = new OAuth2LoginSpec();
		}
		return this.oauth2Login;
	}

	/**
	 * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0
	 * Provider.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oauth2Login((oauth2Login) -&gt;
	 *              oauth2Login
	 *                  .authenticationConverter(authenticationConverter)
	 *                  .authenticationManager(manager)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param oauth2LoginCustomizer the {@link Customizer} to provide more options for the
	 * {@link OAuth2LoginSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity oauth2Login(Customizer<OAuth2LoginSpec> oauth2LoginCustomizer) {
		if (this.oauth2Login == null) {
			this.oauth2Login = new OAuth2LoginSpec();
		}
		oauth2LoginCustomizer.customize(this.oauth2Login);
		return this;
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
	 * @return the {@link OAuth2ClientSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #oauth2Client(Customizer)} or
	 * {@code oauth2Client(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public OAuth2ClientSpec oauth2Client() {
		if (this.client == null) {
			this.client = new OAuth2ClientSpec();
		}
		return this.client;
	}

	/**
	 * Configures the OAuth2 client.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oauth2Client((oauth2Client) -&gt;
	 *              oauth2Client
	 *                  .clientRegistrationRepository(clientRegistrationRepository)
	 *                  .authorizedClientRepository(authorizedClientRepository)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param oauth2ClientCustomizer the {@link Customizer} to provide more options for
	 * the {@link OAuth2ClientSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity oauth2Client(Customizer<OAuth2ClientSpec> oauth2ClientCustomizer) {
		if (this.client == null) {
			this.client = new OAuth2ClientSpec();
		}
		oauth2ClientCustomizer.customize(this.client);
		return this;
	}

	/**
	 * Configures OAuth 2.0 Resource Server support.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oauth2ResourceServer()
	 *              .jwt()
	 *                  .publicKey(publicKey());
	 *      return http.build();
	 *  }
	 * </pre>
	 * @return the {@link OAuth2ResourceServerSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #oauth2ResourceServer(Customizer)}
	 * instead
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public OAuth2ResourceServerSpec oauth2ResourceServer() {
		if (this.resourceServer == null) {
			this.resourceServer = new OAuth2ResourceServerSpec();
		}
		return this.resourceServer;
	}

	/**
	 * Configures OAuth 2.0 Resource Server support.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oauth2ResourceServer((oauth2ResourceServer) -&gt;
	 *              oauth2ResourceServer
	 *                  .jwt((jwt) -&gt;
	 *                      jwt
	 *                          .publicKey(publicKey())
	 *                  )
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param oauth2ResourceServerCustomizer the {@link Customizer} to provide more
	 * options for the {@link OAuth2ResourceServerSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity oauth2ResourceServer(
			Customizer<OAuth2ResourceServerSpec> oauth2ResourceServerCustomizer) {
		if (this.resourceServer == null) {
			this.resourceServer = new OAuth2ResourceServerSpec();
		}
		oauth2ResourceServerCustomizer.customize(this.resourceServer);
		return this;
	}

	/**
	 * Configures OIDC Connect 1.0 Logout support.
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .oidcLogout((logout) -&gt; logout
	 *              .backChannel(Customizer.withDefaults())
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param oidcLogoutCustomizer the {@link Customizer} to provide more options for the
	 * {@link OidcLogoutSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 * @since 6.2
	 */
	public ServerHttpSecurity oidcLogout(Customizer<OidcLogoutSpec> oidcLogoutCustomizer) {
		if (this.oidcLogout == null) {
			this.oidcLogout = new OidcLogoutSpec();
		}
		oidcLogoutCustomizer.customize(this.oidcLogout);
		return this;
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
	 * X-XSS-Protection: 0
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
	 * @return the {@link HeaderSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #headers(Customizer)} or
	 * {@code headers(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public HeaderSpec headers() {
		if (this.headers == null) {
			this.headers = new HeaderSpec();
		}
		return this.headers;
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
	 * X-XSS-Protection: 0
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
	 *          .headers((headers) -&gt;
	 *              headers
	 *                  // customize frame options to be same origin
	 *                  .frameOptions((frameOptions) -&gt;
	 *                      frameOptions
	 *                          .mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN)
	 *                   )
	 *                  // disable cache control
	 *                  .cache((cache) -&gt;
	 *                      cache
	 *                          .disable()
	 *                  )
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param headerCustomizer the {@link Customizer} to provide more options for the
	 * {@link HeaderSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity headers(Customizer<HeaderSpec> headerCustomizer) {
		if (this.headers == null) {
			this.headers = new HeaderSpec();
		}
		headerCustomizer.customize(this.headers);
		return this;
	}

	/**
	 * Configures exception handling (i.e. handles when authentication is requested). An
	 * example configuration can be found below:
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
	 * @return the {@link ExceptionHandlingSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #exceptionHandling(Customizer)} or
	 * {@code exceptionHandling(Customizer.withDefaults())} to stick with defaults. See
	 * the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public ExceptionHandlingSpec exceptionHandling() {
		if (this.exceptionHandling == null) {
			this.exceptionHandling = new ExceptionHandlingSpec();
		}
		return this.exceptionHandling;
	}

	/**
	 * Configures exception handling (i.e. handles when authentication is requested). An
	 * example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .exceptionHandling((exceptionHandling) -&gt;
	 *              exceptionHandling
	 *                  // customize how to request for authentication
	 *                  .authenticationEntryPoint(entryPoint)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param exceptionHandlingCustomizer the {@link Customizer} to provide more options
	 * for the {@link ExceptionHandlingSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity exceptionHandling(Customizer<ExceptionHandlingSpec> exceptionHandlingCustomizer) {
		if (this.exceptionHandling == null) {
			this.exceptionHandling = new ExceptionHandlingSpec();
		}
		exceptionHandlingCustomizer.customize(this.exceptionHandling);
		return this;
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
	 *              .pathMatchers("/users/{username}").access((authentication, context) -&gt;
	 *                  authentication
	 *                      .map(Authentication::getName)
	 *                      .map((username) -&gt; username.equals(context.getVariables().get("username")))
	 *                      .map(AuthorizationDecision::new)
	 *              )
	 *              // allows providing a custom matching strategy that requires the role "ROLE_CUSTOM"
	 *              .matchers(customMatcher).hasRole("CUSTOM")
	 *              // any other request requires the user to be authenticated
	 *              .anyExchange().authenticated();
	 *      return http.build();
	 *  }
	 * </pre>
	 * @return the {@link AuthorizeExchangeSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #authorizeExchange(Customizer)} or
	 * {@code authorizeExchange(Customizer.withDefaults())} to stick with defaults. See
	 * the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public AuthorizeExchangeSpec authorizeExchange() {
		if (this.authorizeExchange == null) {
			this.authorizeExchange = new AuthorizeExchangeSpec();
		}
		return this.authorizeExchange;
	}

	/**
	 * Configures authorization. An example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .authorizeExchange((exchanges) -&gt;
	 *              exchanges
	 *                  // any URL that starts with /admin/ requires the role "ROLE_ADMIN"
	 *                  .pathMatchers("/admin/**").hasRole("ADMIN")
	 *                  // a POST to /users requires the role "USER_POST"
	 *                  .pathMatchers(HttpMethod.POST, "/users").hasAuthority("USER_POST")
	 *                  // a request to /users/{username} requires the current authentication's username
	 *                  // to be equal to the {username}
	 *                  .pathMatchers("/users/{username}").access((authentication, context) -&gt;
	 *                      authentication
	 *                          .map(Authentication::getName)
	 *                          .map((username) -&gt; username.equals(context.getVariables().get("username")))
	 *                          .map(AuthorizationDecision::new)
	 *                  )
	 *                  // allows providing a custom matching strategy that requires the role "ROLE_CUSTOM"
	 *                  .matchers(customMatcher).hasRole("CUSTOM")
	 *                  // any other request requires the user to be authenticated
	 *                  .anyExchange().authenticated()
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param authorizeExchangeCustomizer the {@link Customizer} to provide more options
	 * for the {@link AuthorizeExchangeSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity authorizeExchange(Customizer<AuthorizeExchangeSpec> authorizeExchangeCustomizer) {
		if (this.authorizeExchange == null) {
			this.authorizeExchange = new AuthorizeExchangeSpec();
		}
		authorizeExchangeCustomizer.customize(this.authorizeExchange);
		return this;
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
	 * @deprecated For removal in 7.0. Use {@link #logout(Customizer)} or
	 * {@code logout(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public LogoutSpec logout() {
		if (this.logout == null) {
			this.logout = new LogoutSpec();
		}
		return this.logout;
	}

	/**
	 * Configures log out. An example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .logout((logout) -&gt;
	 *              logout
	 *                  // configures how log out is done
	 *                  .logoutHandler(logoutHandler)
	 *                  // log out will be performed on POST /signout
	 *                  .logoutUrl("/signout")
	 *                  // configure what is done on logout success
	 *                  .logoutSuccessHandler(successHandler)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param logoutCustomizer the {@link Customizer} to provide more options for the
	 * {@link LogoutSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity logout(Customizer<LogoutSpec> logoutCustomizer) {
		if (this.logout == null) {
			this.logout = new LogoutSpec();
		}
		logoutCustomizer.customize(this.logout);
		return this;
	}

	/**
	 * Configures the request cache which is used when a flow is interrupted (i.e. due to
	 * requesting credentials) so that the request can be replayed after authentication.
	 * An example configuration can be found below:
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
	 * @return the {@link RequestCacheSpec} to customize
	 * @deprecated For removal in 7.0. Use {@link #requestCache(Customizer)} or
	 * {@code requestCache(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public RequestCacheSpec requestCache() {
		return this.requestCache;
	}

	/**
	 * Configures the request cache which is used when a flow is interrupted (i.e. due to
	 * requesting credentials) so that the request can be replayed after authentication.
	 * An example configuration can be found below:
	 *
	 * <pre class="code">
	 *  &#064;Bean
	 *  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	 *      http
	 *          // ...
	 *          .requestCache((requestCache) -&gt;
	 *              requestCache
	 *                  // configures how the request is cached
	 *                  .requestCache(customRequestCache)
	 *          );
	 *      return http.build();
	 *  }
	 * </pre>
	 * @param requestCacheCustomizer the {@link Customizer} to provide more options for
	 * the {@link RequestCacheSpec}
	 * @return the {@link ServerHttpSecurity} to customize
	 */
	public ServerHttpSecurity requestCache(Customizer<RequestCacheSpec> requestCacheCustomizer) {
		requestCacheCustomizer.customize(this.requestCache);
		return this;
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
	 * Configures One-Time Token Login Support.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebFluxSecurity
	 * public class SecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception {
	 * 		http
	 * 			// ...
	 * 			.oneTimeTokenLogin(Customizer.withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public ServerOneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler() {
	 * 		return new MyMagicLinkServerOneTimeTokenGenerationSuccessHandler();
	 * 	}
	 *
	 * }
	 * </pre>
	 * @param oneTimeTokenLoginCustomizer the {@link Customizer} to provide more options
	 * for the {@link OneTimeTokenLoginSpec}
	 * @return the {@link ServerHttpSecurity} for further customizations
	 */
	public ServerHttpSecurity oneTimeTokenLogin(Customizer<OneTimeTokenLoginSpec> oneTimeTokenLoginCustomizer) {
		if (this.oneTimeTokenLogin == null) {
			this.oneTimeTokenLogin = new OneTimeTokenLoginSpec();
		}
		oneTimeTokenLoginCustomizer.customize(this.oneTimeTokenLogin);
		return this;
	}

	/**
	 * Builds the {@link SecurityWebFilterChain}
	 * @return the {@link SecurityWebFilterChain}
	 */
	public SecurityWebFilterChain build() {
		if (this.built != null) {
			throw new IllegalStateException(
					"This has already been built with the following stacktrace. " + buildToString());
		}
		this.built = new RuntimeException("First Build Invocation").fillInStackTrace();
		if (this.headers != null) {
			this.headers.configure(this);
		}
		WebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
		this.webFilters.add(securityContextRepositoryWebFilter);
		if (this.sessionManagement != null) {
			this.sessionManagement.configure(this);
		}
		if (this.httpsRedirectSpec != null) {
			this.httpsRedirectSpec.configure(this);
		}
		if (this.x509 != null) {
			this.x509.configure(this);
		}
		if (this.csrf != null) {
			this.csrf.configure(this);
		}
		if (this.cors != null) {
			this.cors.configure(this);
		}
		if (this.httpBasic != null) {
			if (this.httpBasic.authenticationManager == null) {
				this.httpBasic.authenticationManager(this.authenticationManager);
			}
			if (this.httpBasic.securityContextRepository != null) {
				this.httpBasic.securityContextRepository(this.httpBasic.securityContextRepository);
			}
			else if (this.securityContextRepository != null) {
				this.httpBasic.securityContextRepository(this.securityContextRepository);
			}
			else {
				this.httpBasic.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
			}
			this.httpBasic.configure(this);
		}
		if (this.passwordManagement != null) {
			this.passwordManagement.configure(this);
		}
		if (this.formLogin != null) {
			if (this.formLogin.authenticationManager == null) {
				this.formLogin.authenticationManager(this.authenticationManager);
			}
			if (this.formLogin.securityContextRepository != null) {
				this.formLogin.securityContextRepository(this.formLogin.securityContextRepository);
			}
			else if (this.securityContextRepository != null) {
				this.formLogin.securityContextRepository(this.securityContextRepository);
			}
			else {
				this.formLogin.securityContextRepository(new WebSessionServerSecurityContextRepository());
			}
			this.formLogin.configure(this);
		}
		if (this.oauth2Login != null) {
			if (this.oauth2Login.securityContextRepository != null) {
				this.oauth2Login.securityContextRepository(this.oauth2Login.securityContextRepository);
			}
			else if (this.securityContextRepository != null) {
				this.oauth2Login.securityContextRepository(this.securityContextRepository);
			}
			else {
				this.oauth2Login.securityContextRepository(new WebSessionServerSecurityContextRepository());
			}
			this.oauth2Login.configure(this);
		}
		if (this.resourceServer != null) {
			this.resourceServer.configure(this);
		}
		if (this.oidcLogout != null) {
			this.oidcLogout.configure(this);
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
		if (this.oneTimeTokenLogin != null) {
			if (this.oneTimeTokenLogin.securityContextRepository != null) {
				this.oneTimeTokenLogin.securityContextRepository(this.oneTimeTokenLogin.securityContextRepository);
			}
			else if (this.securityContextRepository != null) {
				this.oneTimeTokenLogin.securityContextRepository(this.securityContextRepository);
			}
			else {
				this.oneTimeTokenLogin.securityContextRepository(new WebSessionServerSecurityContextRepository());
			}
			this.oneTimeTokenLogin.configure(this);
		}
		this.addFilterAt(new SecurityContextServerWebExchangeWebFilter(),
				SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE);
		if (this.authorizeExchange != null) {
			ServerAuthenticationEntryPoint authenticationEntryPoint = getAuthenticationEntryPoint();
			ExceptionTranslationWebFilter exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
			if (authenticationEntryPoint != null) {
				exceptionTranslationWebFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
			}
			ServerAccessDeniedHandler accessDeniedHandler = getAccessDeniedHandler();
			if (accessDeniedHandler != null) {
				exceptionTranslationWebFilter.setAccessDeniedHandler(accessDeniedHandler);
			}
			this.addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
			this.authorizeExchange.configure(this);
		}
		AnnotationAwareOrderComparator.sort(this.webFilters);
		List<WebFilter> sortedWebFilters = new ArrayList<>();
		this.webFilters.forEach((f) -> {
			if (f instanceof OrderedWebFilter) {
				f = ((OrderedWebFilter) f).webFilter;
			}
			sortedWebFilters.add(f);
		});
		sortedWebFilters.add(0, new ServerWebExchangeReactorContextWebFilter());
		return new MatcherSecurityWebFilterChain(getSecurityMatcher(), sortedWebFilters);
	}

	private String buildToString() {
		try (StringWriter writer = new StringWriter()) {
			try (PrintWriter printer = new PrintWriter(writer)) {
				printer.println();
				printer.println();
				this.built.printStackTrace(printer);
				printer.println();
				printer.println();
				return writer.toString();
			}
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private ServerAuthenticationEntryPoint getAuthenticationEntryPoint() {
		if (this.authenticationEntryPoint != null || this.defaultEntryPoints.isEmpty()) {
			return this.authenticationEntryPoint;
		}
		if (this.defaultEntryPoints.size() == 1) {
			return this.defaultEntryPoints.get(0).getEntryPoint();
		}
		DelegatingServerAuthenticationEntryPoint result = new DelegatingServerAuthenticationEntryPoint(
				this.defaultEntryPoints);
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
		ServerWebExchangeDelegatingServerAccessDeniedHandler result = new ServerWebExchangeDelegatingServerAccessDeniedHandler(
				this.defaultAccessDeniedHandlers);
		result.setDefaultAccessDeniedHandler(
				this.defaultAccessDeniedHandlers.get(this.defaultAccessDeniedHandlers.size() - 1)
					.getAccessDeniedHandler());
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
		ServerSecurityContextRepository repository = (this.securityContextRepository != null)
				? this.securityContextRepository : new WebSessionServerSecurityContextRepository();
		WebFilter result = new ReactorContextWebFilter(repository);
		return new OrderedWebFilter(result, SecurityWebFiltersOrder.REACTOR_CONTEXT.getOrder());
	}

	private <T> T getBean(Class<T> beanClass) {
		if (this.context == null) {
			return null;
		}
		return this.context.getBean(beanClass);
	}

	private <T> T getBeanOrDefault(Class<T> beanClass, T defaultInstance) {
		if (this.context == null) {
			return defaultInstance;
		}
		return this.context.getBeanProvider(beanClass).getIfUnique(() -> defaultInstance);
	}

	private <T> ObjectProvider<T> getBeanProvider(ResolvableType type) {
		if (this.context == null) {
			return new ObjectProvider<>() {
				@Override
				public Iterator<T> iterator() {
					return Collections.emptyIterator();
				}
			};
		}
		return this.context.getBeanProvider(type);
	}

	private <T> T getBeanOrNull(Class<T> beanClass) {
		return getBeanOrNull(ResolvableType.forClass(beanClass));
	}

	@SuppressWarnings("unchecked")
	private <T> T getBeanOrNull(ResolvableType type) {
		if (this.context == null) {
			return null;
		}
		return (T) this.context.getBeanProvider(type).getIfUnique();
	}

	private <T> T getBeanOrNull(String beanName, Class<T> requiredClass) {
		if (this.context == null) {
			return null;
		}
		try {
			return this.context.getBean(beanName, requiredClass);
		}
		catch (Exception ex) {
			return null;
		}
	}

	private <T> String[] getBeanNamesForTypeOrEmpty(Class<T> beanClass) {
		if (this.context == null) {
			return new String[0];
		}
		return this.context.getBeanNamesForType(beanClass);
	}

	protected void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.context = applicationContext;
	}

	/**
	 * Configures authorization
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #authorizeExchange()
	 */
	public class AuthorizeExchangeSpec extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeSpec.Access> {

		private static final String REQUEST_MAPPING_HANDLER_MAPPING_BEAN_NAME = "requestMappingHandlerMapping";

		private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager
			.builder();

		private ServerWebExchangeMatcher matcher;

		private boolean anyExchangeRegistered;

		private PathPatternParser pathPatternParser;

		private ObjectPostProcessor<ReactiveAuthorizationManager<ServerWebExchange>> postProcessor = ObjectPostProcessor
			.identity();

		public AuthorizeExchangeSpec() {
			ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class,
					ResolvableType.forClassWithGenerics(ReactiveAuthorizationManager.class, ServerWebExchange.class));
			ObjectProvider<ObjectPostProcessor<ReactiveAuthorizationManager<ServerWebExchange>>> postProcessor = getBeanProvider(
					type);
			postProcessor.ifUnique((p) -> this.postProcessor = p);
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #authorizeExchange(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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
		protected PathPatternParser getPathPatternParser() {
			if (this.pathPatternParser != null) {
				return this.pathPatternParser;
			}
			RequestMappingHandlerMapping requestMappingHandlerMapping = getBeanOrNull(
					REQUEST_MAPPING_HANDLER_MAPPING_BEAN_NAME, RequestMappingHandlerMapping.class);
			if (requestMappingHandlerMapping != null) {
				this.pathPatternParser = requestMappingHandlerMapping.getPathPatternParser();
			}
			if (this.pathPatternParser == null) {
				this.pathPatternParser = PathPatternParser.defaultInstance;
			}
			return this.pathPatternParser;
		}

		@Override
		protected Access registerMatcher(ServerWebExchangeMatcher matcher) {
			Assert.state(!this.anyExchangeRegistered, () -> "Cannot register " + matcher
					+ " which would be unreachable because anyExchange() has already been registered.");
			Assert.state(this.matcher == null,
					() -> "The matcher " + matcher + " does not have an access rule defined");
			this.matcher = matcher;
			return new Access();
		}

		protected void configure(ServerHttpSecurity http) {
			Assert.state(this.matcher == null,
					() -> "The matcher " + this.matcher + " does not have an access rule defined");
			ReactiveAuthorizationManager<ServerWebExchange> manager = this.managerBldr.build();
			manager = this.postProcessor.postProcess(manager);
			AuthorizationWebFilter result = new AuthorizationWebFilter(manager);
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
				return access((a, e) -> Mono.just(new AuthorizationDecision(true)));
			}

			/**
			 * Deny access for everyone
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec denyAll() {
				return access((a, e) -> Mono.just(new AuthorizationDecision(false)));
			}

			/**
			 * Require a specific role. This is a shorcut for
			 * {@link #hasAuthority(String)}
			 * @param role the role (i.e. "USER" would require "ROLE_USER")
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasRole(String role) {
				return access(AuthorityReactiveAuthorizationManager.hasRole(role));
			}

			/**
			 * Require any specific role. This is a shortcut for
			 * {@link #hasAnyAuthority(String...)}
			 * @param roles the roles (i.e. "USER" would require "ROLE_USER")
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasAnyRole(String... roles) {
				return access(AuthorityReactiveAuthorizationManager.hasAnyRole(roles));
			}

			/**
			 * Require a specific authority.
			 * @param authority the authority to require (i.e. "USER" would require
			 * authority of "USER").
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec hasAuthority(String authority) {
				return access(AuthorityReactiveAuthorizationManager.hasAuthority(authority));
			}

			/**
			 * Require any authority
			 * @param authorities the authorities to require (i.e. "USER" would require
			 * authority of "USER").
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
			 * Require a specific IP address or range using an IP/Netmask (e.g.
			 * 192.168.1.0/24).
			 * @param ipAddress the address or range of addresses from which the request
			 * must come.
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 * @since 5.7
			 */
			public AuthorizeExchangeSpec hasIpAddress(String ipAddress) {
				return access(IpAddressReactiveAuthorizationManager.hasIpAddress(ipAddress));
			}

			/**
			 * Allows plugging in a custom authorization strategy
			 * @param manager the authorization manager to use
			 * @return the {@link AuthorizeExchangeSpec} to configure
			 */
			public AuthorizeExchangeSpec access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
				AuthorizeExchangeSpec.this.managerBldr
					.add(new ServerWebExchangeMatcherEntry<>(AuthorizeExchangeSpec.this.matcher, manager));
				AuthorizeExchangeSpec.this.matcher = null;
				return AuthorizeExchangeSpec.this;
			}

		}

	}

	/**
	 * Configures how sessions are managed.
	 */
	public class SessionManagementSpec {

		private ConcurrentSessionsSpec concurrentSessions;

		private ServerAuthenticationSuccessHandler authenticationSuccessHandler;

		private ReactiveSessionRegistry sessionRegistry;

		private SessionLimit sessionLimit = SessionLimit.UNLIMITED;

		private ServerMaximumSessionsExceededHandler maximumSessionsExceededHandler;

		/**
		 * Configures how many sessions are allowed for a given user.
		 * @param customizer the customizer to provide more options
		 * @return the {@link SessionManagementSpec} to customize
		 */
		public SessionManagementSpec concurrentSessions(Customizer<ConcurrentSessionsSpec> customizer) {
			if (this.concurrentSessions == null) {
				this.concurrentSessions = new ConcurrentSessionsSpec();
			}
			customizer.customize(this.concurrentSessions);
			return this;
		}

		void configure(ServerHttpSecurity http) {
			if (this.concurrentSessions != null) {
				ReactiveSessionRegistry reactiveSessionRegistry = getSessionRegistry();
				ConcurrentSessionControlServerAuthenticationSuccessHandler concurrentSessionControlStrategy = new ConcurrentSessionControlServerAuthenticationSuccessHandler(
						reactiveSessionRegistry, getMaximumSessionsExceededHandler());
				concurrentSessionControlStrategy.setSessionLimit(this.sessionLimit);
				RegisterSessionServerAuthenticationSuccessHandler registerSessionAuthenticationStrategy = new RegisterSessionServerAuthenticationSuccessHandler(
						reactiveSessionRegistry);
				this.authenticationSuccessHandler = new DelegatingServerAuthenticationSuccessHandler(
						concurrentSessionControlStrategy, registerSessionAuthenticationStrategy);
				SessionRegistryWebFilter sessionRegistryWebFilter = new SessionRegistryWebFilter(
						reactiveSessionRegistry);
				configureSuccessHandlerOnAuthenticationFilters();
				http.addFilterAfter(sessionRegistryWebFilter, SecurityWebFiltersOrder.HTTP_HEADERS_WRITER);
			}
		}

		private ServerMaximumSessionsExceededHandler getMaximumSessionsExceededHandler() {
			if (this.maximumSessionsExceededHandler != null) {
				return this.maximumSessionsExceededHandler;
			}
			DefaultWebSessionManager webSessionManager = getBeanOrNull(
					WebHttpHandlerBuilder.WEB_SESSION_MANAGER_BEAN_NAME, DefaultWebSessionManager.class);
			if (webSessionManager != null) {
				this.maximumSessionsExceededHandler = new InvalidateLeastUsedServerMaximumSessionsExceededHandler(
						webSessionManager.getSessionStore());
			}
			if (this.maximumSessionsExceededHandler == null) {
				throw new IllegalStateException(
						"Could not create a default ServerMaximumSessionsExceededHandler. Please provide "
								+ "a ServerMaximumSessionsExceededHandler via DSL");
			}
			return this.maximumSessionsExceededHandler;
		}

		private void configureSuccessHandlerOnAuthenticationFilters() {
			if (ServerHttpSecurity.this.formLogin != null) {
				ServerHttpSecurity.this.formLogin.defaultSuccessHandlers.add(0, this.authenticationSuccessHandler);
			}
			if (ServerHttpSecurity.this.oauth2Login != null) {
				ServerHttpSecurity.this.oauth2Login.defaultSuccessHandlers.add(0, this.authenticationSuccessHandler);
			}
			if (ServerHttpSecurity.this.httpBasic != null) {
				ServerHttpSecurity.this.httpBasic.defaultSuccessHandlers.add(0, this.authenticationSuccessHandler);
			}
		}

		private ReactiveSessionRegistry getSessionRegistry() {
			if (this.sessionRegistry == null) {
				this.sessionRegistry = getBeanOrNull(ReactiveSessionRegistry.class);
			}
			if (this.sessionRegistry == null) {
				throw new IllegalStateException(
						"A ReactiveSessionRegistry is needed for concurrent session management");
			}
			return this.sessionRegistry;
		}

		/**
		 * Configures how many sessions are allowed for a given user.
		 */
		public class ConcurrentSessionsSpec {

			/**
			 * Sets the {@link ReactiveSessionRegistry} to use.
			 * @param reactiveSessionRegistry the {@link ReactiveSessionRegistry} to use
			 * @return the {@link ConcurrentSessionsSpec} to continue customizing
			 */
			public ConcurrentSessionsSpec sessionRegistry(ReactiveSessionRegistry reactiveSessionRegistry) {
				SessionManagementSpec.this.sessionRegistry = reactiveSessionRegistry;
				return this;
			}

			/**
			 * Sets the maximum number of sessions allowed for any user. You can use
			 * {@link SessionLimit#of(int)} to specify a positive integer or
			 * {@link SessionLimit#UNLIMITED} to allow unlimited sessions. To customize
			 * the maximum number of sessions on a per-user basis, you can provide a
			 * custom {@link SessionLimit} implementation, like so: <pre>
			 *     http
			 *         .sessionManagement((sessions) -> sessions
			 *             .concurrentSessions((concurrency) -> concurrency
			 *                 .maximumSessions((authentication) -> {
			 *                     if (authentication.getName().equals("admin")) {
			 *                         return Mono.empty() // unlimited sessions for admin
			 *                     }
			 *                     return Mono.just(1); // one session for every other user
			 *                 })
			 *             )
			 *         )
			 * </pre>
			 * @param sessionLimit the maximum number of sessions allowed for any user
			 * @return the {@link ConcurrentSessionsSpec} to continue customizing
			 */
			public ConcurrentSessionsSpec maximumSessions(SessionLimit sessionLimit) {
				Assert.notNull(sessionLimit, "sessionLimit cannot be null");
				SessionManagementSpec.this.sessionLimit = sessionLimit;
				return this;
			}

			/**
			 * Sets the {@link ServerMaximumSessionsExceededHandler} to use when the
			 * maximum number of sessions is exceeded.
			 * @param maximumSessionsExceededHandler the
			 * {@link ServerMaximumSessionsExceededHandler} to use
			 * @return the {@link ConcurrentSessionsSpec} to continue customizing
			 */
			public ConcurrentSessionsSpec maximumSessionsExceededHandler(
					ServerMaximumSessionsExceededHandler maximumSessionsExceededHandler) {
				Assert.notNull(maximumSessionsExceededHandler, "maximumSessionsExceededHandler cannot be null");
				SessionManagementSpec.this.maximumSessionsExceededHandler = maximumSessionsExceededHandler;
				return this;
			}

		}

		private static final class SessionRegistryWebFilter implements WebFilter {

			private final ReactiveSessionRegistry sessionRegistry;

			private SessionRegistryWebFilter(ReactiveSessionRegistry sessionRegistry) {
				Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
				this.sessionRegistry = sessionRegistry;
			}

			@Override
			public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
				return chain.filter(new SessionRegistryWebExchange(exchange));
			}

			private final class SessionRegistryWebExchange extends ServerWebExchangeDecorator {

				private final Mono<WebSession> sessionMono;

				private SessionRegistryWebExchange(ServerWebExchange delegate) {
					super(delegate);
					this.sessionMono = delegate.getSession()
						.flatMap((session) -> SessionRegistryWebFilter.this.sessionRegistry
							.updateLastAccessTime(session.getId())
							.thenReturn(session))
						.map(SessionRegistryWebSession::new);
				}

				@Override
				public Mono<WebSession> getSession() {
					return this.sessionMono;
				}

			}

			private final class SessionRegistryWebSession implements WebSession {

				private final WebSession session;

				private SessionRegistryWebSession(WebSession session) {
					this.session = session;
				}

				@Override
				public String getId() {
					return this.session.getId();
				}

				@Override
				public Map<String, Object> getAttributes() {
					return this.session.getAttributes();
				}

				@Override
				public void start() {
					this.session.start();
				}

				@Override
				public boolean isStarted() {
					return this.session.isStarted();
				}

				@Override
				public Mono<Void> changeSessionId() {
					String currentId = this.session.getId();
					return this.session.changeSessionId()
						.then(Mono.defer(
								() -> SessionRegistryWebFilter.this.sessionRegistry.removeSessionInformation(currentId)
									.flatMap((information) -> {
										information = information.withSessionId(this.session.getId());
										return SessionRegistryWebFilter.this.sessionRegistry
											.saveSessionInformation(information);
									})));
				}

				@Override
				public Mono<Void> invalidate() {
					String currentId = this.session.getId();
					return this.session.invalidate()
						.then(Mono.defer(() -> SessionRegistryWebFilter.this.sessionRegistry
							.removeSessionInformation(currentId)))
						.then();
				}

				@Override
				public Mono<Void> save() {
					return this.session.save();
				}

				@Override
				public boolean isExpired() {
					return this.session.isExpired();
				}

				@Override
				public Instant getCreationTime() {
					return this.session.getCreationTime();
				}

				@Override
				public Instant getLastAccessTime() {
					return this.session.getLastAccessTime();
				}

				@Override
				public void setMaxIdleTime(Duration maxIdleTime) {
					this.session.setMaxIdleTime(maxIdleTime);
				}

				@Override
				public Duration getMaxIdleTime() {
					return this.session.getMaxIdleTime();
				}

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
		 * @param matchers the list of conditions that, when any are met, the filter
		 * should redirect to https
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
		 * @param when determines when to redirect to https
		 * @return the {@link HttpsRedirectSpec} for additional configuration
		 */
		public HttpsRedirectSpec httpsRedirectWhen(Function<ServerWebExchange, Boolean> when) {
			ServerWebExchangeMatcher matcher = (e) -> when.apply(e) ? ServerWebExchangeMatcher.MatchResult.match()
					: ServerWebExchangeMatcher.MatchResult.notMatch();
			return httpsRedirectWhen(matcher);
		}

		/**
		 * Configures a custom HTTPS port to redirect to
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
		 * @deprecated use {@link #redirectToHttps(Customizer)}
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

	}

	/**
	 * Configures <a href=
	 * "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet">CSRF
	 * Protection</a>
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #csrf()
	 */
	public final class CsrfSpec {

		private CsrfSpec() {
		}

		private CsrfWebFilter filter = new CsrfWebFilter();

		private ServerCsrfTokenRepository csrfTokenRepository = new WebSessionServerCsrfTokenRepository();

		private boolean specifiedRequireCsrfProtectionMatcher;

		/**
		 * Configures the {@link ServerAccessDeniedHandler} used when a CSRF token is
		 * invalid. Default is to send an
		 * {@link org.springframework.http.HttpStatus#FORBIDDEN}.
		 * @param accessDeniedHandler the access denied handler.
		 * @return the {@link CsrfSpec} for additional configuration
		 */
		public CsrfSpec accessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
			this.filter.setAccessDeniedHandler(accessDeniedHandler);
			return this;
		}

		/**
		 * Configures the {@link ServerCsrfTokenRepository} used to persist the CSRF
		 * Token. Default is
		 * {@link org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository}.
		 * @param csrfTokenRepository the repository to use
		 * @return the {@link CsrfSpec} for additional configuration
		 */
		public CsrfSpec csrfTokenRepository(ServerCsrfTokenRepository csrfTokenRepository) {
			this.csrfTokenRepository = csrfTokenRepository;
			return this;
		}

		/**
		 * Configures the {@link ServerWebExchangeMatcher} used to determine when CSRF
		 * protection is enabled. Default is PUT, POST, DELETE requests.
		 * @param requireCsrfProtectionMatcher the matcher to use
		 * @return the {@link CsrfSpec} for additional configuration
		 */
		public CsrfSpec requireCsrfProtectionMatcher(ServerWebExchangeMatcher requireCsrfProtectionMatcher) {
			this.filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
			this.specifiedRequireCsrfProtectionMatcher = true;
			return this;
		}

		/**
		 * Specifies a {@link ServerCsrfTokenRequestHandler} that is used to make the
		 * {@code CsrfToken} available as an exchange attribute.
		 * @param requestHandler the {@link ServerCsrfTokenRequestHandler} to use
		 * @return the {@link CsrfSpec} for additional configuration
		 * @since 5.8
		 */
		public CsrfSpec csrfTokenRequestHandler(ServerCsrfTokenRequestHandler requestHandler) {
			this.filter.setRequestHandler(requestHandler);
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #csrf(Customizer)} or
		 * {@code csrf(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Disables CSRF Protection. Disabling CSRF Protection is only recommended when
		 * the application is never used within a browser.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 */
		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.csrf = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			if (this.csrfTokenRepository != null) {
				this.filter.setCsrfTokenRepository(this.csrfTokenRepository);
				if (ServerHttpSecurity.this.logout != null) {
					ServerHttpSecurity.this.logout
						.addLogoutHandler(new CsrfServerLogoutHandler(this.csrfTokenRepository));
				}
			}
			http.addFilterAt(this.filter, SecurityWebFiltersOrder.CSRF);
		}

	}

	/**
	 * Configures exception handling
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #exceptionHandling()
	 */
	public final class ExceptionHandlingSpec {

		private ExceptionHandlingSpec() {
		}

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
		 * Configures what to do when an authenticated user does not hold a required
		 * authority
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
		 * @deprecated For removal in 7.0. Use {@link #exceptionHandling(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

	}

	/**
	 * Configures the request cache which is used when a flow is interrupted (i.e. due to
	 * requesting credentials) so that the request can be replayed after authentication.
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #requestCache()
	 */
	public final class RequestCacheSpec {

		private ServerRequestCache requestCache = new WebSessionServerRequestCache();

		private RequestCacheSpec() {
		}

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
		 * @deprecated For removal in 7.0. Use {@link #requestCache(Customizer)} or
		 * {@code requestCache(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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

	}

	/**
	 * Configures HTTP Basic Authentication
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #httpBasic()
	 */
	public final class HttpBasicSpec {

		private final ServerWebExchangeMatcher xhrMatcher = (exchange) -> Mono.just(exchange.getRequest().getHeaders())
			.filter((h) -> h.getOrEmpty("X-Requested-With").contains("XMLHttpRequest"))
			.flatMap((h) -> ServerWebExchangeMatcher.MatchResult.match())
			.switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch());

		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository;

		private ServerAuthenticationEntryPoint entryPoint;

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private final List<ServerAuthenticationSuccessHandler> defaultSuccessHandlers = new ArrayList<>(
				List.of(new WebFilterChainServerAuthenticationSuccessHandler()));

		private List<ServerAuthenticationSuccessHandler> authenticationSuccessHandlers = new ArrayList<>();

		private HttpBasicSpec() {
			List<DelegateEntry> entryPoints = new ArrayList<>();
			entryPoints
				.add(new DelegateEntry(this.xhrMatcher, new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)));
			DelegatingServerAuthenticationEntryPoint defaultEntryPoint = new DelegatingServerAuthenticationEntryPoint(
					entryPoints);
			defaultEntryPoint.setDefaultEntryPoint(new HttpBasicServerAuthenticationEntryPoint());
			this.entryPoint = defaultEntryPoint;
		}

		/**
		 * The {@link ServerAuthenticationSuccessHandler} used after authentication
		 * success. Defaults to {@link WebFilterChainServerAuthenticationSuccessHandler}.
		 * Note that this method clears previously added success handlers via
		 * {@link #authenticationSuccessHandler(Consumer)}
		 * @param authenticationSuccessHandler the success handler to use
		 * @return the {@link HttpBasicSpec} to continue configuring
		 * @since 6.3
		 */
		public HttpBasicSpec authenticationSuccessHandler(
				ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
			Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
			authenticationSuccessHandler((handlers) -> {
				handlers.clear();
				handlers.add(authenticationSuccessHandler);
			});
			return this;
		}

		/**
		 * Allows customizing the list of {@link ServerAuthenticationSuccessHandler}. The
		 * default list contains a
		 * {@link WebFilterChainServerAuthenticationSuccessHandler}.
		 * @param handlersConsumer the handlers consumer
		 * @return the {@link HttpBasicSpec} to continue configuring
		 * @since 6.3
		 */
		public HttpBasicSpec authenticationSuccessHandler(
				Consumer<List<ServerAuthenticationSuccessHandler>> handlersConsumer) {
			Assert.notNull(handlersConsumer, "handlersConsumer cannot be null");
			handlersConsumer.accept(this.authenticationSuccessHandlers);
			return this;
		}

		/**
		 * The {@link ReactiveAuthenticationManager} used to authenticate. Defaults to
		 * {@link ServerHttpSecurity#authenticationManager(ReactiveAuthenticationManager)}.
		 * @param authenticationManager the authentication manager to use
		 * @return the {@link HttpBasicSpec} to continue configuring
		 */
		public HttpBasicSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * The {@link ServerSecurityContextRepository} used to save the
		 * {@code Authentication}. Defaults to
		 * {@link NoOpServerSecurityContextRepository}. For the {@code SecurityContext} to
		 * be loaded on subsequent requests the {@link ReactorContextWebFilter} must be
		 * configured to be able to load the value (they are not implicitly linked).
		 * @param securityContextRepository the repository to use
		 * @return the {@link HttpBasicSpec} to continue configuring
		 */
		public HttpBasicSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
			return this;
		}

		/**
		 * Allows easily setting the entry point.
		 * @param authenticationEntryPoint the {@link ServerAuthenticationEntryPoint} to
		 * use
		 * @return {@link HttpBasicSpec} for additional customization
		 * @since 5.2.0
		 */
		public HttpBasicSpec authenticationEntryPoint(ServerAuthenticationEntryPoint authenticationEntryPoint) {
			Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
			this.entryPoint = authenticationEntryPoint;
			return this;
		}

		public HttpBasicSpec authenticationFailureHandler(
				ServerAuthenticationFailureHandler authenticationFailureHandler) {
			Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #httpBasic(Customizer)} or
		 * {@code httpBasic(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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
					MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
					MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
					MediaType.TEXT_XML);
			restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerWebExchangeMatcher notHtmlMatcher = new NegatedServerWebExchangeMatcher(
					new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML));
			ServerWebExchangeMatcher restNotHtmlMatcher = new AndServerWebExchangeMatcher(
					Arrays.asList(notHtmlMatcher, restMatcher));
			ServerWebExchangeMatcher preferredMatcher = new OrServerWebExchangeMatcher(
					Arrays.asList(this.xhrMatcher, restNotHtmlMatcher));
			ServerHttpSecurity.this.defaultEntryPoints.add(new DelegateEntry(preferredMatcher, this.entryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(this.authenticationManager);
			authenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
			authenticationFilter.setAuthenticationConverter(new ServerHttpBasicAuthenticationConverter());
			authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			authenticationFilter.setAuthenticationSuccessHandler(getAuthenticationSuccessHandler(http));
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);
		}

		private ServerAuthenticationSuccessHandler getAuthenticationSuccessHandler(ServerHttpSecurity http) {
			if (this.authenticationSuccessHandlers.isEmpty()) {
				return new DelegatingServerAuthenticationSuccessHandler(this.defaultSuccessHandlers);
			}
			return new DelegatingServerAuthenticationSuccessHandler(this.authenticationSuccessHandlers);
		}

		private ServerAuthenticationFailureHandler authenticationFailureHandler() {
			if (this.authenticationFailureHandler != null) {
				return this.authenticationFailureHandler;
			}
			return new ServerAuthenticationEntryPointFailureHandler(this.entryPoint);
		}

	}

	/**
	 * Configures password management.
	 *
	 * @author Evgeniy Cheban
	 * @since 5.6
	 * @see #passwordManagement()
	 */
	public final class PasswordManagementSpec {

		private static final String WELL_KNOWN_CHANGE_PASSWORD_PATTERN = "/.well-known/change-password";

		private static final String DEFAULT_CHANGE_PASSWORD_PAGE = "/change-password";

		private String changePasswordPage = DEFAULT_CHANGE_PASSWORD_PAGE;

		/**
		 * Sets the change password page. Defaults to
		 * {@link PasswordManagementSpec#DEFAULT_CHANGE_PASSWORD_PAGE}.
		 * @param changePasswordPage the change password page
		 * @return the {@link PasswordManagementSpec} to continue configuring
		 */
		public PasswordManagementSpec changePasswordPage(String changePasswordPage) {
			Assert.hasText(changePasswordPage, "changePasswordPage cannot be empty");
			this.changePasswordPage = changePasswordPage;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}.
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #passwordManagement(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			ExchangeMatcherRedirectWebFilter changePasswordWebFilter = new ExchangeMatcherRedirectWebFilter(
					new PathPatternParserServerWebExchangeMatcher(WELL_KNOWN_CHANGE_PASSWORD_PATTERN),
					this.changePasswordPage);
			http.addFilterBefore(changePasswordWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);
		}

		private PasswordManagementSpec() {
		}

	}

	/**
	 * Configures Form Based authentication
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #formLogin()
	 */
	public final class FormLoginSpec {

		private final RedirectServerAuthenticationSuccessHandler defaultSuccessHandler = new RedirectServerAuthenticationSuccessHandler(
				"/");

		private final List<ServerAuthenticationSuccessHandler> defaultSuccessHandlers = new ArrayList<>(
				List.of(this.defaultSuccessHandler));

		private RedirectServerAuthenticationEntryPoint defaultEntryPoint;

		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository;

		private ServerAuthenticationEntryPoint authenticationEntryPoint;

		private boolean isEntryPointExplicit;

		private ServerWebExchangeMatcher requiresAuthenticationMatcher;

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private List<ServerAuthenticationSuccessHandler> authenticationSuccessHandlers = new ArrayList<>();

		private FormLoginSpec() {
		}

		/**
		 * The {@link ReactiveAuthenticationManager} used to authenticate. Defaults to
		 * {@link ServerHttpSecurity#authenticationManager(ReactiveAuthenticationManager)}.
		 * @param authenticationManager the authentication manager to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 */
		public FormLoginSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * The {@link ServerAuthenticationSuccessHandler} used after authentication
		 * success. Defaults to {@link RedirectServerAuthenticationSuccessHandler}. Note
		 * that this method clears previously added success handlers via
		 * {@link #authenticationSuccessHandler(Consumer)}
		 * @param authenticationSuccessHandler the success handler to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 */
		public FormLoginSpec authenticationSuccessHandler(
				ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
			Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
			authenticationSuccessHandler((handlers) -> {
				handlers.clear();
				handlers.add(authenticationSuccessHandler);
			});
			return this;
		}

		/**
		 * Allows customizing the list of {@link ServerAuthenticationSuccessHandler}. The
		 * default list contains a {@link RedirectServerAuthenticationSuccessHandler} that
		 * redirects to "/".
		 * @param handlersConsumer the handlers consumer
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @since 6.3
		 */
		public FormLoginSpec authenticationSuccessHandler(
				Consumer<List<ServerAuthenticationSuccessHandler>> handlersConsumer) {
			Assert.notNull(handlersConsumer, "handlersConsumer cannot be null");
			handlersConsumer.accept(this.authenticationSuccessHandlers);
			return this;
		}

		/**
		 * Configures the log in page to redirect to, the authentication failure page, and
		 * when authentication is performed. The default is that Spring Security will
		 * generate a log in page at "/login" and a log out page at "/logout". If this is
		 * customized:
		 * <ul>
		 * <li>The default log in &amp; log out page are no longer provided</li>
		 * <li>The application must render a log in page at the provided URL</li>
		 * <li>The application must render an authentication error page at the provided
		 * URL + "?error"</li>
		 * <li>Authentication will occur for POST to the provided URL</li>
		 * </ul>
		 * @param loginPage the url to redirect to which provides a form to log in (i.e.
		 * "/login")
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @see #authenticationEntryPoint(ServerAuthenticationEntryPoint)
		 * @see #requiresAuthenticationMatcher(ServerWebExchangeMatcher)
		 * @see #authenticationFailureHandler(ServerAuthenticationFailureHandler)
		 */
		public FormLoginSpec loginPage(String loginPage) {
			this.defaultEntryPoint = new RedirectServerAuthenticationEntryPoint(loginPage);
			this.authenticationEntryPoint = this.defaultEntryPoint;
			if (this.requiresAuthenticationMatcher == null) {
				this.requiresAuthenticationMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, loginPage);
			}
			if (this.authenticationFailureHandler == null) {
				this.authenticationFailureHandler = new RedirectServerAuthenticationFailureHandler(
						loginPage + "?error");
			}
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
		 * Configures how a failed authentication is handled. The default is to redirect
		 * to "/login?error".
		 * @param authenticationFailureHandler the handler to use
		 * @return the {@link FormLoginSpec} to continue configuring
		 * @see #loginPage(String)
		 */
		public FormLoginSpec authenticationFailureHandler(
				ServerAuthenticationFailureHandler authenticationFailureHandler) {
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		/**
		 * The {@link ServerSecurityContextRepository} used to save the
		 * {@code Authentication}. Defaults to
		 * {@link WebSessionServerSecurityContextRepository}. For the
		 * {@code SecurityContext} to be loaded on subsequent requests the
		 * {@link ReactorContextWebFilter} must be configured to be able to load the value
		 * (they are not implicitly linked).
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
		 * @deprecated For removal in 7.0. Use {@link #formLogin(Customizer)} or
		 * {@code formLogin(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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
			}
			else {
				this.isEntryPointExplicit = true;
			}
			if (http.requestCache != null) {
				ServerRequestCache requestCache = http.requestCache.requestCache;
				this.defaultSuccessHandler.setRequestCache(requestCache);
				if (this.defaultEntryPoint != null) {
					this.defaultEntryPoint.setRequestCache(requestCache);
				}
			}
			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerHttpSecurity.this.defaultEntryPoints.add(0,
					new DelegateEntry(htmlMatcher, this.authenticationEntryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(this.authenticationManager);
			authenticationFilter.setRequiresAuthenticationMatcher(this.requiresAuthenticationMatcher);
			authenticationFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
			authenticationFilter.setAuthenticationConverter(new ServerFormLoginAuthenticationConverter());
			authenticationFilter.setAuthenticationSuccessHandler(getAuthenticationSuccessHandler(http));
			authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.FORM_LOGIN);
		}

		private ServerAuthenticationSuccessHandler getAuthenticationSuccessHandler(ServerHttpSecurity http) {
			if (this.authenticationSuccessHandlers.isEmpty()) {
				return new DelegatingServerAuthenticationSuccessHandler(this.defaultSuccessHandlers);
			}
			return new DelegatingServerAuthenticationSuccessHandler(this.authenticationSuccessHandlers);
		}

	}

	private final class LoginPageSpec {

		private LoginPageSpec() {
		}

		protected void configure(ServerHttpSecurity http) {
			if (http.authenticationEntryPoint != null) {
				return;
			}
			if (http.formLogin != null && http.formLogin.isEntryPointExplicit
					|| http.oauth2Login != null && StringUtils.hasText(http.oauth2Login.loginPage)) {
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
				http.addFilterBefore(DefaultResourcesWebFilter.css(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING);
				if (http.logout != null) {
					http.addFilterAt(new LogoutPageGeneratingWebFilter(),
							SecurityWebFiltersOrder.LOGOUT_PAGE_GENERATING);
				}
			}
		}

	}

	/**
	 * Configures HTTP Response Headers.
	 *
	 * @author Rob Winch
	 * @since 5.0
	 * @see #headers()
	 */
	public final class HeaderSpec {

		private final List<ServerHttpHeadersWriter> writers;

		private CacheControlServerHttpHeadersWriter cacheControl = new CacheControlServerHttpHeadersWriter();

		private ContentTypeOptionsServerHttpHeadersWriter contentTypeOptions = new ContentTypeOptionsServerHttpHeadersWriter();

		private StrictTransportSecurityServerHttpHeadersWriter hsts = new StrictTransportSecurityServerHttpHeadersWriter();

		private XFrameOptionsServerHttpHeadersWriter frameOptions = new XFrameOptionsServerHttpHeadersWriter();

		private XXssProtectionServerHttpHeadersWriter xss = new XXssProtectionServerHttpHeadersWriter();

		private FeaturePolicyServerHttpHeadersWriter featurePolicy = new FeaturePolicyServerHttpHeadersWriter();

		private PermissionsPolicyServerHttpHeadersWriter permissionsPolicy = new PermissionsPolicyServerHttpHeadersWriter();

		private ContentSecurityPolicyServerHttpHeadersWriter contentSecurityPolicy = new ContentSecurityPolicyServerHttpHeadersWriter();

		private ReferrerPolicyServerHttpHeadersWriter referrerPolicy = new ReferrerPolicyServerHttpHeadersWriter();

		private CrossOriginOpenerPolicyServerHttpHeadersWriter crossOriginOpenerPolicy = new CrossOriginOpenerPolicyServerHttpHeadersWriter();

		private CrossOriginEmbedderPolicyServerHttpHeadersWriter crossOriginEmbedderPolicy = new CrossOriginEmbedderPolicyServerHttpHeadersWriter();

		private CrossOriginResourcePolicyServerHttpHeadersWriter crossOriginResourcePolicy = new CrossOriginResourcePolicyServerHttpHeadersWriter();

		private HeaderSpec() {
			this.writers = new ArrayList<>(Arrays.asList(this.cacheControl, this.contentTypeOptions, this.hsts,
					this.frameOptions, this.xss, this.featurePolicy, this.permissionsPolicy, this.contentSecurityPolicy,
					this.referrerPolicy, this.crossOriginOpenerPolicy, this.crossOriginEmbedderPolicy,
					this.crossOriginResourcePolicy));
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #headers(Customizer)} or
		 * {@code headers(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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
		 * @deprecated For removal in 7.0. Use {@link #cache(Customizer)} or
		 * {@code cache(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public CacheSpec cache() {
			return new CacheSpec();
		}

		/**
		 * Configures cache control headers
		 * @param cacheCustomizer the {@link Customizer} to provide more options for the
		 * {@link CacheSpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec cache(Customizer<CacheSpec> cacheCustomizer) {
			cacheCustomizer.customize(new CacheSpec());
			return this;
		}

		/**
		 * Configures content type response headers
		 * @return the {@link ContentTypeOptionsSpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #contentTypeOptions(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ContentTypeOptionsSpec contentTypeOptions() {
			return new ContentTypeOptionsSpec();
		}

		/**
		 * Configures content type response headers
		 * @param contentTypeOptionsCustomizer the {@link Customizer} to provide more
		 * options for the {@link ContentTypeOptionsSpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec contentTypeOptions(Customizer<ContentTypeOptionsSpec> contentTypeOptionsCustomizer) {
			contentTypeOptionsCustomizer.customize(new ContentTypeOptionsSpec());
			return this;
		}

		/**
		 * Configures frame options response headers
		 * @return the {@link FrameOptionsSpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #frameOptions(Customizer)} or
		 * {@code frameOptions(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public FrameOptionsSpec frameOptions() {
			return new FrameOptionsSpec();
		}

		/**
		 * Configures frame options response headers
		 * @param frameOptionsCustomizer the {@link Customizer} to provide more options
		 * for the {@link FrameOptionsSpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec frameOptions(Customizer<FrameOptionsSpec> frameOptionsCustomizer) {
			frameOptionsCustomizer.customize(new FrameOptionsSpec());
			return this;
		}

		/**
		 * Configures custom headers writer
		 * @param serverHttpHeadersWriter the {@link ServerHttpHeadersWriter} to provide
		 * custom headers writer
		 * @return the {@link HeaderSpec} to customize
		 * @since 5.3.0
		 */
		public HeaderSpec writer(ServerHttpHeadersWriter serverHttpHeadersWriter) {
			Assert.notNull(serverHttpHeadersWriter, "serverHttpHeadersWriter cannot be null");
			this.writers.add(serverHttpHeadersWriter);
			return this;
		}

		/**
		 * Configures the Strict Transport Security response headers
		 * @return the {@link HstsSpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #hsts(Customizer)} or
		 * {@code hsts(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public HstsSpec hsts() {
			return new HstsSpec();
		}

		/**
		 * Configures the Strict Transport Security response headers
		 * @param hstsCustomizer the {@link Customizer} to provide more options for the
		 * {@link HstsSpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec hsts(Customizer<HstsSpec> hstsCustomizer) {
			hstsCustomizer.customize(new HstsSpec());
			return this;
		}

		protected void configure(ServerHttpSecurity http) {
			ServerHttpHeadersWriter writer = new CompositeServerHttpHeadersWriter(this.writers);
			HttpHeaderWriterWebFilter result = new HttpHeaderWriterWebFilter(writer);
			http.addFilterAt(result, SecurityWebFiltersOrder.HTTP_HEADERS_WRITER);
		}

		/**
		 * Configures x-xss-protection response header.
		 * @return the {@link XssProtectionSpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #xssProtection(Customizer)} or
		 * {@code xssProtection(Customizer.withDefaults())} to stick with defaults. See
		 * the <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public XssProtectionSpec xssProtection() {
			return new XssProtectionSpec();
		}

		/**
		 * Configures x-xss-protection response header.
		 * @param xssProtectionCustomizer the {@link Customizer} to provide more options
		 * for the {@link XssProtectionSpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec xssProtection(Customizer<XssProtectionSpec> xssProtectionCustomizer) {
			xssProtectionCustomizer.customize(new XssProtectionSpec());
			return this;
		}

		/**
		 * Configures {@code Content-Security-Policy} response header.
		 * @param policyDirectives the policy directive(s)
		 * @return the {@link ContentSecurityPolicySpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #contentSecurityPolicy(Customizer)}
		 * instead.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ContentSecurityPolicySpec contentSecurityPolicy(String policyDirectives) {
			return new ContentSecurityPolicySpec(policyDirectives);
		}

		/**
		 * Configures {@code Content-Security-Policy} response header.
		 * @param contentSecurityPolicyCustomizer the {@link Customizer} to provide more
		 * options for the {@link ContentSecurityPolicySpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec contentSecurityPolicy(Customizer<ContentSecurityPolicySpec> contentSecurityPolicyCustomizer) {
			contentSecurityPolicyCustomizer.customize(new ContentSecurityPolicySpec());
			return this;
		}

		/**
		 * Configures {@code Feature-Policy} response header.
		 * @param policyDirectives the policy
		 * @return the {@link FeaturePolicySpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #permissionsPolicy(Customizer)}
		 * instead.
		 */
		@Deprecated
		public FeaturePolicySpec featurePolicy(String policyDirectives) {
			return new FeaturePolicySpec(policyDirectives);
		}

		/**
		 * Configures {@code Permissions-Policy} response header.
		 * @return the {@link PermissionsPolicySpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #permissionsPolicy(Customizer)}
		 * instead.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public PermissionsPolicySpec permissionsPolicy() {
			return new PermissionsPolicySpec();
		}

		/**
		 * Configures {@code Permissions-Policy} response header.
		 * @param permissionsPolicyCustomizer the {@link Customizer} to provide more
		 * options for the {@link PermissionsPolicySpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec permissionsPolicy(Customizer<PermissionsPolicySpec> permissionsPolicyCustomizer) {
			permissionsPolicyCustomizer.customize(new PermissionsPolicySpec());
			return this;
		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 * @param referrerPolicy the policy to use
		 * @return the {@link ReferrerPolicySpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #referrerPolicy(Customizer)}
		 * instead.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ReferrerPolicySpec referrerPolicy(ReferrerPolicy referrerPolicy) {
			return new ReferrerPolicySpec(referrerPolicy);
		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 * @return the {@link ReferrerPolicySpec} to configure
		 * @deprecated For removal in 7.0. Use {@link #referrerPolicy(Customizer)}
		 * instead.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ReferrerPolicySpec referrerPolicy() {
			return new ReferrerPolicySpec();
		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 * @param referrerPolicyCustomizer the {@link Customizer} to provide more options
		 * for the {@link ReferrerPolicySpec}
		 * @return the {@link HeaderSpec} to customize
		 */
		public HeaderSpec referrerPolicy(Customizer<ReferrerPolicySpec> referrerPolicyCustomizer) {
			referrerPolicyCustomizer.customize(new ReferrerPolicySpec());
			return this;
		}

		/**
		 * Configures the <a href=
		 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">
		 * Cross-Origin-Opener-Policy</a> header.
		 * @return the {@link CrossOriginOpenerPolicySpec} to configure
		 * @since 5.7
		 * @deprecated For removal in 7.0. Use
		 * {@link #crossOriginOpenerPolicy(Customizer)} instead.
		 * @see CrossOriginOpenerPolicyServerHttpHeadersWriter
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public CrossOriginOpenerPolicySpec crossOriginOpenerPolicy() {
			return new CrossOriginOpenerPolicySpec();
		}

		/**
		 * Configures the <a href=
		 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">
		 * Cross-Origin-Opener-Policy</a> header.
		 * @return the {@link HeaderSpec} to customize
		 * @since 5.7
		 * @see CrossOriginOpenerPolicyServerHttpHeadersWriter
		 */
		public HeaderSpec crossOriginOpenerPolicy(
				Customizer<CrossOriginOpenerPolicySpec> crossOriginOpenerPolicyCustomizer) {
			crossOriginOpenerPolicyCustomizer.customize(new CrossOriginOpenerPolicySpec());
			return this;
		}

		/**
		 * Configures the <a href=
		 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">
		 * Cross-Origin-Embedder-Policy</a> header.
		 * @return the {@link CrossOriginEmbedderPolicySpec} to configure
		 * @since 5.7
		 * @deprecated For removal in 7.0. Use
		 * {@link #crossOriginEmbedderPolicy(Customizer)} instead.
		 * @see CrossOriginEmbedderPolicyServerHttpHeadersWriter
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public CrossOriginEmbedderPolicySpec crossOriginEmbedderPolicy() {
			return new CrossOriginEmbedderPolicySpec();
		}

		/**
		 * Configures the <a href=
		 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">
		 * Cross-Origin-Embedder-Policy</a> header.
		 * @return the {@link HeaderSpec} to customize
		 * @since 5.7
		 * @see CrossOriginEmbedderPolicyServerHttpHeadersWriter
		 */
		public HeaderSpec crossOriginEmbedderPolicy(
				Customizer<CrossOriginEmbedderPolicySpec> crossOriginEmbedderPolicyCustomizer) {
			crossOriginEmbedderPolicyCustomizer.customize(new CrossOriginEmbedderPolicySpec());
			return this;
		}

		/**
		 * Configures the <a href=
		 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy">
		 * Cross-Origin-Resource-Policy</a> header.
		 * @return the {@link CrossOriginResourcePolicySpec} to configure
		 * @since 5.7
		 * @deprecated For removal in 7.0. Use
		 * {@link #crossOriginResourcePolicy(Customizer)} instead.
		 * @see CrossOriginResourcePolicyServerHttpHeadersWriter
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public CrossOriginResourcePolicySpec crossOriginResourcePolicy() {
			return new CrossOriginResourcePolicySpec();
		}

		/**
		 * Configures the <a href=
		 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy">
		 * Cross-Origin-Resource-Policy</a> header.
		 * @return the {@link HeaderSpec} to customize
		 * @since 5.7
		 * @see CrossOriginResourcePolicyServerHttpHeadersWriter
		 */
		public HeaderSpec crossOriginResourcePolicy(
				Customizer<CrossOriginResourcePolicySpec> crossOriginResourcePolicyCustomizer) {
			crossOriginResourcePolicyCustomizer.customize(new CrossOriginResourcePolicySpec());
			return this;
		}

		/**
		 * Configures cache control headers
		 *
		 * @see #cache()
		 */
		public final class CacheSpec {

			private CacheSpec() {
			}

			/**
			 * Disables cache control response headers
			 * @return the {@link HeaderSpec} to configure
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.cacheControl);
				return HeaderSpec.this;
			}

		}

		/**
		 * The content type headers
		 *
		 * @see #contentTypeOptions()
		 */
		public final class ContentTypeOptionsSpec {

			private ContentTypeOptionsSpec() {
			}

			/**
			 * Disables the content type options response header
			 * @return the {@link HeaderSpec} to configure
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.contentTypeOptions);
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures frame options response header
		 *
		 * @see #frameOptions()
		 */
		public final class FrameOptionsSpec {

			private FrameOptionsSpec() {
			}

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
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use {@link #frameOptions(Customizer)}
			 * instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
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

		}

		/**
		 * Configures Strict Transport Security response header
		 *
		 * @see #hsts()
		 */
		public final class HstsSpec {

			private HstsSpec() {
			}

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
			 * <p>
			 * Configures if preload should be included. Default is false
			 * </p>
			 *
			 * <p>
			 * See <a href="https://hstspreload.org/">Website hstspreload.org</a> for
			 * additional details.
			 * </p>
			 * @param preload if subdomains should be included
			 * @return the {@link HstsSpec} to continue configuring
			 * @since 5.2.0
			 */
			public HstsSpec preload(boolean preload) {
				HeaderSpec.this.hsts.setPreload(preload);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use {@link #hsts(Customizer)} or
			 * {@code hsts(Customizer.withDefaults())} to stick with defaults. See the
			 * <a href=
			 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
			 * for more details.
			 */
			@Deprecated(since = "6.1", forRemoval = true)
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

		}

		/**
		 * Configures x-xss-protection response header
		 *
		 * @see #xssProtection()
		 */
		public final class XssProtectionSpec {

			private XssProtectionSpec() {
			}

			/**
			 * Disables the x-xss-protection response header
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.xss);
				return HeaderSpec.this;
			}

			/**
			 * Sets the value of x-xss-protection header. OWASP recommends using
			 * {@link XXssProtectionServerHttpHeadersWriter.HeaderValue#DISABLED}.
			 * @param headerValue the headerValue
			 * @return the {@link HeaderSpec} to continue configuring
			 * @since 5.8
			 */
			public HeaderSpec headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue headerValue) {
				HeaderSpec.this.xss.setHeaderValue(headerValue);
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures {@code Content-Security-Policy} response header.
		 *
		 * @since 5.1
		 * @see #contentSecurityPolicy(String)
		 */
		public final class ContentSecurityPolicySpec {

			private static final String DEFAULT_SRC_SELF_POLICY = "default-src 'self'";

			private ContentSecurityPolicySpec() {
				HeaderSpec.this.contentSecurityPolicy.setPolicyDirectives(DEFAULT_SRC_SELF_POLICY);
			}

			/**
			 * Whether to include the {@code Content-Security-Policy-Report-Only} header
			 * in the response. Otherwise, defaults to the {@code Content-Security-Policy}
			 * header.
			 * @param reportOnly whether to only report policy violations
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec reportOnly(boolean reportOnly) {
				HeaderSpec.this.contentSecurityPolicy.setReportOnly(reportOnly);
				return HeaderSpec.this;
			}

			/**
			 * Sets the security policy directive(s) to be used in the response header.
			 * @param policyDirectives the security policy directive(s)
			 * @return the {@link HeaderSpec} to continue configuring
			 */
			public HeaderSpec policyDirectives(String policyDirectives) {
				HeaderSpec.this.contentSecurityPolicy.setPolicyDirectives(policyDirectives);
				return HeaderSpec.this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use
			 * {@link #contentSecurityPolicy(Customizer)} instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
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
		 * @since 5.1
		 * @see #featurePolicy(String)
		 */
		public final class FeaturePolicySpec {

			private FeaturePolicySpec(String policyDirectives) {
				HeaderSpec.this.featurePolicy.setPolicyDirectives(policyDirectives);
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use {@link #featurePolicy(Customizer)}
			 * instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures {@code Permissions-Policy} response header.
		 *
		 * @since 5.5
		 * @see #permissionsPolicy()
		 */
		public final class PermissionsPolicySpec {

			private PermissionsPolicySpec() {
			}

			/**
			 * Sets the policy to be used in the response header.
			 * @param policy a permissions policy
			 * @return the {@link PermissionsPolicySpec} to continue configuring
			 */
			public PermissionsPolicySpec policy(String policy) {
				HeaderSpec.this.permissionsPolicy.setPolicy(policy);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use {@link #permissionsPolicy(Customizer)}
			 * instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures {@code Referrer-Policy} response header.
		 *
		 * @since 5.1
		 * @see #referrerPolicy()
		 * @see #referrerPolicy(ReferrerPolicy)
		 */
		public final class ReferrerPolicySpec {

			private ReferrerPolicySpec() {
			}

			private ReferrerPolicySpec(ReferrerPolicy referrerPolicy) {
				HeaderSpec.this.referrerPolicy.setPolicy(referrerPolicy);
			}

			/**
			 * Sets the policy to be used in the response header.
			 * @param referrerPolicy a referrer policy
			 * @return the {@link ReferrerPolicySpec} to continue configuring
			 */
			public ReferrerPolicySpec policy(ReferrerPolicy referrerPolicy) {
				HeaderSpec.this.referrerPolicy.setPolicy(referrerPolicy);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use {@link #referrerPolicy(Customizer)}
			 * instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures the Cross-Origin-Opener-Policy header
		 *
		 * @since 5.7
		 */
		public final class CrossOriginOpenerPolicySpec {

			private CrossOriginOpenerPolicySpec() {
			}

			/**
			 * Sets the value to be used in the `Cross-Origin-Opener-Policy` header
			 * @param openerPolicy a opener policy
			 * @return the {@link CrossOriginOpenerPolicySpec} to continue configuring
			 */
			public CrossOriginOpenerPolicySpec policy(CrossOriginOpenerPolicy openerPolicy) {
				HeaderSpec.this.crossOriginOpenerPolicy.setPolicy(openerPolicy);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use
			 * {@link #crossOriginOpenerPolicy(Customizer)} instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures the Cross-Origin-Embedder-Policy header
		 *
		 * @since 5.7
		 */
		public final class CrossOriginEmbedderPolicySpec {

			private CrossOriginEmbedderPolicySpec() {
			}

			/**
			 * Sets the value to be used in the `Cross-Origin-Embedder-Policy` header
			 * @param embedderPolicy a opener policy
			 * @return the {@link CrossOriginEmbedderPolicySpec} to continue configuring
			 */
			public CrossOriginEmbedderPolicySpec policy(CrossOriginEmbedderPolicy embedderPolicy) {
				HeaderSpec.this.crossOriginEmbedderPolicy.setPolicy(embedderPolicy);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use
			 * {@link #crossOriginEmbedderPolicy(Customizer)} instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

		}

		/**
		 * Configures the Cross-Origin-Resource-Policy header
		 *
		 * @since 5.7
		 */
		public final class CrossOriginResourcePolicySpec {

			private CrossOriginResourcePolicySpec() {
			}

			/**
			 * Sets the value to be used in the `Cross-Origin-Resource-Policy` header
			 * @param resourcePolicy a opener policy
			 * @return the {@link CrossOriginResourcePolicySpec} to continue configuring
			 */
			public CrossOriginResourcePolicySpec policy(CrossOriginResourcePolicy resourcePolicy) {
				HeaderSpec.this.crossOriginResourcePolicy.setPolicy(resourcePolicy);
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}.
			 * @return the {@link HeaderSpec} to continue configuring
			 * @deprecated For removal in 7.0. Use
			 * {@link #crossOriginResourcePolicy(Customizer)} instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public HeaderSpec and() {
				return HeaderSpec.this;
			}

		}

	}

	/**
	 * Configures log out
	 *
	 * @author Shazin Sadakath
	 * @since 5.0
	 * @see #logout()
	 */
	public final class LogoutSpec {

		private LogoutWebFilter logoutWebFilter = new LogoutWebFilter();

		private final SecurityContextServerLogoutHandler DEFAULT_LOGOUT_HANDLER = new SecurityContextServerLogoutHandler();

		private List<ServerLogoutHandler> logoutHandlers = new ArrayList<>(Arrays.asList(this.DEFAULT_LOGOUT_HANDLER));

		private LogoutSpec() {
		}

		/**
		 * Configures the logout handler. Default is
		 * {@code SecurityContextServerLogoutHandler}
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
		 * @param logoutUrl the url to trigger a log out (i.e. "/signout" would mean a
		 * POST to "/signout" would trigger log out)
		 * @return the {@link LogoutSpec} to configure
		 */
		public LogoutSpec logoutUrl(String logoutUrl) {
			Assert.notNull(logoutUrl, "logoutUrl must not be null");
			ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,
					logoutUrl);
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
		 * @deprecated For removal in 7.0. Use {@link #logout(Customizer)} or
		 * {@code logout(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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

		private ServerLogoutHandler createLogoutHandler() {
			ServerSecurityContextRepository securityContextRepository = ServerHttpSecurity.this.securityContextRepository;
			if (securityContextRepository != null) {
				this.DEFAULT_LOGOUT_HANDLER.setSecurityContextRepository(securityContextRepository);
			}
			if (this.logoutHandlers.isEmpty()) {
				return null;
			}
			if (this.logoutHandlers.size() == 1) {
				return this.logoutHandlers.get(0);
			}
			return new DelegatingServerLogoutHandler(this.logoutHandlers);
		}

		protected void configure(ServerHttpSecurity http) {
			ServerLogoutHandler logoutHandler = createLogoutHandler();
			if (logoutHandler != null) {
				this.logoutWebFilter.setLogoutHandler(logoutHandler);
			}
			http.addFilterAt(this.logoutWebFilter, SecurityWebFiltersOrder.LOGOUT);
		}

	}

	private static class OrderedWebFilter implements WebFilter, Ordered {

		private final WebFilter webFilter;

		private final int order;

		OrderedWebFilter(WebFilter webFilter, int order) {
			this.webFilter = webFilter;
			this.order = order;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return this.webFilter.filter(exchange, chain);
		}

		@Override
		public int getOrder() {
			return this.order;
		}

		@Override
		public String toString() {
			return "OrderedWebFilter{" + "webFilter=" + this.webFilter + ", order=" + this.order + '}';
		}

	}

	/**
	 * Workaround https://jira.spring.io/projects/SPR/issues/SPR-17213
	 */
	static class ServerWebExchangeReactorContextWebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange).contextWrite(Context.of(ServerWebExchange.class, exchange));
		}

	}

	/**
	 * Configures CORS support within Spring Security. This ensures that the
	 * {@link CorsWebFilter} is place in the correct order.
	 */
	public final class CorsSpec {

		private CorsWebFilter corsFilter;

		private CorsSpec() {
		}

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
		 * @deprecated For removal in 7.0. Use {@link #cors(Customizer)} or
		 * {@code cors(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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

	}

	/**
	 * Configures X509 authentication
	 *
	 * @author Alexey Nesterov
	 * @since 5.2
	 * @see #x509()
	 */
	public final class X509Spec {

		private X509PrincipalExtractor principalExtractor;

		private ReactiveAuthenticationManager authenticationManager;

		private X509Spec() {
		}

		public X509Spec principalExtractor(X509PrincipalExtractor principalExtractor) {
			this.principalExtractor = principalExtractor;
			return this;
		}

		public X509Spec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * @deprecated For removal in 7.0. Use {@link #x509(Customizer)} or
		 * {@code x509(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
			X509PrincipalExtractor principalExtractor = getPrincipalExtractor();
			AuthenticationWebFilter filter = new AuthenticationWebFilter(authenticationManager);
			filter.setServerAuthenticationConverter(new ServerX509AuthenticationConverter(principalExtractor));
			http.addFilterAt(filter, SecurityWebFiltersOrder.AUTHENTICATION);
		}

		private X509PrincipalExtractor getPrincipalExtractor() {
			if (this.principalExtractor != null) {
				return this.principalExtractor;
			}
			return new SubjectDnX509PrincipalExtractor();
		}

		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager != null) {
				return this.authenticationManager;
			}
			ReactiveUserDetailsService userDetailsService = getBean(ReactiveUserDetailsService.class);
			return new ReactivePreAuthenticatedAuthenticationManager(userDetailsService);
		}

	}

	public final class OAuth2LoginSpec {

		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

		private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository;

		private ServerAuthenticationConverter authenticationConverter;

		private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;

		private ServerRedirectStrategy authorizationRedirectStrategy;

		private ServerWebExchangeMatcher authenticationMatcher;

		private ReactiveOidcSessionRegistry oidcSessionRegistry;

		private final RedirectServerAuthenticationSuccessHandler defaultAuthenticationSuccessHandler = new RedirectServerAuthenticationSuccessHandler();

		private final List<ServerAuthenticationSuccessHandler> defaultSuccessHandlers = new ArrayList<>(
				List.of(this.defaultAuthenticationSuccessHandler));

		private List<ServerAuthenticationSuccessHandler> authenticationSuccessHandlers = new ArrayList<>();

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private String loginPage;

		private OAuth2LoginSpec() {
		}

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
		 * The {@link ServerSecurityContextRepository} used to save the
		 * {@code Authentication}. Defaults to
		 * {@link WebSessionServerSecurityContextRepository}.
		 * @param securityContextRepository the repository to use
		 * @return the {@link OAuth2LoginSpec} to continue configuring
		 * @since 5.2
		 */
		public OAuth2LoginSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
			return this;
		}

		/**
		 * Configures the {@link ReactiveOidcSessionRegistry} to use when logins use OIDC.
		 * Default is to look the value up as a Bean, or else use an
		 * {@link InMemoryReactiveOidcSessionRegistry}.
		 * @param oidcSessionRegistry the registry to use
		 * @return the {@link OidcLogoutSpec} to customize
		 * @since 6.2
		 */
		public OAuth2LoginSpec oidcSessionRegistry(ReactiveOidcSessionRegistry oidcSessionRegistry) {
			Assert.notNull(oidcSessionRegistry, "oidcSessionRegistry cannot be null");
			this.oidcSessionRegistry = oidcSessionRegistry;
			return this;
		}

		/**
		 * The {@link ServerAuthenticationSuccessHandler} used after authentication
		 * success. Defaults to {@link RedirectServerAuthenticationSuccessHandler}
		 * redirecting to "/". Note that this method clears previously added success
		 * handlers via {@link #authenticationSuccessHandler(Consumer)}
		 * @param authenticationSuccessHandler the success handler to use
		 * @return the {@link OAuth2LoginSpec} to customize
		 * @since 5.2
		 */
		public OAuth2LoginSpec authenticationSuccessHandler(
				ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
			Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
			authenticationSuccessHandler((handlers) -> {
				handlers.clear();
				handlers.add(authenticationSuccessHandler);
			});
			return this;
		}

		/**
		 * Allows customizing the list of {@link ServerAuthenticationSuccessHandler}. The
		 * default list contains a {@link RedirectServerAuthenticationSuccessHandler} that
		 * redirects to "/".
		 * @param handlersConsumer the handlers consumer
		 * @return the {@link OAuth2LoginSpec} to continue configuring
		 * @since 6.3
		 */
		public OAuth2LoginSpec authenticationSuccessHandler(
				Consumer<List<ServerAuthenticationSuccessHandler>> handlersConsumer) {
			Assert.notNull(handlersConsumer, "handlersConsumer cannot be null");
			handlersConsumer.accept(this.authenticationSuccessHandlers);
			return this;
		}

		/**
		 * The {@link ServerAuthenticationFailureHandler} used after authentication
		 * failure. Defaults to {@link RedirectServerAuthenticationFailureHandler}
		 * redirecting to "/login?error".
		 * @param authenticationFailureHandler the failure handler to use
		 * @return the {@link OAuth2LoginSpec} to customize
		 * @since 5.2
		 */
		public OAuth2LoginSpec authenticationFailureHandler(
				ServerAuthenticationFailureHandler authenticationFailureHandler) {
			Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		/**
		 * Gets the {@link ReactiveAuthenticationManager} to use. First tries an
		 * explicitly configured manager, and defaults to
		 * {@link OAuth2AuthorizationCodeReactiveAuthenticationManager}
		 * @return the {@link ReactiveAuthenticationManager} to use
		 */
		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				this.authenticationManager = createDefault();
			}
			return this.authenticationManager;
		}

		private ReactiveAuthenticationManager createDefault() {
			ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> client = getAccessTokenResponseClient();
			OAuth2LoginReactiveAuthenticationManager oauth2Manager = new OAuth2LoginReactiveAuthenticationManager(
					client, getOauth2UserService());
			GrantedAuthoritiesMapper authoritiesMapper = getBeanOrNull(GrantedAuthoritiesMapper.class);
			if (authoritiesMapper != null) {
				oauth2Manager.setAuthoritiesMapper(authoritiesMapper);
			}
			boolean oidcAuthenticationProviderEnabled = ClassUtils
				.isPresent("org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());
			if (!oidcAuthenticationProviderEnabled) {
				return oauth2Manager;
			}
			OidcAuthorizationCodeReactiveAuthenticationManager oidc = new OidcAuthorizationCodeReactiveAuthenticationManager(
					client, getOidcUserService());
			ResolvableType type = ResolvableType.forClassWithGenerics(ReactiveJwtDecoderFactory.class,
					ClientRegistration.class);
			ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory = getBeanOrNull(type);
			if (jwtDecoderFactory != null) {
				oidc.setJwtDecoderFactory(jwtDecoderFactory);
			}
			if (authoritiesMapper != null) {
				oidc.setAuthoritiesMapper(authoritiesMapper);
			}
			return new DelegatingReactiveAuthenticationManager(oidc, oauth2Manager);
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

		private ServerAuthenticationConverter getAuthenticationConverter(
				ReactiveClientRegistrationRepository clientRegistrationRepository) {
			if (this.authenticationConverter != null) {
				return this.authenticationConverter;
			}
			ServerOAuth2AuthorizationCodeAuthenticationTokenConverter delegate = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
					clientRegistrationRepository);
			delegate.setAuthorizationRequestRepository(getAuthorizationRequestRepository());
			ServerAuthenticationConverter authenticationConverter = (exchange) -> delegate.convert(exchange)
				.onErrorMap(OAuth2AuthorizationException.class,
						(e) -> new OAuth2AuthenticationException(e.getError(), e.getError().toString()));
			this.authenticationConverter = authenticationConverter;
			return authenticationConverter;
		}

		public OAuth2LoginSpec clientRegistrationRepository(
				ReactiveClientRegistrationRepository clientRegistrationRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
			return this;
		}

		public OAuth2LoginSpec authorizedClientService(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
			this.authorizedClientRepository = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
					authorizedClientService);
			return this;
		}

		public OAuth2LoginSpec authorizedClientRepository(
				ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.authorizedClientRepository = authorizedClientRepository;
			return this;
		}

		/**
		 * Sets the repository to use for storing {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestRepository the repository to use for storing
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link OAuth2LoginSpec} for further configuration
		 * @since 5.2
		 */
		public OAuth2LoginSpec authorizationRequestRepository(
				ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		/**
		 * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestResolver the resolver used for resolving
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link OAuth2LoginSpec} for further configuration
		 * @since 5.2
		 */
		public OAuth2LoginSpec authorizationRequestResolver(
				ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver) {
			this.authorizationRequestResolver = authorizationRequestResolver;
			return this;
		}

		/**
		 * Sets the redirect strategy for Authorization Endpoint redirect URI.
		 * @param authorizationRedirectStrategy the redirect strategy
		 * @return the {@link OAuth2LoginSpec} for further configuration
		 */
		public OAuth2LoginSpec authorizationRedirectStrategy(ServerRedirectStrategy authorizationRedirectStrategy) {
			this.authorizationRedirectStrategy = authorizationRedirectStrategy;
			return this;
		}

		/**
		 * Sets the {@link ServerWebExchangeMatcher matcher} used for determining if the
		 * request is an authentication request.
		 * @param authenticationMatcher the {@link ServerWebExchangeMatcher matcher} used
		 * for determining if the request is an authentication request
		 * @return the {@link OAuth2LoginSpec} for further configuration
		 * @since 5.2
		 */
		public OAuth2LoginSpec authenticationMatcher(ServerWebExchangeMatcher authenticationMatcher) {
			this.authenticationMatcher = authenticationMatcher;
			return this;
		}

		private ServerWebExchangeMatcher getAuthenticationMatcher() {
			if (this.authenticationMatcher == null) {
				this.authenticationMatcher = createAttemptAuthenticationRequestMatcher();
			}
			return this.authenticationMatcher;
		}

		/**
		 * Specifies the URL to send users to if login is required. A default login page
		 * will be generated when this attribute is not specified.
		 * @param loginPage the URL to send users to if login is required
		 * @return the {@link OAuth2LoginSpec} for further configuration
		 * @since 6.4
		 */
		public OAuth2LoginSpec loginPage(String loginPage) {
			Assert.hasText(loginPage, "loginPage cannot be empty");
			this.loginPage = loginPage;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #oauth2Login(Customizer)} or
		 * {@code oauth2Login(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			ReactiveClientRegistrationRepository clientRegistrationRepository = getClientRegistrationRepository();
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository = getAuthorizedClientRepository();
			OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter = getRedirectWebFilter();
			ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = getAuthorizationRequestRepository();
			oauthRedirectFilter.setAuthorizationRequestRepository(authorizationRequestRepository);
			oauthRedirectFilter.setAuthorizationRedirectStrategy(getAuthorizationRedirectStrategy());
			oauthRedirectFilter.setRequestCache(http.requestCache.requestCache);

			ReactiveAuthenticationManager manager = getAuthenticationManager();
			ReactiveOidcSessionRegistry sessionRegistry = getOidcSessionRegistry();
			AuthenticationWebFilter authenticationFilter = (sessionRegistry != null)
					? new OidcSessionRegistryAuthenticationWebFilter(manager, authorizedClientRepository,
							sessionRegistry)
					: new OAuth2LoginAuthenticationWebFilter(manager, authorizedClientRepository);
			authenticationFilter.setRequiresAuthenticationMatcher(getAuthenticationMatcher());
			authenticationFilter
				.setServerAuthenticationConverter(getAuthenticationConverter(clientRegistrationRepository));
			authenticationFilter.setAuthenticationSuccessHandler(getAuthenticationSuccessHandler(http));
			authenticationFilter.setAuthenticationFailureHandler(getAuthenticationFailureHandler());
			authenticationFilter.setSecurityContextRepository(this.securityContextRepository);

			setDefaultEntryPoints(http);
			if (sessionRegistry != null) {
				http.addFilterAfter(new OidcSessionRegistryWebFilter(sessionRegistry),
						SecurityWebFiltersOrder.HTTP_HEADERS_WRITER);
			}
			http.addFilterAt(oauthRedirectFilter, SecurityWebFiltersOrder.HTTP_BASIC);
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);
		}

		private void setDefaultEntryPoints(ServerHttpSecurity http) {
			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
					MediaType.APPLICATION_XHTML_XML, new MediaType("image", "*"), MediaType.TEXT_HTML,
					MediaType.TEXT_PLAIN);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerWebExchangeMatcher xhrMatcher = (exchange) -> {
				if (exchange.getRequest().getHeaders().getOrEmpty("X-Requested-With").contains("XMLHttpRequest")) {
					return ServerWebExchangeMatcher.MatchResult.match();
				}
				return ServerWebExchangeMatcher.MatchResult.notMatch();
			};
			ServerWebExchangeMatcher notXhrMatcher = new NegatedServerWebExchangeMatcher(xhrMatcher);
			ServerWebExchangeMatcher defaultEntryPointMatcher = new AndServerWebExchangeMatcher(notXhrMatcher,
					htmlMatcher);
			String loginPage = "/login";
			if (StringUtils.hasText(this.loginPage)) {
				loginPage = this.loginPage;
			}
			else {
				Map<String, String> urlToText = http.oauth2Login.getLinks();
				String providerLoginPage = null;
				if (urlToText.size() == 1) {
					providerLoginPage = urlToText.keySet().iterator().next();
				}
				if (providerLoginPage != null) {
					ServerWebExchangeMatcher loginPageMatcher = new PathPatternParserServerWebExchangeMatcher(
							loginPage);
					ServerWebExchangeMatcher faviconMatcher = new PathPatternParserServerWebExchangeMatcher(
							"/favicon.ico");
					ServerWebExchangeMatcher defaultLoginPageMatcher = new AndServerWebExchangeMatcher(
							new OrServerWebExchangeMatcher(loginPageMatcher, faviconMatcher), defaultEntryPointMatcher);

					ServerWebExchangeMatcher matcher = new AndServerWebExchangeMatcher(notXhrMatcher,
							new NegatedServerWebExchangeMatcher(defaultLoginPageMatcher));
					RedirectServerAuthenticationEntryPoint entryPoint = new RedirectServerAuthenticationEntryPoint(
							providerLoginPage);
					entryPoint.setRequestCache(http.requestCache.requestCache);
					http.defaultEntryPoints.add(new DelegateEntry(matcher, entryPoint));
				}
			}
			RedirectServerAuthenticationEntryPoint defaultEntryPoint = new RedirectServerAuthenticationEntryPoint(
					loginPage);
			defaultEntryPoint.setRequestCache(http.requestCache.requestCache);
			http.defaultEntryPoints.add(new DelegateEntry(defaultEntryPointMatcher, defaultEntryPoint));
		}

		private ReactiveOidcSessionRegistry getOidcSessionRegistry() {
			if (ServerHttpSecurity.this.oidcLogout == null && this.oidcSessionRegistry == null) {
				return null;
			}
			if (this.oidcSessionRegistry == null) {
				this.oidcSessionRegistry = getBeanOrNull(ReactiveOidcSessionRegistry.class);
			}
			if (this.oidcSessionRegistry == null) {
				this.oidcSessionRegistry = new InMemoryReactiveOidcSessionRegistry();
			}
			return this.oidcSessionRegistry;
		}

		private ServerAuthenticationSuccessHandler getAuthenticationSuccessHandler(ServerHttpSecurity http) {
			this.defaultAuthenticationSuccessHandler.setRequestCache(http.requestCache.requestCache);
			if (this.authenticationSuccessHandlers.isEmpty()) {
				return new DelegatingServerAuthenticationSuccessHandler(this.defaultSuccessHandlers);
			}
			return new DelegatingServerAuthenticationSuccessHandler(this.authenticationSuccessHandlers);
		}

		private ServerAuthenticationFailureHandler getAuthenticationFailureHandler() {
			if (this.authenticationFailureHandler == null) {
				this.authenticationFailureHandler = new RedirectServerAuthenticationFailureHandler("/login?error");
			}
			return this.authenticationFailureHandler;
		}

		private ServerWebExchangeMatcher createAttemptAuthenticationRequestMatcher() {
			return new PathPatternParserServerWebExchangeMatcher("/login/oauth2/code/{registrationId}");
		}

		private ReactiveOAuth2UserService<OidcUserRequest, OidcUser> getOidcUserService() {
			ResolvableType type = ResolvableType.forClassWithGenerics(ReactiveOAuth2UserService.class,
					OidcUserRequest.class, OidcUser.class);
			ReactiveOAuth2UserService<OidcUserRequest, OidcUser> bean = getBeanOrNull(type);
			if (bean != null) {
				return bean;
			}
			OidcReactiveOAuth2UserService reactiveOAuth2UserService = new OidcReactiveOAuth2UserService();
			reactiveOAuth2UserService.setOauth2UserService(getOauth2UserService());
			return reactiveOAuth2UserService;
		}

		private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> getOauth2UserService() {
			ResolvableType type = ResolvableType.forClassWithGenerics(ReactiveOAuth2UserService.class,
					OAuth2UserRequest.class, OAuth2User.class);
			ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> bean = getBeanOrNull(type);
			if (bean != null) {
				return bean;
			}
			return new DefaultReactiveOAuth2UserService();
		}

		private Map<String, String> getLinks() {
			Iterable<ClientRegistration> registrations = getBeanOrNull(
					ResolvableType.forClassWithGenerics(Iterable.class, ClientRegistration.class));
			if (registrations == null) {
				return Collections.emptyMap();
			}
			Map<String, String> result = new HashMap<>();
			registrations.iterator().forEachRemaining((r) -> {
				if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(r.getAuthorizationGrantType())) {
					result.put("/oauth2/authorization/" + r.getRegistrationId(), r.getClientName());
				}
			});
			return result;
		}

		private ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient() {
			ResolvableType type = ResolvableType.forClassWithGenerics(ReactiveOAuth2AccessTokenResponseClient.class,
					OAuth2AuthorizationCodeGrantRequest.class);
			ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> bean = getBeanOrNull(type);
			if (bean != null) {
				return bean;
			}
			return new WebClientReactiveAuthorizationCodeTokenResponseClient();
		}

		private ReactiveClientRegistrationRepository getClientRegistrationRepository() {
			if (this.clientRegistrationRepository == null) {
				this.clientRegistrationRepository = getBeanOrNull(ReactiveClientRegistrationRepository.class);
			}
			return this.clientRegistrationRepository;
		}

		private OAuth2AuthorizationRequestRedirectWebFilter getRedirectWebFilter() {
			ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver = this.authorizationRequestResolver;
			if (authorizationRequestResolver == null) {
				authorizationRequestResolver = getBeanOrNull(ServerOAuth2AuthorizationRequestResolver.class);
			}
			if (authorizationRequestResolver != null) {
				return new OAuth2AuthorizationRequestRedirectWebFilter(authorizationRequestResolver);
			}
			return new OAuth2AuthorizationRequestRedirectWebFilter(getClientRegistrationRepository());
		}

		private ServerOAuth2AuthorizedClientRepository getAuthorizedClientRepository() {
			ServerOAuth2AuthorizedClientRepository result = this.authorizedClientRepository;
			if (result == null) {
				result = getBeanOrNull(ServerOAuth2AuthorizedClientRepository.class);
			}
			if (result == null) {
				ReactiveOAuth2AuthorizedClientService authorizedClientService = getAuthorizedClientService();
				if (authorizedClientService != null) {
					result = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(authorizedClientService);
				}
			}
			return result;
		}

		private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> getAuthorizationRequestRepository() {
			if (this.authorizationRequestRepository == null) {
				this.authorizationRequestRepository = new WebSessionOAuth2ServerAuthorizationRequestRepository();
			}
			return this.authorizationRequestRepository;
		}

		private ServerRedirectStrategy getAuthorizationRedirectStrategy() {
			if (this.authorizationRedirectStrategy == null) {
				this.authorizationRedirectStrategy = new DefaultServerRedirectStrategy();
			}
			return this.authorizationRedirectStrategy;
		}

		private ReactiveOAuth2AuthorizedClientService getAuthorizedClientService() {
			ReactiveOAuth2AuthorizedClientService bean = getBeanOrNull(ReactiveOAuth2AuthorizedClientService.class);
			if (bean != null) {
				return bean;
			}
			return new InMemoryReactiveOAuth2AuthorizedClientService(getClientRegistrationRepository());
		}

		private static final class OidcSessionRegistryWebFilter implements WebFilter {

			private final ReactiveOidcSessionRegistry oidcSessionRegistry;

			OidcSessionRegistryWebFilter(ReactiveOidcSessionRegistry oidcSessionRegistry) {
				this.oidcSessionRegistry = oidcSessionRegistry;
			}

			@Override
			public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
				return chain.filter(new OidcSessionRegistryServerWebExchange(exchange));
			}

			private final class OidcSessionRegistryServerWebExchange extends ServerWebExchangeDecorator {

				private final Mono<WebSession> sessionMono;

				protected OidcSessionRegistryServerWebExchange(ServerWebExchange delegate) {
					super(delegate);
					this.sessionMono = delegate.getSession().map(OidcSessionRegistryWebSession::new);
				}

				@Override
				public Mono<WebSession> getSession() {
					return this.sessionMono;
				}

				private final class OidcSessionRegistryWebSession implements WebSession {

					private final WebSession session;

					OidcSessionRegistryWebSession(WebSession session) {
						this.session = session;
					}

					@Override
					public String getId() {
						return this.session.getId();
					}

					@Override
					public Map<String, Object> getAttributes() {
						return this.session.getAttributes();
					}

					@Override
					public void start() {
						this.session.start();
					}

					@Override
					public boolean isStarted() {
						return this.session.isStarted();
					}

					@Override
					public Mono<Void> changeSessionId() {
						String currentId = this.session.getId();
						return this.session.changeSessionId()
							.then(Mono.defer(() -> OidcSessionRegistryWebFilter.this.oidcSessionRegistry
								.removeSessionInformation(currentId)
								.flatMap((information) -> {
									information = information.withSessionId(this.session.getId());
									return OidcSessionRegistryWebFilter.this.oidcSessionRegistry
										.saveSessionInformation(information);
								})));
					}

					@Override
					public Mono<Void> invalidate() {
						String currentId = this.session.getId();
						return this.session.invalidate()
							.then(Mono.defer(() -> OidcSessionRegistryWebFilter.this.oidcSessionRegistry
								.removeSessionInformation(currentId)
								.then(Mono.empty())));
					}

					@Override
					public Mono<Void> save() {
						return this.session.save();
					}

					@Override
					public boolean isExpired() {
						return this.session.isExpired();
					}

					@Override
					public Instant getCreationTime() {
						return this.session.getCreationTime();
					}

					@Override
					public Instant getLastAccessTime() {
						return this.session.getLastAccessTime();
					}

					@Override
					public void setMaxIdleTime(Duration maxIdleTime) {
						this.session.setMaxIdleTime(maxIdleTime);
					}

					@Override
					public Duration getMaxIdleTime() {
						return this.session.getMaxIdleTime();
					}

				}

			}

		}

		static final class OidcSessionRegistryAuthenticationWebFilter extends OAuth2LoginAuthenticationWebFilter {

			private final Log logger = LogFactory.getLog(getClass());

			private final ReactiveOidcSessionRegistry oidcSessionRegistry;

			OidcSessionRegistryAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager,
					ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
					ReactiveOidcSessionRegistry oidcSessionRegistry) {
				super(authenticationManager, authorizedClientRepository);
				this.oidcSessionRegistry = oidcSessionRegistry;
			}

			@Override
			protected Mono<Void> onAuthenticationSuccess(Authentication authentication,
					WebFilterExchange webFilterExchange) {
				if (!(authentication.getPrincipal() instanceof OidcUser user)) {
					return super.onAuthenticationSuccess(authentication, webFilterExchange);
				}
				return webFilterExchange.getExchange().getSession().doOnNext((session) -> {
					if (this.logger.isTraceEnabled()) {
						this.logger.trace(String.format("Linking a provider [%s] session to this client's session",
								user.getIssuer()));
					}
				}).flatMap((session) -> {
					Mono<CsrfToken> csrfToken = webFilterExchange.getExchange().getAttribute(CsrfToken.class.getName());
					return (csrfToken != null)
							? csrfToken.map((token) -> new OidcSessionInformation(session.getId(),
									Map.of(token.getHeaderName(), token.getToken()), user))
							: Mono.just(new OidcSessionInformation(session.getId(), Map.of(), user));
				})
					.flatMap(this.oidcSessionRegistry::saveSessionInformation)
					.then(super.onAuthenticationSuccess(authentication, webFilterExchange));
			}

		}

	}

	public final class OAuth2ClientSpec {

		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ServerAuthenticationConverter authenticationConverter;

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

		private ReactiveAuthenticationManager authenticationManager;

		private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;

		private ServerRedirectStrategy authorizationRedirectStrategy;

		private OAuth2ClientSpec() {
		}

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
				ServerOAuth2AuthorizationCodeAuthenticationTokenConverter authenticationConverter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
						getClientRegistrationRepository());
				authenticationConverter.setAuthorizationRequestRepository(getAuthorizationRequestRepository());
				this.authenticationConverter = authenticationConverter;
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
		 * Gets the {@link ReactiveAuthenticationManager} to use. First tries an
		 * explicitly configured manager, and defaults to
		 * {@link OAuth2AuthorizationCodeReactiveAuthenticationManager}
		 * @return the {@link ReactiveAuthenticationManager} to use
		 */
		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				this.authenticationManager = new OAuth2AuthorizationCodeReactiveAuthenticationManager(
						getAuthorizationCodeTokenResponseClient());
			}
			return this.authenticationManager;
		}

		private ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAuthorizationCodeTokenResponseClient() {
			ResolvableType resolvableType = ResolvableType.forClassWithGenerics(
					ReactiveOAuth2AccessTokenResponseClient.class, OAuth2AuthorizationCodeGrantRequest.class);
			ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = getBeanOrNull(
					resolvableType);
			if (accessTokenResponseClient == null) {
				accessTokenResponseClient = new WebClientReactiveAuthorizationCodeTokenResponseClient();
			}
			return accessTokenResponseClient;
		}

		/**
		 * Configures the {@link ReactiveClientRegistrationRepository}. Default is to look
		 * the value up as a Bean.
		 * @param clientRegistrationRepository the repository to use
		 * @return the {@link OAuth2ClientSpec} to customize
		 */
		public OAuth2ClientSpec clientRegistrationRepository(
				ReactiveClientRegistrationRepository clientRegistrationRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
			return this;
		}

		/**
		 * Configures the {@link ReactiveClientRegistrationRepository}. Default is to look
		 * the value up as a Bean.
		 * @param authorizedClientRepository the repository to use
		 * @return the {@link OAuth2ClientSpec} to customize
		 */
		public OAuth2ClientSpec authorizedClientRepository(
				ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.authorizedClientRepository = authorizedClientRepository;
			return this;
		}

		/**
		 * Sets the repository to use for storing {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestRepository the repository to use for storing
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link OAuth2ClientSpec} to customize
		 * @since 5.2
		 */
		public OAuth2ClientSpec authorizationRequestRepository(
				ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> getAuthorizationRequestRepository() {
			if (this.authorizationRequestRepository == null) {
				this.authorizationRequestRepository = new WebSessionOAuth2ServerAuthorizationRequestRepository();
			}
			return this.authorizationRequestRepository;
		}

		/**
		 * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestResolver the resolver used for resolving
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link OAuth2ClientSpec} to customize
		 * @since 6.1
		 */
		public OAuth2ClientSpec authorizationRequestResolver(
				ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver) {
			this.authorizationRequestResolver = authorizationRequestResolver;
			return this;
		}

		private OAuth2AuthorizationRequestRedirectWebFilter getRedirectWebFilter() {
			if (this.authorizationRequestResolver != null) {
				return new OAuth2AuthorizationRequestRedirectWebFilter(this.authorizationRequestResolver);
			}
			return new OAuth2AuthorizationRequestRedirectWebFilter(getClientRegistrationRepository());
		}

		/**
		 * Sets the redirect strategy for Authorization Endpoint redirect URI.
		 * @param authorizationRedirectStrategy the redirect strategy
		 * @return the {@link OAuth2ClientSpec} for further configuration
		 */
		public OAuth2ClientSpec authorizationRedirectStrategy(ServerRedirectStrategy authorizationRedirectStrategy) {
			this.authorizationRedirectStrategy = authorizationRedirectStrategy;
			return this;
		}

		private ServerRedirectStrategy getAuthorizationRedirectStrategy() {
			if (this.authorizationRedirectStrategy == null) {
				this.authorizationRedirectStrategy = new DefaultServerRedirectStrategy();
			}
			return this.authorizationRedirectStrategy;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #oauth2Client(Customizer)} or
		 * {@code oauth2Client(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository = getAuthorizedClientRepository();
			ServerAuthenticationConverter authenticationConverter = getAuthenticationConverter();
			ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
			OAuth2AuthorizationCodeGrantWebFilter codeGrantWebFilter = new OAuth2AuthorizationCodeGrantWebFilter(
					authenticationManager, authenticationConverter, authorizedClientRepository);
			codeGrantWebFilter.setAuthorizationRequestRepository(getAuthorizationRequestRepository());
			if (http.requestCache != null) {
				codeGrantWebFilter.setRequestCache(http.requestCache.requestCache);
			}

			OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter = getRedirectWebFilter();
			oauthRedirectFilter.setAuthorizationRequestRepository(getAuthorizationRequestRepository());
			oauthRedirectFilter.setAuthorizationRedirectStrategy(getAuthorizationRedirectStrategy());
			if (http.requestCache != null) {
				oauthRedirectFilter.setRequestCache(http.requestCache.requestCache);
			}

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
			if (result != null) {
				return result;
			}
			ReactiveOAuth2AuthorizedClientService authorizedClientService = getAuthorizedClientService();
			if (authorizedClientService != null) {
				return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(authorizedClientService);
			}
			return null;
		}

		private ReactiveOAuth2AuthorizedClientService getAuthorizedClientService() {
			ReactiveOAuth2AuthorizedClientService bean = getBeanOrNull(ReactiveOAuth2AuthorizedClientService.class);
			if (bean != null) {
				return bean;
			}
			return new InMemoryReactiveOAuth2AuthorizedClientService(getClientRegistrationRepository());
		}

	}

	/**
	 * Configures OAuth2 Resource Server Support
	 */
	public class OAuth2ResourceServerSpec {

		private ServerAuthenticationEntryPoint entryPoint = new BearerTokenServerAuthenticationEntryPoint();

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private ServerAccessDeniedHandler accessDeniedHandler = new BearerTokenServerAccessDeniedHandler();

		private ServerAuthenticationConverter bearerTokenConverter = new ServerBearerTokenAuthenticationConverter();

		private AuthenticationConverterServerWebExchangeMatcher authenticationConverterServerWebExchangeMatcher;

		private JwtSpec jwt;

		private OpaqueTokenSpec opaqueToken;

		private ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver;

		/**
		 * Configures the {@link ServerAccessDeniedHandler} to use for requests
		 * authenticating with
		 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target=
		 * "_blank">Bearer Token</a>s. requests.
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
		 * Configures the {@link ServerAuthenticationEntryPoint} to use for requests
		 * authenticating with
		 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target=
		 * "_blank">Bearer Token</a>s.
		 * @param entryPoint the {@link ServerAuthenticationEntryPoint} to use
		 * @return the {@link OAuth2ResourceServerSpec} for additional configuration
		 * @since 5.2
		 */
		public OAuth2ResourceServerSpec authenticationEntryPoint(ServerAuthenticationEntryPoint entryPoint) {
			Assert.notNull(entryPoint, "entryPoint cannot be null");
			this.entryPoint = entryPoint;
			return this;
		}

		public OAuth2ResourceServerSpec authenticationFailureHandler(
				ServerAuthenticationFailureHandler authenticationFailureHandler) {
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		/**
		 * Configures the {@link ServerAuthenticationConverter} to use for requests
		 * authenticating with
		 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target=
		 * "_blank">Bearer Token</a>s.
		 * @param bearerTokenConverter The {@link ServerAuthenticationConverter} to use
		 * @return The {@link OAuth2ResourceServerSpec} for additional configuration
		 * @since 5.2
		 */
		public OAuth2ResourceServerSpec bearerTokenConverter(ServerAuthenticationConverter bearerTokenConverter) {
			Assert.notNull(bearerTokenConverter, "bearerTokenConverter cannot be null");
			this.bearerTokenConverter = bearerTokenConverter;
			return this;
		}

		/**
		 * Configures the {@link ReactiveAuthenticationManagerResolver}
		 * @param authenticationManagerResolver the
		 * {@link ReactiveAuthenticationManagerResolver}
		 * @return the {@link OAuth2ResourceServerSpec} for additional configuration
		 * @since 5.3
		 */
		public OAuth2ResourceServerSpec authenticationManagerResolver(
				ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver) {
			Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
			this.authenticationManagerResolver = authenticationManagerResolver;
			return this;
		}

		/**
		 * Enables JWT Resource Server support.
		 * @return the {@link JwtSpec} for additional configuration
		 * @deprecated For removal in 7.0. Use {@link #jwt(Customizer)} or
		 * {@code jwt(Customizer.withDefaults())} to stick with defaults. See the <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public JwtSpec jwt() {
			if (this.jwt == null) {
				this.jwt = new JwtSpec();
			}
			return this.jwt;
		}

		/**
		 * Enables JWT Resource Server support.
		 * @param jwtCustomizer the {@link Customizer} to provide more options for the
		 * {@link JwtSpec}
		 * @return the {@link OAuth2ResourceServerSpec} to customize
		 */
		public OAuth2ResourceServerSpec jwt(Customizer<JwtSpec> jwtCustomizer) {
			if (this.jwt == null) {
				this.jwt = new JwtSpec();
			}
			jwtCustomizer.customize(this.jwt);
			return this;
		}

		/**
		 * Enables Opaque Token Resource Server support.
		 * @return the {@link OpaqueTokenSpec} for additional configuration
		 * @deprecated For removal in 7.0. Use {@link #opaqueToken(Customizer)} or
		 * {@code opaqueToken(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public OpaqueTokenSpec opaqueToken() {
			if (this.opaqueToken == null) {
				this.opaqueToken = new OpaqueTokenSpec();
			}
			return this.opaqueToken;
		}

		/**
		 * Enables Opaque Token Resource Server support.
		 * @param opaqueTokenCustomizer the {@link Customizer} to provide more options for
		 * the {@link OpaqueTokenSpec}
		 * @return the {@link OAuth2ResourceServerSpec} to customize
		 */
		public OAuth2ResourceServerSpec opaqueToken(Customizer<OpaqueTokenSpec> opaqueTokenCustomizer) {
			if (this.opaqueToken == null) {
				this.opaqueToken = new OpaqueTokenSpec();
			}
			opaqueTokenCustomizer.customize(this.opaqueToken);
			return this;
		}

		protected void configure(ServerHttpSecurity http) {
			this.authenticationConverterServerWebExchangeMatcher = new AuthenticationConverterServerWebExchangeMatcher(
					this.bearerTokenConverter);
			registerDefaultAccessDeniedHandler(http);
			registerDefaultAuthenticationEntryPoint(http);
			registerDefaultCsrfOverride(http);
			validateConfiguration();
			if (this.authenticationManagerResolver != null) {
				AuthenticationWebFilter oauth2 = new AuthenticationWebFilter(this.authenticationManagerResolver);
				oauth2.setServerAuthenticationConverter(this.bearerTokenConverter);
				oauth2.setAuthenticationFailureHandler(authenticationFailureHandler());
				http.addFilterAt(oauth2, SecurityWebFiltersOrder.AUTHENTICATION);
			}
			else if (this.jwt != null) {
				this.jwt.configure(http);
			}
			else if (this.opaqueToken != null) {
				this.opaqueToken.configure(http);
			}
		}

		private void validateConfiguration() {
			if (this.authenticationManagerResolver == null) {
				Assert.state(this.jwt != null || this.opaqueToken != null,
						"Jwt and Opaque Token are the only supported formats for bearer tokens "
								+ "in Spring Security and neither was found. Make sure to configure JWT "
								+ "via http.oauth2ResourceServer().jwt() or Opaque Tokens via "
								+ "http.oauth2ResourceServer().opaqueToken().");
				Assert.state(this.jwt == null || this.opaqueToken == null,
						"Spring Security only supports JWTs or Opaque Tokens, not both at the " + "same time.");
			}
			else {
				Assert.state(this.jwt == null && this.opaqueToken == null,
						"If an authenticationManagerResolver() is configured, then it takes "
								+ "precedence over any jwt() or opaqueToken() configuration.");
			}
		}

		private void registerDefaultAccessDeniedHandler(ServerHttpSecurity http) {
			if (http.exceptionHandling != null) {
				http.defaultAccessDeniedHandlers
					.add(new ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
							this.authenticationConverterServerWebExchangeMatcher,
							OAuth2ResourceServerSpec.this.accessDeniedHandler));
			}
		}

		private void registerDefaultAuthenticationEntryPoint(ServerHttpSecurity http) {
			if (http.exceptionHandling != null) {
				http.defaultEntryPoints.add(new DelegateEntry(this.authenticationConverterServerWebExchangeMatcher,
						OAuth2ResourceServerSpec.this.entryPoint));
			}
		}

		private void registerDefaultCsrfOverride(ServerHttpSecurity http) {
			if (http.csrf != null && !http.csrf.specifiedRequireCsrfProtectionMatcher) {
				AndServerWebExchangeMatcher matcher = new AndServerWebExchangeMatcher(
						CsrfWebFilter.DEFAULT_CSRF_MATCHER,
						new NegatedServerWebExchangeMatcher(this.authenticationConverterServerWebExchangeMatcher));
				http.csrf().requireCsrfProtectionMatcher(matcher);
			}
		}

		private ServerAuthenticationFailureHandler authenticationFailureHandler() {
			if (this.authenticationFailureHandler != null) {
				return this.authenticationFailureHandler;
			}
			return new ServerAuthenticationEntryPointFailureHandler(this.entryPoint);
		}

		/**
		 * @deprecated For removal in 7.0. Use {@link #oauth2ResourceServer(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		/**
		 * Configures JWT Resource Server Support
		 */
		public class JwtSpec {

			private ReactiveAuthenticationManager authenticationManager;

			private ReactiveJwtDecoder jwtDecoder;

			private Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter;

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
			 * @param jwtAuthenticationConverter the converter to use
			 * @return the {@code JwtSpec} for additional configuration
			 * @since 5.1.1
			 */
			public JwtSpec jwtAuthenticationConverter(
					Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
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
			 * Configures a {@link ReactiveJwtDecoder} that leverages the provided
			 * {@link RSAPublicKey}
			 * @param publicKey the public key to use.
			 * @return the {@code JwtSpec} for additional configuration
			 */
			public JwtSpec publicKey(RSAPublicKey publicKey) {
				this.jwtDecoder = new NimbusReactiveJwtDecoder(publicKey);
				return this;
			}

			/**
			 * Configures a {@link ReactiveJwtDecoder} using
			 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key
			 * (JWK)</a> URL
			 * @param jwkSetUri the URL to use.
			 * @return the {@code JwtSpec} for additional configuration
			 */
			public JwtSpec jwkSetUri(String jwkSetUri) {
				this.jwtDecoder = new NimbusReactiveJwtDecoder(jwkSetUri);
				return this;
			}

			/**
			 * @deprecated For removal in 7.0. Use {@link #jwt(Customizer)} or
			 * {@code jwt(Customizer.withDefaults())} to stick with defaults. See the
			 * <a href=
			 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
			 * for more details.
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public OAuth2ResourceServerSpec and() {
				return OAuth2ResourceServerSpec.this;
			}

			protected void configure(ServerHttpSecurity http) {
				ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
				AuthenticationWebFilter oauth2 = new AuthenticationWebFilter(authenticationManager);
				oauth2.setServerAuthenticationConverter(OAuth2ResourceServerSpec.this.bearerTokenConverter);
				oauth2.setAuthenticationFailureHandler(authenticationFailureHandler());
				http.addFilterAt(oauth2, SecurityWebFiltersOrder.AUTHENTICATION);
			}

			protected ReactiveJwtDecoder getJwtDecoder() {
				return (this.jwtDecoder != null) ? this.jwtDecoder : getBean(ReactiveJwtDecoder.class);
			}

			protected Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> getJwtAuthenticationConverter() {
				if (this.jwtAuthenticationConverter != null) {
					return this.jwtAuthenticationConverter;
				}

				if (getBeanNamesForTypeOrEmpty(ReactiveJwtAuthenticationConverter.class).length > 0) {
					return getBean(ReactiveJwtAuthenticationConverter.class);
				}
				else {
					return new ReactiveJwtAuthenticationConverter();
				}
			}

			private ReactiveAuthenticationManager getAuthenticationManager() {
				if (this.authenticationManager != null) {
					return this.authenticationManager;
				}
				ReactiveJwtDecoder jwtDecoder = getJwtDecoder();
				Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter = getJwtAuthenticationConverter();
				JwtReactiveAuthenticationManager authenticationManager = new JwtReactiveAuthenticationManager(
						jwtDecoder);
				authenticationManager.setJwtAuthenticationConverter(jwtAuthenticationConverter);
				return authenticationManager;
			}

		}

		/**
		 * Configures Opaque Token Resource Server support
		 *
		 * @author Josh Cummings
		 * @since 5.2
		 */
		public final class OpaqueTokenSpec {

			private String introspectionUri;

			private String clientId;

			private String clientSecret;

			private Supplier<ReactiveOpaqueTokenIntrospector> introspector;

			private ReactiveOpaqueTokenAuthenticationConverter authenticationConverter;

			private OpaqueTokenSpec() {
			}

			/**
			 * Configures the URI of the Introspection endpoint
			 * @param introspectionUri The URI of the Introspection endpoint
			 * @return the {@code OpaqueTokenSpec} for additional configuration
			 */
			public OpaqueTokenSpec introspectionUri(String introspectionUri) {
				Assert.hasText(introspectionUri, "introspectionUri cannot be empty");
				this.introspectionUri = introspectionUri;
				this.introspector = () -> new NimbusReactiveOpaqueTokenIntrospector(this.introspectionUri,
						this.clientId, this.clientSecret);
				return this;
			}

			/**
			 * Configures the credentials for Introspection endpoint
			 * @param clientId The clientId part of the credentials
			 * @param clientSecret The clientSecret part of the credentials
			 * @return the {@code OpaqueTokenSpec} for additional configuration
			 */
			public OpaqueTokenSpec introspectionClientCredentials(String clientId, String clientSecret) {
				Assert.hasText(clientId, "clientId cannot be empty");
				Assert.notNull(clientSecret, "clientSecret cannot be null");
				this.clientId = clientId;
				this.clientSecret = clientSecret;
				this.introspector = () -> new NimbusReactiveOpaqueTokenIntrospector(this.introspectionUri,
						this.clientId, this.clientSecret);
				return this;
			}

			public OpaqueTokenSpec introspector(ReactiveOpaqueTokenIntrospector introspector) {
				Assert.notNull(introspector, "introspector cannot be null");
				this.introspector = () -> introspector;
				return this;
			}

			public OpaqueTokenSpec authenticationConverter(
					ReactiveOpaqueTokenAuthenticationConverter authenticationConverter) {
				Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
				this.authenticationConverter = authenticationConverter;
				return this;
			}

			/**
			 * Allows method chaining to continue configuring the
			 * {@link ServerHttpSecurity}
			 * @return the {@link ServerHttpSecurity} to continue configuring
			 * @deprecated For removal in 7.0. Use {@link #opaqueToken(Customizer)}
			 * instead
			 */
			@Deprecated(since = "6.1", forRemoval = true)
			public OAuth2ResourceServerSpec and() {
				return OAuth2ResourceServerSpec.this;
			}

			protected ReactiveAuthenticationManager getAuthenticationManager() {
				OpaqueTokenReactiveAuthenticationManager authenticationManager = new OpaqueTokenReactiveAuthenticationManager(
						getIntrospector());
				ReactiveOpaqueTokenAuthenticationConverter authenticationConverter = getAuthenticationConverter();
				if (authenticationConverter != null) {
					authenticationManager.setAuthenticationConverter(authenticationConverter);
				}
				return authenticationManager;
			}

			protected ReactiveOpaqueTokenIntrospector getIntrospector() {
				if (this.introspector != null) {
					return this.introspector.get();
				}
				return getBean(ReactiveOpaqueTokenIntrospector.class);
			}

			protected ReactiveOpaqueTokenAuthenticationConverter getAuthenticationConverter() {
				if (this.authenticationConverter != null) {
					return this.authenticationConverter;
				}
				return getBeanOrNull(ReactiveOpaqueTokenAuthenticationConverter.class);
			}

			protected void configure(ServerHttpSecurity http) {
				ReactiveAuthenticationManager authenticationManager = getAuthenticationManager();
				AuthenticationWebFilter oauth2 = new AuthenticationWebFilter(authenticationManager);
				oauth2.setServerAuthenticationConverter(OAuth2ResourceServerSpec.this.bearerTokenConverter);
				oauth2.setAuthenticationFailureHandler(authenticationFailureHandler());
				http.addFilterAt(oauth2, SecurityWebFiltersOrder.AUTHENTICATION);
			}

		}

	}

	/**
	 * Configures OIDC 1.0 Logout support
	 *
	 * @author Josh Cummings
	 * @since 6.2
	 */
	public final class OidcLogoutSpec {

		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ReactiveOidcSessionRegistry sessionRegistry;

		private BackChannelLogoutConfigurer backChannel;

		/**
		 * Configures the {@link ReactiveClientRegistrationRepository}. Default is to look
		 * the value up as a Bean.
		 * @param clientRegistrationRepository the repository to use
		 * @return the {@link OidcLogoutSpec} to customize
		 */
		public OidcLogoutSpec clientRegistrationRepository(
				ReactiveClientRegistrationRepository clientRegistrationRepository) {
			Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
			this.clientRegistrationRepository = clientRegistrationRepository;
			return this;
		}

		/**
		 * Configures the {@link ReactiveOidcSessionRegistry}. Default is to use the value
		 * from {@link OAuth2LoginSpec#oidcSessionRegistry}, then look the value up as a
		 * Bean, or else use an {@link InMemoryReactiveOidcSessionRegistry}.
		 * @param sessionRegistry the registry to use
		 * @return the {@link OidcLogoutSpec} to customize
		 */
		public OidcLogoutSpec oidcSessionRegistry(ReactiveOidcSessionRegistry sessionRegistry) {
			Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
			this.sessionRegistry = sessionRegistry;
			return this;
		}

		/**
		 * Configure OIDC Back-Channel Logout using the provided {@link Consumer}
		 * @return the {@link OidcLogoutSpec} for further configuration
		 */
		public OidcLogoutSpec backChannel(Customizer<BackChannelLogoutConfigurer> backChannelLogoutConfigurer) {
			if (this.backChannel == null) {
				this.backChannel = new OidcLogoutSpec.BackChannelLogoutConfigurer();
			}
			backChannelLogoutConfigurer.customize(this.backChannel);
			return this;
		}

		@Deprecated(forRemoval = true, since = "6.2")
		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		void configure(ServerHttpSecurity http) {
			if (this.backChannel != null) {
				this.backChannel.configure(http);
			}
		}

		private ReactiveClientRegistrationRepository getClientRegistrationRepository() {
			if (this.clientRegistrationRepository == null) {
				this.clientRegistrationRepository = getBeanOrNull(ReactiveClientRegistrationRepository.class);
			}
			return this.clientRegistrationRepository;
		}

		private ReactiveOidcSessionRegistry getSessionRegistry() {
			if (this.sessionRegistry == null && ServerHttpSecurity.this.oauth2Login == null) {
				return getBeanOrDefault(ReactiveOidcSessionRegistry.class, new InMemoryReactiveOidcSessionRegistry());
			}
			if (this.sessionRegistry == null) {
				return ServerHttpSecurity.this.oauth2Login.oidcSessionRegistry;
			}
			return this.sessionRegistry;
		}

		/**
		 * A configurer for configuring OIDC Back-Channel Logout
		 */
		public final class BackChannelLogoutConfigurer {

			private ServerAuthenticationConverter authenticationConverter;

			private final ReactiveAuthenticationManager authenticationManager = new OidcBackChannelLogoutReactiveAuthenticationManager();

			private Supplier<ServerLogoutHandler> logoutHandler = this::logoutHandler;

			private ServerAuthenticationConverter authenticationConverter() {
				if (this.authenticationConverter == null) {
					this.authenticationConverter = new OidcLogoutServerAuthenticationConverter(
							OidcLogoutSpec.this.getClientRegistrationRepository());
				}
				return this.authenticationConverter;
			}

			private ReactiveAuthenticationManager authenticationManager() {
				return this.authenticationManager;
			}

			private ServerLogoutHandler logoutHandler() {
				OidcBackChannelServerLogoutHandler logoutHandler = getBeanOrNull(
						OidcBackChannelServerLogoutHandler.class);
				if (logoutHandler != null) {
					return logoutHandler;
				}
				logoutHandler = new OidcBackChannelServerLogoutHandler(OidcLogoutSpec.this.getSessionRegistry());
				return logoutHandler;
			}

			/**
			 * Use this endpoint when invoking a back-channel logout.
			 *
			 * <p>
			 * The resulting {@link LogoutHandler} will {@code POST} the session cookie
			 * and CSRF token to this endpoint to invalidate the corresponding end-user
			 * session.
			 *
			 * <p>
			 * Supports URI templates like {@code {baseUrl}}, {@code {baseScheme}}, and
			 * {@code {basePort}}.
			 *
			 * <p>
			 * By default, the URI is set to
			 * {@code {baseUrl}/logout/connect/back-channel/{registrationId}}, meaning
			 * that the scheme and port of the original back-channel request is preserved,
			 * while the host and endpoint are changed.
			 *
			 * <p>
			 * If you are using Spring Security for the logout endpoint, the path part of
			 * this URI should match the value configured there.
			 *
			 * <p>
			 * Otherwise, this is handy in the event that your server configuration means
			 * that the scheme, server name, or port in the {@code Host} header are
			 * different from how you would address the same server internally.
			 * @param logoutUri the URI to request logout on the back-channel
			 * @return the {@link BackChannelLogoutConfigurer} for further customizations
			 * @since 6.2.4
			 */
			public BackChannelLogoutConfigurer logoutUri(String logoutUri) {
				this.logoutHandler = () -> {
					OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler(
							OidcLogoutSpec.this.getSessionRegistry());
					logoutHandler.setLogoutUri(logoutUri);
					return logoutHandler;
				};
				return this;
			}

			/**
			 * Configure what and how per-session logout will be performed.
			 *
			 * <p>
			 * This overrides any value given to {@link #logoutUri(String)}
			 *
			 * <p>
			 * By default, the resulting {@link LogoutHandler} will {@code POST} the
			 * session cookie and OIDC logout token back to the original back-channel
			 * logout endpoint.
			 *
			 * <p>
			 * Using this method changes the underlying default that {@code POST}s the
			 * session cookie and CSRF token to your application's {@code /logout}
			 * endpoint. As such, it is recommended to call this instead of accepting the
			 * {@code /logout} default as this does not require any special CSRF
			 * configuration, even if you don't require other changes.
			 *
			 * <p>
			 * For example, configuring Back-Channel Logout in the following way:
			 *
			 * <pre>
			 * 	http
			 *     	.oidcLogout((oidc) -&gt; oidc
			 *     		.backChannel((backChannel) -&gt; backChannel
			 *     			.logoutHandler(new OidcBackChannelServerLogoutHandler())
			 *     		)
			 *     	);
			 * </pre>
			 *
			 * will make so that the per-session logout invocation no longer requires
			 * special CSRF configurations.
			 *
			 * <p>
			 * The default URI is
			 * {@code {baseUrl}/logout/connect/back-channel/{registrationId}}, which is
			 * simply an internal version of the same endpoint exposed to your
			 * Back-Channel services. You can use
			 * {@link OidcBackChannelServerLogoutHandler#setLogoutUri(String)} to alter
			 * the scheme, server name, or port in the {@code Host} header to accommodate
			 * how your application would address itself internally.
			 *
			 * <p>
			 * For example, if the way your application would internally call itself is on
			 * a different scheme and port than incoming traffic, you can configure the
			 * endpoint in the following way:
			 *
			 * <pre>
			 * 	http
			 * 		.oidcLogout((oidc) -&gt; oidc
			 * 			.backChannel((backChannel) -&gt; backChannel
			 * 				.logoutUri("http://localhost:9000/logout/connect/back-channel/{registrationId}")
			 * 			)
			 * 		);
			 * </pre>
			 *
			 * <p>
			 * You can also publish it as a {@code @Bean} as follows:
			 *
			 * <pre>
			 *	&commat;Bean
			 *	OidcBackChannelServerLogoutHandler oidcLogoutHandler() {
			 *  	OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler();
			 *  	logoutHandler.setLogoutUri("http://localhost:9000/logout/connect/back-channel/{registrationId}");
			 *  	return logoutHandler;
			 *	}
			 * </pre>
			 *
			 * to have the same effect.
			 * @param logoutHandler the {@link ServerLogoutHandler} to use each individual
			 * session
			 * @return {@link BackChannelLogoutConfigurer} for further customizations
			 * @since 6.4
			 */
			public BackChannelLogoutConfigurer logoutHandler(ServerLogoutHandler logoutHandler) {
				this.logoutHandler = () -> logoutHandler;
				return this;
			}

			void configure(ServerHttpSecurity http) {
				ServerLogoutHandler oidcLogout = this.logoutHandler.get();
				ServerLogoutHandler sessionLogout = new SecurityContextServerLogoutHandler();
				LogoutSpec logout = ServerHttpSecurity.this.logout;
				if (logout != null) {
					sessionLogout = new DelegatingServerLogoutHandler(logout.logoutHandlers);
				}
				OidcBackChannelLogoutWebFilter filter = new OidcBackChannelLogoutWebFilter(authenticationConverter(),
						authenticationManager(), new EitherLogoutHandler(oidcLogout, sessionLogout));
				http.addFilterBefore(filter, SecurityWebFiltersOrder.CSRF);
			}

			private static final class EitherLogoutHandler implements ServerLogoutHandler {

				private final ServerLogoutHandler left;

				private final ServerLogoutHandler right;

				EitherLogoutHandler(ServerLogoutHandler left, ServerLogoutHandler right) {
					this.left = left;
					this.right = right;
				}

				@Override
				public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
					return exchange.getExchange().getFormData().flatMap((data) -> {
						if (data.getFirst("_spring_security_internal_logout") == null) {
							return this.left.logout(exchange, authentication);
						}
						else {
							return this.right.logout(exchange, authentication);
						}
					});
				}

			}

		}

	}

	/**
	 * Configures anonymous authentication
	 *
	 * @since 5.2.0
	 */
	public final class AnonymousSpec {

		private String key;

		private AnonymousAuthenticationWebFilter authenticationFilter;

		private Object principal = "anonymousUser";

		private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");

		/**
		 * Sets the key to identify tokens created for anonymous authentication. Default
		 * is a secure randomly generated key.
		 * @param key the key to identify tokens created for anonymous authentication.
		 * Default is a secure randomly generated key.
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec key(String key) {
			this.key = key;
			return this;
		}

		/**
		 * Sets the principal for {@link Authentication} objects of anonymous users
		 * @param principal used for the {@link Authentication} object of anonymous users
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec principal(Object principal) {
			this.principal = principal;
			return this;
		}

		/**
		 * Sets the
		 * {@link org.springframework.security.core.Authentication#getAuthorities()} for
		 * anonymous users
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
		 * Sets the
		 * {@link org.springframework.security.core.Authentication#getAuthorities()} for
		 * anonymous users
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
		 * Sets the {@link AnonymousAuthenticationWebFilter} used to populate an anonymous
		 * user. If this is set, no attributes on the {@link AnonymousSpec} will be set on
		 * the {@link AnonymousAuthenticationWebFilter}.
		 * @param authenticationFilter the {@link AnonymousAuthenticationWebFilter} used
		 * to populate an anonymous user.
		 * @return the {@link AnonymousSpec} for further customization of anonymous
		 * authentication
		 */
		public AnonymousSpec authenticationFilter(AnonymousAuthenticationWebFilter authenticationFilter) {
			this.authenticationFilter = authenticationFilter;
			return this;
		}

		/**
		 * Allows method chaining to continue configuring the {@link ServerHttpSecurity}
		 * @return the {@link ServerHttpSecurity} to continue configuring
		 * @deprecated For removal in 7.0. Use {@link #anonymous(Customizer)} or
		 * {@code anonymous(Customizer.withDefaults())} to stick with defaults. See the
		 * <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
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
			if (this.authenticationFilter == null) {
				this.authenticationFilter = new AnonymousAuthenticationWebFilter(getKey(), this.principal,
						this.authorities);
			}
			http.addFilterAt(this.authenticationFilter, SecurityWebFiltersOrder.ANONYMOUS_AUTHENTICATION);
		}

		private String getKey() {
			if (this.key == null) {
				this.key = UUID.randomUUID().toString();
			}
			return this.key;
		}

		private AnonymousSpec() {
		}

	}

	/**
	 * Configures One-Time Token Login Support
	 *
	 * @author Max Batischev
	 * @since 6.4
	 * @see #oneTimeTokenLogin(Customizer)
	 */
	public final class OneTimeTokenLoginSpec {

		private ReactiveAuthenticationManager authenticationManager;

		private ReactiveOneTimeTokenService tokenService;

		private ServerAuthenticationConverter authenticationConverter = new ServerOneTimeTokenAuthenticationConverter();

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private final RedirectServerAuthenticationSuccessHandler defaultSuccessHandler = new RedirectServerAuthenticationSuccessHandler(
				"/");

		private final List<ServerAuthenticationSuccessHandler> defaultSuccessHandlers = new ArrayList<>(
				List.of(this.defaultSuccessHandler));

		private final List<ServerAuthenticationSuccessHandler> authenticationSuccessHandlers = new ArrayList<>();

		private ServerOneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

		private ServerSecurityContextRepository securityContextRepository;

		private String loginProcessingUrl = "/login/ott";

		private String defaultSubmitPageUrl = "/login/ott";

		private String tokenGeneratingUrl = "/ott/generate";

		private boolean submitPageEnabled = true;

		protected void configure(ServerHttpSecurity http) {
			configureSubmitPage(http);
			configureOttGenerateFilter(http);
			configureOttAuthenticationFilter(http);
			configureDefaultLoginPage(http);
		}

		private void configureOttAuthenticationFilter(ServerHttpSecurity http) {
			AuthenticationWebFilter ottWebFilter = new AuthenticationWebFilter(getAuthenticationManager());
			ottWebFilter.setServerAuthenticationConverter(this.authenticationConverter);
			ottWebFilter.setAuthenticationFailureHandler(getAuthenticationFailureHandler());
			ottWebFilter.setAuthenticationSuccessHandler(getAuthenticationSuccessHandler());
			ottWebFilter.setRequiresAuthenticationMatcher(
					ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, this.loginProcessingUrl));
			ottWebFilter.setSecurityContextRepository(this.securityContextRepository);
			http.addFilterAt(ottWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);
		}

		private void configureSubmitPage(ServerHttpSecurity http) {
			if (!this.submitPageEnabled) {
				return;
			}
			OneTimeTokenSubmitPageGeneratingWebFilter submitPage = new OneTimeTokenSubmitPageGeneratingWebFilter();
			submitPage.setLoginProcessingUrl(this.loginProcessingUrl);

			if (StringUtils.hasText(this.defaultSubmitPageUrl)) {
				submitPage.setRequestMatcher(
						ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, this.defaultSubmitPageUrl));
			}
			http.addFilterAt(submitPage, SecurityWebFiltersOrder.ONE_TIME_TOKEN_SUBMIT_PAGE_GENERATING);
		}

		private void configureOttGenerateFilter(ServerHttpSecurity http) {
			GenerateOneTimeTokenWebFilter generateFilter = new GenerateOneTimeTokenWebFilter(getTokenService(),
					getTokenGenerationSuccessHandler());
			generateFilter
				.setRequestMatcher(ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, this.tokenGeneratingUrl));
			http.addFilterAt(generateFilter, SecurityWebFiltersOrder.ONE_TIME_TOKEN);
		}

		private void configureDefaultLoginPage(ServerHttpSecurity http) {
			if (http.formLogin != null) {
				for (WebFilter webFilter : http.webFilters) {
					OrderedWebFilter orderedWebFilter = (OrderedWebFilter) webFilter;
					if (orderedWebFilter.webFilter instanceof LoginPageGeneratingWebFilter loginPageGeneratingFilter) {
						loginPageGeneratingFilter.setOneTimeTokenEnabled(true);
						loginPageGeneratingFilter.setGenerateOneTimeTokenUrl(this.tokenGeneratingUrl);
						break;
					}
				}
			}
		}

		/**
		 * Allows customizing the list of {@link ServerAuthenticationSuccessHandler}. The
		 * default list contains a {@link RedirectServerAuthenticationSuccessHandler} that
		 * redirects to "/".
		 * @param handlersConsumer the handlers consumer
		 * @return the {@link OneTimeTokenLoginSpec} to continue configuring
		 */
		public OneTimeTokenLoginSpec authenticationSuccessHandler(
				Consumer<List<ServerAuthenticationSuccessHandler>> handlersConsumer) {
			Assert.notNull(handlersConsumer, "handlersConsumer cannot be null");
			handlersConsumer.accept(this.authenticationSuccessHandlers);
			return this;
		}

		/**
		 * Specifies the {@link ServerAuthenticationSuccessHandler}
		 * @param authenticationSuccessHandler the
		 * {@link ServerAuthenticationSuccessHandler}.
		 */
		public OneTimeTokenLoginSpec authenticationSuccessHandler(
				ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
			Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
			authenticationSuccessHandler((handlers) -> {
				handlers.clear();
				handlers.add(authenticationSuccessHandler);
			});
			return this;
		}

		private ServerAuthenticationSuccessHandler getAuthenticationSuccessHandler() {
			if (this.authenticationSuccessHandlers.isEmpty()) {
				return new DelegatingServerAuthenticationSuccessHandler(this.defaultSuccessHandlers);
			}
			return new DelegatingServerAuthenticationSuccessHandler(this.authenticationSuccessHandlers);
		}

		/**
		 * Specifies the {@link ServerAuthenticationFailureHandler} to use when
		 * authentication fails. The default is redirecting to "/login?error" using
		 * {@link RedirectServerAuthenticationFailureHandler}
		 * @param authenticationFailureHandler the
		 * {@link ServerAuthenticationFailureHandler} to use when authentication fails.
		 */
		public OneTimeTokenLoginSpec authenticationFailureHandler(
				ServerAuthenticationFailureHandler authenticationFailureHandler) {
			Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		ServerAuthenticationFailureHandler getAuthenticationFailureHandler() {
			if (this.authenticationFailureHandler == null) {
				this.authenticationFailureHandler = new RedirectServerAuthenticationFailureHandler("/login?error");
			}
			return this.authenticationFailureHandler;
		}

		/**
		 * Specifies {@link ReactiveAuthenticationManager} for one time tokens. Default
		 * implementation is {@link OneTimeTokenReactiveAuthenticationManager}
		 * @param authenticationManager
		 */
		public OneTimeTokenLoginSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			Assert.notNull(authenticationManager, "authenticationManager cannot be null");
			this.authenticationManager = authenticationManager;
			return this;
		}

		ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				ReactiveUserDetailsService userDetailsService = getBean(ReactiveUserDetailsService.class);
				return new OneTimeTokenReactiveAuthenticationManager(getTokenService(), userDetailsService);
			}
			return this.authenticationManager;
		}

		/**
		 * Configures the {@link ReactiveOneTimeTokenService} used to generate and consume
		 * {@link OneTimeToken}
		 * @param oneTimeTokenService
		 */
		public OneTimeTokenLoginSpec tokenService(ReactiveOneTimeTokenService oneTimeTokenService) {
			Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
			this.tokenService = oneTimeTokenService;
			return this;
		}

		ReactiveOneTimeTokenService getTokenService() {
			if (this.tokenService != null) {
				return this.tokenService;
			}
			ReactiveOneTimeTokenService oneTimeTokenService = getBeanOrNull(ReactiveOneTimeTokenService.class);
			if (oneTimeTokenService != null) {
				return oneTimeTokenService;
			}
			this.tokenService = new InMemoryReactiveOneTimeTokenService();
			return this.tokenService;
		}

		/**
		 * Use this {@link ServerAuthenticationConverter} when converting incoming
		 * requests to an {@link Authentication}. By default, the
		 * {@link ServerOneTimeTokenAuthenticationConverter} is used.
		 * @param authenticationConverter the {@link ServerAuthenticationConverter} to use
		 */
		public OneTimeTokenLoginSpec authenticationConverter(ServerAuthenticationConverter authenticationConverter) {
			Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
			this.authenticationConverter = authenticationConverter;
			return this;
		}

		/**
		 * Specifies the URL to process the login request, defaults to {@code /login/ott}.
		 * Only POST requests are processed, for that reason make sure that you pass a
		 * valid CSRF token if CSRF protection is enabled.
		 * @param loginProcessingUrl
		 */
		public OneTimeTokenLoginSpec loginProcessingUrl(String loginProcessingUrl) {
			Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty");
			this.loginProcessingUrl = loginProcessingUrl;
			return this;
		}

		/**
		 * Configures whether the default one-time token submit page should be shown. This
		 * will prevent the {@link OneTimeTokenSubmitPageGeneratingWebFilter} to be
		 * configured.
		 * @param show
		 */
		public OneTimeTokenLoginSpec showDefaultSubmitPage(boolean show) {
			this.submitPageEnabled = show;
			return this;
		}

		/**
		 * Sets the URL that the default submit page will be generated. Defaults to
		 * {@code /login/ott}. If you don't want to generate the default submit page you
		 * should use {@link #showDefaultSubmitPage(boolean)}. Note that this method
		 * always invoke {@link #showDefaultSubmitPage(boolean)} passing {@code true}.
		 * @param submitPageUrl
		 */
		public OneTimeTokenLoginSpec defaultSubmitPageUrl(String submitPageUrl) {
			Assert.hasText(submitPageUrl, "submitPageUrl cannot be null or empty");
			this.defaultSubmitPageUrl = submitPageUrl;
			showDefaultSubmitPage(true);
			return this;
		}

		/**
		 * Specifies strategy to be used to handle generated one-time tokens.
		 * @param oneTimeTokenGenerationSuccessHandler
		 */
		public OneTimeTokenLoginSpec tokenGenerationSuccessHandler(
				ServerOneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler) {
			Assert.notNull(oneTimeTokenGenerationSuccessHandler, "oneTimeTokenGenerationSuccessHandler cannot be null");
			this.tokenGenerationSuccessHandler = oneTimeTokenGenerationSuccessHandler;
			return this;
		}

		/**
		 * Specifies the URL that a One-Time Token generate request will be processed.
		 * Defaults to {@code /ott/generate}.
		 * @param tokenGeneratingUrl
		 */
		public OneTimeTokenLoginSpec tokenGeneratingUrl(String tokenGeneratingUrl) {
			Assert.hasText(tokenGeneratingUrl, "tokenGeneratingUrl cannot be null or empty");
			this.tokenGeneratingUrl = tokenGeneratingUrl;
			return this;
		}

		/**
		 * The {@link ServerSecurityContextRepository} used to save the
		 * {@code Authentication}. Defaults to
		 * {@link WebSessionServerSecurityContextRepository}. For the
		 * {@code SecurityContext} to be loaded on subsequent requests the
		 * {@link ReactorContextWebFilter} must be configured to be able to load the value
		 * (they are not implicitly linked).
		 * @param securityContextRepository the repository to use
		 * @return the {@link OneTimeTokenLoginSpec} to continue configuring
		 */
		public OneTimeTokenLoginSpec securityContextRepository(
				ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
			return this;
		}

		private ServerOneTimeTokenGenerationSuccessHandler getTokenGenerationSuccessHandler() {
			if (this.tokenGenerationSuccessHandler == null) {
				this.tokenGenerationSuccessHandler = getBeanOrNull(ServerOneTimeTokenGenerationSuccessHandler.class);
			}
			if (this.tokenGenerationSuccessHandler == null) {
				throw new IllegalStateException("""
						A ServerOneTimeTokenGenerationSuccessHandler is required to enable oneTimeTokenLogin().
						Please provide it as a bean or pass it to the oneTimeTokenLogin() DSL.
						""");
			}
			return this.tokenGenerationSuccessHandler;
		}

	}

}
