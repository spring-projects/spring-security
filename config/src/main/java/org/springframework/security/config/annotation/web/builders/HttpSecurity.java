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

package org.springframework.security.config.annotation.web.builders;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.JeeConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.PasswordManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcLogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2MetadataConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * A {@link HttpSecurity} is similar to Spring Security's XML &lt;http&gt; element in the
 * namespace configuration. It allows configuring web based security for specific http
 * requests. By default it will be applied to all requests, but can be restricted using
 * {@link #requestMatcher(RequestMatcher)} or other similar methods.
 *
 * <h2>Example Usage</h2>
 *
 * The most basic form based configuration can be seen below. The configuration will
 * require that any URL that is requested will require a User with the role "ROLE_USER".
 * It also defines an in memory authentication scheme with a user that has the username
 * "user", the password "password", and the role "ROLE_USER". For additional examples,
 * refer to the Java Doc of individual methods on {@link HttpSecurity}.
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class FormLoginSecurityConfig {
 *
 * 	&#064;Bean
 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
 * 		http.authorizeHttpRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
 * 		return http.build();
 * 	}
 *
 * 	&#064;Bean
 * 	public UserDetailsService userDetailsService() {
 * 		UserDetails user = User.withDefaultPasswordEncoder()
 * 			.username(&quot;user&quot;)
 * 			.password(&quot;password&quot;)
 * 			.roles(&quot;USER&quot;)
 * 			.build();
 * 		return new InMemoryUserDetailsManager(user);
 * 	}
 * }
 * </pre>
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @author Ngoc Nhan
 * @since 3.2
 * @see EnableWebSecurity
 */
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
		implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final boolean mvcPresent;

	private final RequestMatcherConfigurer requestMatcherConfigurer;

	private List<OrderedFilter> filters = new ArrayList<>();

	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

	private FilterOrderRegistration filterOrders = new FilterOrderRegistration();

	private AuthenticationManager authenticationManager;

	static {
		mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR, HttpSecurity.class.getClassLoader());
	}

	/**
	 * Creates a new instance
	 * @param objectPostProcessor the {@link ObjectPostProcessor} that should be used
	 * @param authenticationBuilder the {@link AuthenticationManagerBuilder} to use for
	 * additional updates
	 * @param sharedObjects the shared Objects to initialize the {@link HttpSecurity} with
	 * @see WebSecurityConfiguration
	 */
	@SuppressWarnings("unchecked")
	public HttpSecurity(ObjectPostProcessor<Object> objectPostProcessor,
			AuthenticationManagerBuilder authenticationBuilder, Map<Class<?>, Object> sharedObjects) {
		super(objectPostProcessor);
		Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
		setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
		for (Map.Entry<Class<?>, Object> entry : sharedObjects.entrySet()) {
			setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
		}
		ApplicationContext context = (ApplicationContext) sharedObjects.get(ApplicationContext.class);
		this.requestMatcherConfigurer = new RequestMatcherConfigurer(context);
	}

	/**
	 * @deprecated
	 */
	@Deprecated(since = "6.4", forRemoval = true)
	@SuppressWarnings("unchecked")
	public HttpSecurity(org.springframework.security.config.annotation.ObjectPostProcessor<Object> objectPostProcessor,
			AuthenticationManagerBuilder authenticationBuilder, Map<Class<?>, Object> sharedObjects) {
		super(objectPostProcessor);
		Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
		setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
		for (Map.Entry<Class<?>, Object> entry : sharedObjects.entrySet()) {
			setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
		}
		ApplicationContext context = (ApplicationContext) sharedObjects.get(ApplicationContext.class);
		this.requestMatcherConfigurer = new RequestMatcherConfigurer(context);
	}

	private ApplicationContext getContext() {
		return getSharedObject(ApplicationContext.class);
	}

	/**
	 * Adds the Security headers to the response. This is activated by default when using
	 * {@link EnableWebSecurity}. Accepting the default provided by
	 * {@link EnableWebSecurity} or only invoking {@link #headers()} without invoking
	 * additional methods on it, is the equivalent of:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers()
	 * 				.contentTypeOptions()
	 * 				.and()
	 * 				.xssProtection()
	 * 				.and()
	 * 				.cacheControl()
	 * 				.and()
	 * 				.httpStrictTransportSecurity()
	 * 				.and()
	 * 				.frameOptions()
	 * 				.and()
	 * 			...;
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * You can disable the headers using the following:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers().disable()
	 * 			...;
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * You can enable only a few of the headers by first invoking
	 * {@link HeadersConfigurer#defaultsDisabled()} and then invoking the appropriate
	 * methods on the {@link #headers()} result. For example, the following will enable
	 * {@link HeadersConfigurer#cacheControl()} and
	 * {@link HeadersConfigurer#frameOptions()} only.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers()
	 * 				.defaultsDisabled()
	 * 				.cacheControl()
	 * 				.and()
	 * 				.frameOptions()
	 * 				.and()
	 * 			...;
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * You can also choose to keep the defaults but explicitly disable a subset of
	 * headers. For example, the following will enable all the default headers except
	 * {@link HeadersConfigurer#frameOptions()}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers()
	 * 				 .frameOptions()
	 * 				 	.disable()
	 * 				 .and()
	 * 			...;
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link HeadersConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #headers(Customizer)} or
	 * {@code headers(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 * @see HeadersConfigurer
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public HeadersConfigurer<HttpSecurity> headers() throws Exception {
		return getOrApply(new HeadersConfigurer<>());
	}

	/**
	 * Adds the Security headers to the response. This is activated by default when using
	 * {@link EnableWebSecurity}.
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * Accepting the default provided by {@link EnableWebSecurity} or only invoking
	 * {@link #headers()} without invoking additional methods on it, is the equivalent of:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 *	&#064;Bean
	 *	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 *		http
	 *			.headers((headers) -&gt;
	 *				headers
	 *					.contentTypeOptions(withDefaults())
	 *					.xssProtection(withDefaults())
	 *					.cacheControl(withDefaults())
	 *					.httpStrictTransportSecurity(withDefaults())
	 *					.frameOptions(withDefaults()
	 *			);
	 *		return http.build();
	 *	}
	 * }
	 * </pre>
	 *
	 * You can disable the headers using the following:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 *	&#064;Bean
	 *	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers((headers) -&gt; headers.disable());
	 *		return http.build();
	 *	}
	 * }
	 * </pre>
	 *
	 * You can enable only a few of the headers by first invoking
	 * {@link HeadersConfigurer#defaultsDisabled()} and then invoking the appropriate
	 * methods on the {@link #headers()} result. For example, the following will enable
	 * {@link HeadersConfigurer#cacheControl()} and
	 * {@link HeadersConfigurer#frameOptions()} only.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 *	&#064;Bean
	 *	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 *		http
	 *			.headers((headers) -&gt;
	 *				headers
	 *			 		.defaultsDisabled()
	 *			 		.cacheControl(withDefaults())
	 *			 		.frameOptions(withDefaults())
	 *			);
	 *		return http.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * You can also choose to keep the defaults but explicitly disable a subset of
	 * headers. For example, the following will enable all the default headers except
	 * {@link HeadersConfigurer#frameOptions()}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 *  	http
	 *  		.headers((headers) -&gt;
	 *  			headers
	 *  				.frameOptions((frameOptions) -&gt; frameOptions.disable())
	 *  		);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param headersCustomizer the {@link Customizer} to provide more options for the
	 * {@link HeadersConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity headers(Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer) throws Exception {
		headersCustomizer.customize(getOrApply(new HeadersConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Adds a {@link CorsFilter} to be used. If a bean by the name of corsFilter is
	 * provided, that {@link CorsFilter} is used. Else if corsConfigurationSource is
	 * defined, then that {@link CorsConfiguration} is used. Otherwise, if Spring MVC is
	 * on the classpath a {@link HandlerMappingIntrospector} is used.
	 * @return the {@link CorsConfigurer} for customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #cors(Customizer)} or
	 * {@code cors(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public CorsConfigurer<HttpSecurity> cors() throws Exception {
		return getOrApply(new CorsConfigurer<>());
	}

	/**
	 * Adds a {@link CorsFilter} to be used. If a bean by the name of corsFilter is
	 * provided, that {@link CorsFilter} is used. Else if corsConfigurationSource is
	 * defined, then that {@link CorsConfiguration} is used. Otherwise, if Spring MVC is
	 * on the classpath a {@link HandlerMappingIntrospector} is used. You can enable CORS
	 * using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CorsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.cors(withDefaults());
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param corsCustomizer the {@link Customizer} to provide more options for the
	 * {@link CorsConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity cors(Customizer<CorsConfigurer<HttpSecurity>> corsCustomizer) throws Exception {
		corsCustomizer.customize(getOrApply(new CorsConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring of Session Management.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration demonstrates how to enforce that only a single instance
	 * of a user is authenticated at a time. If a user authenticates with the username
	 * "user" without logging out and an attempt to authenticate with "user" is made the
	 * first session will be forcibly terminated and sent to the "/login?expired" URL.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SessionManagementSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().anyRequest().hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and().sessionManagement().maximumSessions(1)
	 * 				.expiredUrl(&quot;/login?expired&quot;);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do not forget
	 * to configure {@link HttpSessionEventPublisher} for the application to ensure that
	 * expired sessions are cleaned up.
	 *
	 * In a web.xml this can be configured using the following:
	 *
	 * <pre>
	 * &lt;listener&gt;
	 *      &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
	 * &lt;/listener&gt;
	 * </pre>
	 *
	 * Alternatively,
	 * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
	 * could return true.
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #sessionManagement(Customizer)} or
	 * {@code sessionManagement(Customizer.withDefaults())} to stick with defaults. See
	 * the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public SessionManagementConfigurer<HttpSecurity> sessionManagement() throws Exception {
		return getOrApply(new SessionManagementConfigurer<>());
	}

	/**
	 * Allows configuring of Session Management.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration demonstrates how to enforce that only a single instance
	 * of a user is authenticated at a time. If a user authenticates with the username
	 * "user" without logging out and an attempt to authenticate with "user" is made the
	 * first session will be forcibly terminated and sent to the "/login?expired" URL.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SessionManagementSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin((formLogin) -&gt;
	 * 				formLogin
	 * 					.permitAll()
	 * 			)
	 * 			.sessionManagement((sessionManagement) -&gt;
	 * 				sessionManagement
	 * 					.sessionConcurrency((sessionConcurrency) -&gt;
	 * 						sessionConcurrency
	 * 							.maximumSessions(1)
	 * 							.expiredUrl(&quot;/login?expired&quot;)
	 * 					)
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do not forget
	 * to configure {@link HttpSessionEventPublisher} for the application to ensure that
	 * expired sessions are cleaned up.
	 *
	 * In a web.xml this can be configured using the following:
	 *
	 * <pre>
	 * &lt;listener&gt;
	 *      &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
	 * &lt;/listener&gt;
	 * </pre>
	 *
	 * Alternatively,
	 * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
	 * could return true.
	 * @param sessionManagementCustomizer the {@link Customizer} to provide more options
	 * for the {@link SessionManagementConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity sessionManagement(
			Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer) throws Exception {
		sessionManagementCustomizer.customize(getOrApply(new SessionManagementConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring a {@link PortMapper} that is available from
	 * {@link HttpSecurity#getSharedObject(Class)}. Other provided
	 * {@link SecurityConfigurer} objects use this configured {@link PortMapper} as a
	 * default {@link PortMapper} when redirecting from HTTP to HTTPS or from HTTPS to
	 * HTTP (for example when used in combination with {@link #requiresChannel()}. By
	 * default Spring Security uses a {@link PortMapperImpl} which maps the HTTP port 8080
	 * to the HTTPS port 8443 and the HTTP port of 80 to the HTTPS port of 443.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration will ensure that redirects within Spring Security from
	 * HTTP of a port of 9090 will redirect to HTTPS port of 9443 and the HTTP port of 80
	 * to the HTTPS port of 443.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class PortMapperSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and()
	 * 				// Example portMapper() configuration
	 * 				.portMapper().http(9090).mapsTo(9443).http(80).mapsTo(443);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link PortMapperConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #portMapper(Customizer)} or
	 * {@code portMapper(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 * @see #requiresChannel()
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public PortMapperConfigurer<HttpSecurity> portMapper() throws Exception {
		return getOrApply(new PortMapperConfigurer<>());
	}

	/**
	 * Allows configuring a {@link PortMapper} that is available from
	 * {@link HttpSecurity#getSharedObject(Class)}. Other provided
	 * {@link SecurityConfigurer} objects use this configured {@link PortMapper} as a
	 * default {@link PortMapper} when redirecting from HTTP to HTTPS or from HTTPS to
	 * HTTP (for example when used in combination with {@link #requiresChannel()}. By
	 * default Spring Security uses a {@link PortMapperImpl} which maps the HTTP port 8080
	 * to the HTTPS port 8443 and the HTTP port of 80 to the HTTPS port of 443.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration will ensure that redirects within Spring Security from
	 * HTTP of a port of 9090 will redirect to HTTPS port of 9443 and the HTTP port of 80
	 * to the HTTPS port of 443.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class PortMapperSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requiresChannel((requiresChannel) -&gt;
	 * 				requiresChannel
	 * 					.anyRequest().requiresSecure()
	 * 			)
	 * 			.portMapper((portMapper) -&gt;
	 * 				portMapper
	 * 					.http(9090).mapsTo(9443)
	 * 					.http(80).mapsTo(443)
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param portMapperCustomizer the {@link Customizer} to provide more options for the
	 * {@link PortMapperConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see #requiresChannel()
	 */
	public HttpSecurity portMapper(Customizer<PortMapperConfigurer<HttpSecurity>> portMapperCustomizer)
			throws Exception {
		portMapperCustomizer.customize(getOrApply(new PortMapperConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures container based pre authentication. In this case, authentication is
	 * managed by the Servlet Container.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration will use the principal found on the
	 * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
	 * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class JeeSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
	 * 		// Example jee() configuration
	 * 				.jee().mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * Developers wishing to use pre authentication with the container will need to ensure
	 * their web.xml configures the security constraints. For example, the web.xml (there
	 * is no equivalent Java based configuration supported by the Servlet specification)
	 * might look like:
	 *
	 * <pre>
	 * &lt;login-config&gt;
	 *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
	 *     &lt;form-login-config&gt;
	 *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
	 *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
	 *     &lt;/form-login-config&gt;
	 * &lt;/login-config&gt;
	 *
	 * &lt;security-role&gt;
	 *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 * &lt;/security-role&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
	 *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
	 *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 * &lt;/security-constraint&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
	 *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 *     &lt;auth-constraint&gt;
	 *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 *     &lt;/auth-constraint&gt;
	 * &lt;/security-constraint&gt;
	 * </pre>
	 *
	 * Last you will need to configure your container to contain the user with the correct
	 * roles. This configuration is specific to the Servlet Container, so consult your
	 * Servlet Container's documentation.
	 * @return the {@link JeeConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #jee(Customizer)} or
	 * {@code jee(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public JeeConfigurer<HttpSecurity> jee() throws Exception {
		return getOrApply(new JeeConfigurer<>());
	}

	/**
	 * Configures container based pre authentication. In this case, authentication is
	 * managed by the Servlet Container.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration will use the principal found on the
	 * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
	 * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class JeeSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.jee((jee) -&gt;
	 * 				jee
	 * 					.mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;)
	 * 			);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * Developers wishing to use pre authentication with the container will need to ensure
	 * their web.xml configures the security constraints. For example, the web.xml (there
	 * is no equivalent Java based configuration supported by the Servlet specification)
	 * might look like:
	 *
	 * <pre>
	 * &lt;login-config&gt;
	 *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
	 *     &lt;form-login-config&gt;
	 *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
	 *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
	 *     &lt;/form-login-config&gt;
	 * &lt;/login-config&gt;
	 *
	 * &lt;security-role&gt;
	 *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 * &lt;/security-role&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
	 *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
	 *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 * &lt;/security-constraint&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
	 *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 *     &lt;auth-constraint&gt;
	 *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 *     &lt;/auth-constraint&gt;
	 * &lt;/security-constraint&gt;
	 * </pre>
	 *
	 * Last you will need to configure your container to contain the user with the correct
	 * roles. This configuration is specific to the Servlet Container, so consult your
	 * Servlet Container's documentation.
	 * @param jeeCustomizer the {@link Customizer} to provide more options for the
	 * {@link JeeConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity jee(Customizer<JeeConfigurer<HttpSecurity>> jeeCustomizer) throws Exception {
		jeeCustomizer.customize(getOrApply(new JeeConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures X509 based pre authentication.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration will attempt to extract the username from the X509
	 * certificate. Remember that the Servlet Container will need to be configured to
	 * request client certificates in order for this to work.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class X509SecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
	 * 		// Example x509() configuration
	 * 				.x509();
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link X509Configurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #x509(Customizer)} or
	 * {@code x509(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public X509Configurer<HttpSecurity> x509() throws Exception {
		return getOrApply(new X509Configurer<>());
	}

	/**
	 * Configures X509 based pre authentication.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration will attempt to extract the username from the X509
	 * certificate. Remember that the Servlet Container will need to be configured to
	 * request client certificates in order for this to work.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class X509SecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.x509(withDefaults());
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param x509Customizer the {@link Customizer} to provide more options for the
	 * {@link X509Configurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity x509(Customizer<X509Configurer<HttpSecurity>> x509Customizer) throws Exception {
		x509Customizer.customize(getOrApply(new X509Configurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring of Remember Me authentication.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration demonstrates how to allow token based remember me
	 * authentication. Upon authenticating if the HTTP parameter named "remember-me"
	 * exists, then the user will be remembered even after their
	 * {@link jakarta.servlet.http.HttpSession} expires.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RememberMeSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and()
	 * 				// Example Remember Me Configuration
	 * 				.rememberMe();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link RememberMeConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #rememberMe(Customizer)} or
	 * {@code rememberMe(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public RememberMeConfigurer<HttpSecurity> rememberMe() throws Exception {
		return getOrApply(new RememberMeConfigurer<>());
	}

	/**
	 * Allows configuring of Remember Me authentication.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration demonstrates how to allow token based remember me
	 * authentication. Upon authenticating if the HTTP parameter named "remember-me"
	 * exists, then the user will be remembered even after their
	 * {@link jakarta.servlet.http.HttpSession} expires.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RememberMeSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			.rememberMe(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param rememberMeCustomizer the {@link Customizer} to provide more options for the
	 * {@link RememberMeConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity rememberMe(Customizer<RememberMeConfigurer<HttpSecurity>> rememberMeCustomizer)
			throws Exception {
		rememberMeCustomizer.customize(getOrApply(new RememberMeConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows restricting access based upon the {@link HttpServletRequest} using
	 * {@link RequestMatcher} implementations (i.e. via URL patterns).
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * The most basic example is to configure all URLs to require the role "ROLE_USER".
	 * The configuration below requires authentication to every URL and will grant access
	 * to both the user "admin" and "user".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * We can also configure multiple URLs. The configuration below requires
	 * authentication to every URL and will grant access to URLs starting with /admin/ to
	 * only the "admin" user. All other URLs either user can access.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 				.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).requestMatchers(&quot;/admin/**&quot;)
	 * 			.hasRole(&quot;ADMIN&quot;)
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #authorizeHttpRequests(Customizer)}
	 * instead
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests()
			throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context)).getRegistry();
	}

	/**
	 * Allows restricting access based upon the {@link HttpServletRequest} using
	 * {@link RequestMatcher} implementations (i.e. via URL patterns).
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * The most basic example is to configure all URLs to require the role "ROLE_USER".
	 * The configuration below requires authentication to every URL and will grant access
	 * to both the user "admin" and "user".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * We can also configure multiple URLs. The configuration below requires
	 * authentication to every URL and will grant access to URLs starting with /admin/ to
	 * only the "admin" user. All other URLs either user can access.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		 http
	 * 		 	.authorizeRequests((authorizeRequests) -&gt;
	 * 		 		authorizeRequests
	 * 			 		.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			 		.requestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 		 	);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param authorizeRequestsCustomizer the {@link Customizer} to provide more options
	 * for the {@link ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #authorizeHttpRequests(Customizer)}
	 * instead
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public HttpSecurity authorizeRequests(
			Customizer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry> authorizeRequestsCustomizer)
			throws Exception {
		ApplicationContext context = getContext();
		authorizeRequestsCustomizer
			.customize(getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context)).getRegistry());
		return HttpSecurity.this;
	}

	/**
	 * Allows restricting access based upon the {@link HttpServletRequest} using
	 * {@link RequestMatcher} implementations (i.e. via URL patterns).
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * The most basic example is to configure all URLs to require the role "ROLE_USER".
	 * The configuration below requires authentication to every URL and will grant access
	 * to both the user "admin" and "user".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests()
	 * 				.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * We can also configure multiple URLs. The configuration below requires
	 * authentication to every URL and will grant access to URLs starting with /admin/ to
	 * only the "admin" user. All other URLs either user can access.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests()
	 * 				.requestMatchers(&quot;/admin&quot;).hasRole(&quot;ADMIN&quot;)
	 * 				.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests()
	 * 				.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.requestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 				.and()
	 * 			.formLogin();
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.6
	 * @deprecated For removal in 7.0. Use {@link #authorizeHttpRequests(Customizer)}
	 * instead
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorizeHttpRequests()
			throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new AuthorizeHttpRequestsConfigurer<>(context)).getRegistry();
	}

	/**
	 * Allows restricting access based upon the {@link HttpServletRequest} using
	 * {@link RequestMatcher} implementations (i.e. via URL patterns).
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * The most basic example is to configure all URLs to require the role "ROLE_USER".
	 * The configuration below requires authentication to every URL and will grant access
	 * to both the user "admin" and "user".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests((authorizeHttpRequests) -&gt;
	 * 				authorizeHttpRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * We can also configure multiple URLs. The configuration below requires
	 * authentication to every URL and will grant access to URLs starting with /admin/ to
	 * only the "admin" user. All other URLs either user can access.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests((authorizeHttpRequests) -&gt;
	 * 				authorizeHttpRequests
	 * 					.requestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		UserDetails admin = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;admin&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;ADMIN&quot;, &quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user, admin);
	 * 	}
	 * }
	 * </pre>
	 *
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 		 	.authorizeHttpRequests((authorizeHttpRequests) -&gt;
	 * 		 		authorizeHttpRequests
	 * 			 		.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			 		.requestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 		 	);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param authorizeHttpRequestsCustomizer the {@link Customizer} to provide more
	 * options for the {@link AuthorizationManagerRequestMatcherRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.5
	 */
	public HttpSecurity authorizeHttpRequests(
			Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> authorizeHttpRequestsCustomizer)
			throws Exception {
		ApplicationContext context = getContext();
		authorizeHttpRequestsCustomizer
			.customize(getOrApply(new AuthorizeHttpRequestsConfigurer<>(context)).getRegistry());
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring the Request Cache. For example, a protected page (/protected)
	 * may be requested prior to authentication. The application will redirect the user to
	 * a login page. After authentication, Spring Security will redirect the user to the
	 * originally requested protected page (/protected). This is automatically applied
	 * when using {@link EnableWebSecurity}.
	 * @return the {@link RequestCacheConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #requestCache(Customizer)} or
	 * {@code requestCache(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public RequestCacheConfigurer<HttpSecurity> requestCache() throws Exception {
		return getOrApply(new RequestCacheConfigurer<>());
	}

	/**
	 * Allows configuring the Request Cache. For example, a protected page (/protected)
	 * may be requested prior to authentication. The application will redirect the user to
	 * a login page. After authentication, Spring Security will redirect the user to the
	 * originally requested protected page (/protected). This is automatically applied
	 * when using {@link EnableWebSecurity}.
	 *
	 * <h2>Example Custom Configuration</h2>
	 *
	 * The following example demonstrates how to disable request caching.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestCacheDisabledSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.requestCache((requestCache) -&gt;
	 * 				requestCache.disable()
	 * 			);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param requestCacheCustomizer the {@link Customizer} to provide more options for
	 * the {@link RequestCacheConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity requestCache(Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer)
			throws Exception {
		requestCacheCustomizer.customize(getOrApply(new RequestCacheConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring exception handling. This is automatically applied when using
	 * {@link EnableWebSecurity}.
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #exceptionHandling(Customizer)} or
	 * {@code exceptionHandling(Customizer.withDefaults())} to stick with defaults. See
	 * the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling() throws Exception {
		return getOrApply(new ExceptionHandlingConfigurer<>());
	}

	/**
	 * Allows configuring exception handling. This is automatically applied when using
	 * {@link EnableWebSecurity}.
	 *
	 * <h2>Example Custom Configuration</h2>
	 *
	 * The following customization will ensure that users who are denied access are
	 * forwarded to the page "/errors/access-denied".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ExceptionHandlingSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			// sample exception handling customization
	 * 			.exceptionHandling((exceptionHandling) -&gt;
	 * 				exceptionHandling
	 * 					.accessDeniedPage(&quot;/errors/access-denied&quot;)
	 * 			);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param exceptionHandlingCustomizer the {@link Customizer} to provide more options
	 * for the {@link ExceptionHandlingConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity exceptionHandling(
			Customizer<ExceptionHandlingConfigurer<HttpSecurity>> exceptionHandlingCustomizer) throws Exception {
		exceptionHandlingCustomizer.customize(getOrApply(new ExceptionHandlingConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Sets up management of the {@link SecurityContext} on the
	 * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
	 * automatically applied when using {@link EnableWebSecurity}.
	 * @return the {@link SecurityContextConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #securityContext(Customizer)} or
	 * {@code securityContext(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public SecurityContextConfigurer<HttpSecurity> securityContext() throws Exception {
		return getOrApply(new SecurityContextConfigurer<>());
	}

	/**
	 * Sets up management of the {@link SecurityContext} on the
	 * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
	 * automatically applied when using {@link EnableWebSecurity}.
	 *
	 * The following customization specifies the shared {@link SecurityContextRepository}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SecurityContextSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityContext((securityContext) -&gt;
	 * 				securityContext
	 * 					.securityContextRepository(SCR)
	 * 			);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param securityContextCustomizer the {@link Customizer} to provide more options for
	 * the {@link SecurityContextConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity securityContext(Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer)
			throws Exception {
		securityContextCustomizer.customize(getOrApply(new SecurityContextConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Integrates the {@link HttpServletRequest} methods with the values found on the
	 * {@link SecurityContext}. This is automatically applied when using
	 * {@link EnableWebSecurity}.
	 * @return the {@link ServletApiConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #servletApi(Customizer)} or
	 * {@code servletApi(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public ServletApiConfigurer<HttpSecurity> servletApi() throws Exception {
		return getOrApply(new ServletApiConfigurer<>());
	}

	/**
	 * Integrates the {@link HttpServletRequest} methods with the values found on the
	 * {@link SecurityContext}. This is automatically applied when using
	 * {@link EnableWebSecurity}. You can disable it using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ServletApiSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.servletApi((servletApi) -&gt;
	 * 				servletApi.disable()
	 * 			);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param servletApiCustomizer the {@link Customizer} to provide more options for the
	 * {@link ServletApiConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity servletApi(Customizer<ServletApiConfigurer<HttpSecurity>> servletApiCustomizer)
			throws Exception {
		servletApiCustomizer.customize(getOrApply(new ServletApiConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Enables CSRF protection. This is activated by default when using
	 * {@link EnableWebSecurity}'s default constructor. You can disable it using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.csrf().disable()
	 * 			...;
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #csrf(Customizer)} or
	 * {@code csrf(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public CsrfConfigurer<HttpSecurity> csrf() throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new CsrfConfigurer<>(context));
	}

	/**
	 * Enables CSRF protection. This is activated by default when using
	 * {@link EnableWebSecurity}. You can disable it using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.csrf((csrf) -&gt; csrf.disable());
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param csrfCustomizer the {@link Customizer} to provide more options for the
	 * {@link CsrfConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity csrf(Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {
		ApplicationContext context = getContext();
		csrfCustomizer.customize(getOrApply(new CsrfConfigurer<>(context)));
		return HttpSecurity.this;
	}

	/**
	 * Provides logout support. This is automatically applied when using
	 * {@link EnableWebSecurity}. The default is that accessing the URL "/logout" will log
	 * the user out by invalidating the HTTP Session, cleaning up any
	 * {@link #rememberMe()} authentication that was configured, clearing the
	 * {@link SecurityContextHolder}, and then redirect to "/login?success".
	 *
	 * <h2>Example Custom Configuration</h2>
	 *
	 * The following customization to log out when the URL "/custom-logout" is invoked.
	 * Log out will remove the cookie named "remove", not invalidate the HttpSession,
	 * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class LogoutSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.and()
	 * 				// sample logout customization
	 * 				.logout().deleteCookies(&quot;remove&quot;).invalidateHttpSession(false)
	 * 				.logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link LogoutConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #logout(Customizer)} or
	 * {@code logout(Customizer.withDefaults())} to stick with defaults. See the <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public LogoutConfigurer<HttpSecurity> logout() throws Exception {
		return getOrApply(new LogoutConfigurer<>());
	}

	/**
	 * Provides logout support. This is automatically applied when using
	 * {@link EnableWebSecurity}. The default is that accessing the URL "/logout" will log
	 * the user out by invalidating the HTTP Session, cleaning up any
	 * {@link #rememberMe()} authentication that was configured, clearing the
	 * {@link SecurityContextHolder}, and then redirect to "/login?success".
	 *
	 * <h2>Example Custom Configuration</h2>
	 *
	 * The following customization to log out when the URL "/custom-logout" is invoked.
	 * Log out will remove the cookie named "remove", not invalidate the HttpSession,
	 * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class LogoutSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample logout customization
	 * 			.logout((logout) -&gt;
	 * 				logout.deleteCookies(&quot;remove&quot;)
	 * 					.invalidateHttpSession(false)
	 * 					.logoutUrl(&quot;/custom-logout&quot;)
	 * 					.logoutSuccessUrl(&quot;/logout-success&quot;)
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param logoutCustomizer the {@link Customizer} to provide more options for the
	 * {@link LogoutConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity logout(Customizer<LogoutConfigurer<HttpSecurity>> logoutCustomizer) throws Exception {
		logoutCustomizer.customize(getOrApply(new LogoutConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring how an anonymous user is represented. This is automatically
	 * applied when used in conjunction with {@link EnableWebSecurity}. By default
	 * anonymous users will be represented with an
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
	 * and contain the role "ROLE_ANONYMOUS".
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration demonstrates how to specify that anonymous users should
	 * contain the role "ROLE_ANON" instead.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin()
	 * 				.and()
	 * 			// sample anonymous customization
	 * 			.anonymous().authorities(&quot;ROLE_ANON&quot;);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The following demonstrates how to represent anonymous users as null. Note that this
	 * can cause {@link NullPointerException} in code that assumes anonymous
	 * authentication is enabled.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin()
	 * 				.and()
	 * 			// sample anonymous customization
	 * 			.anonymous().disable();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link AnonymousConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #anonymous(Customizer)} or
	 * {@code anonymous(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public AnonymousConfigurer<HttpSecurity> anonymous() throws Exception {
		return getOrApply(new AnonymousConfigurer<>());
	}

	/**
	 * Allows configuring how an anonymous user is represented. This is automatically
	 * applied when used in conjunction with {@link EnableWebSecurity}. By default
	 * anonymous users will be represented with an
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
	 * and contain the role "ROLE_ANONYMOUS".
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following configuration demonstrates how to specify that anonymous users should
	 * contain the role "ROLE_ANON" instead.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample anonymous customization
	 * 			.anonymous((anonymous) -&gt;
	 * 				anonymous
	 * 					.authorities(&quot;ROLE_ANON&quot;)
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The following demonstrates how to represent anonymous users as null. Note that this
	 * can cause {@link NullPointerException} in code that assumes anonymous
	 * authentication is enabled.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample anonymous customization
	 * 			.anonymous((anonymous) -&gt;
	 * 				anonymous.disable()
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param anonymousCustomizer the {@link Customizer} to provide more options for the
	 * {@link AnonymousConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity anonymous(Customizer<AnonymousConfigurer<HttpSecurity>> anonymousCustomizer) throws Exception {
		anonymousCustomizer.customize(getOrApply(new AnonymousConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Specifies to support form based authentication. If
	 * {@link FormLoginConfigurer#loginPage(String)} is not specified a default login page
	 * will be generated.
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * The most basic configuration defaults to automatically generating a login page at
	 * the URL "/login", redirecting to "/login?error" for authentication failure. The
	 * details of the login page can be found on
	 * {@link FormLoginConfigurer#loginPage(String)}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below demonstrates customizing the defaults.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.usernameParameter(&quot;username&quot;) // default is username
	 * 				.passwordParameter(&quot;password&quot;) // default is password
	 * 				.loginPage(&quot;/authentication/login&quot;) // default is /login with an HTTP get
	 * 				.failureUrl(&quot;/authentication/login?failed&quot;) // default is /login?error
	 * 				.loginProcessingUrl(&quot;/authentication/login/process&quot;); // default is /login
	 * 																		// with an HTTP
	 * 																		// post
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link FormLoginConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #formLogin(Customizer)} or
	 * {@code formLogin(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 * @see FormLoginConfigurer#loginPage(String)
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
		return getOrApply(new FormLoginConfigurer<>());
	}

	/**
	 * Specifies to support form based authentication. If
	 * {@link FormLoginConfigurer#loginPage(String)} is not specified a default login page
	 * will be generated.
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * The most basic configuration defaults to automatically generating a login page at
	 * the URL "/login", redirecting to "/login?error" for authentication failure. The
	 * details of the login page can be found on
	 * {@link FormLoginConfigurer#loginPage(String)}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below demonstrates customizing the defaults.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin((formLogin) -&gt;
	 * 				formLogin
	 * 					.usernameParameter(&quot;username&quot;)
	 * 					.passwordParameter(&quot;password&quot;)
	 * 					.loginPage(&quot;/authentication/login&quot;)
	 * 					.failureUrl(&quot;/authentication/login?failed&quot;)
	 * 					.loginProcessingUrl(&quot;/authentication/login/process&quot;)
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param formLoginCustomizer the {@link Customizer} to provide more options for the
	 * {@link FormLoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see FormLoginConfigurer#loginPage(String)
	 */
	public HttpSecurity formLogin(Customizer<FormLoginConfigurer<HttpSecurity>> formLoginCustomizer) throws Exception {
		formLoginCustomizer.customize(getOrApply(new FormLoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures authentication support using an SAML 2.0 Service Provider. <br>
	 * <br>
	 *
	 * The &quot;authentication flow&quot; is implemented using the <b>Web Browser SSO
	 * Profile, using POST and REDIRECT bindings</b>, as documented in the
	 * <a target="_blank" href="https://docs.oasis-open.org/security/saml/">SAML V2.0
	 * Core,Profiles and Bindings</a> specifications. <br>
	 * <br>
	 *
	 * As a prerequisite to using this feature, is that you have a SAML v2.0 Identity
	 * Provider to provide an assertion. The representation of the Service Provider, the
	 * relying party, and the remote Identity Provider, the asserting party is contained
	 * within {@link RelyingPartyRegistration}. <br>
	 * <br>
	 *
	 * {@link RelyingPartyRegistration}(s) are composed within a
	 * {@link RelyingPartyRegistrationRepository}, which is <b>required</b> and must be
	 * registered with the {@link ApplicationContext} or configured via
	 * <code>saml2Login().relyingPartyRegistrationRepository(..)</code>. <br>
	 * <br>
	 *
	 * The default configuration provides an auto-generated login page at
	 * <code>&quot;/login&quot;</code> and redirects to
	 * <code>&quot;/login?error&quot;</code> when an authentication error occurs. The
	 * login page will display each of the identity providers with a link that is capable
	 * of initiating the &quot;authentication flow&quot;. <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using SimpleSamlPhp
	 * as the Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class Saml2LoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.anyRequest().authenticated()
	 * 				.and()
	 * 			.saml2Login();
	 * 		return http.build();
	 * 	}
	 *
	 *	&#064;Bean
	 *	public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 *		return new InMemoryRelyingPartyRegistrationRepository(this.getSaml2RelyingPartyRegistration());
	 *	}
	 *
	 * 	private RelyingPartyRegistration getSaml2RelyingPartyRegistration() {
	 * 		//remote IDP entity ID
	 * 		String idpEntityId = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php";
	 * 		//remote WebSSO Endpoint - Where to Send AuthNRequests to
	 * 		String webSsoEndpoint = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php";
	 * 		//local registration ID
	 * 		String registrationId = "simplesamlphp";
	 * 		//local entity ID - autogenerated based on URL
	 * 		String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
	 * 		//local signing (and decryption key)
	 * 		Saml2X509Credential signingCredential = getSigningCredential();
	 * 		//IDP certificate for verification of incoming messages
	 * 		Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();
	 * 		return RelyingPartyRegistration.withRegistrationId(registrationId)
	 * 				.remoteIdpEntityId(idpEntityId)
	 * 				.idpWebSsoUrl(webSsoEndpoint)
	 * 				.credential(signingCredential)
	 * 				.credential(idpVerificationCertificate)
	 * 				.localEntityIdTemplate(localEntityIdTemplate)
	 * 				.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * <p>
	 * @return the {@link Saml2LoginConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.2
	 * @deprecated For removal in 7.0. Use {@link #saml2Login(Customizer)} or
	 * {@code saml2Login(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public Saml2LoginConfigurer<HttpSecurity> saml2Login() throws Exception {
		return getOrApply(new Saml2LoginConfigurer<>());
	}

	/**
	 * Configures authentication support using an SAML 2.0 Service Provider. <br>
	 * <br>
	 *
	 * The &quot;authentication flow&quot; is implemented using the <b>Web Browser SSO
	 * Profile, using POST and REDIRECT bindings</b>, as documented in the
	 * <a target="_blank" href="https://docs.oasis-open.org/security/saml/">SAML V2.0
	 * Core,Profiles and Bindings</a> specifications. <br>
	 * <br>
	 *
	 * As a prerequisite to using this feature, is that you have a SAML v2.0 Identity
	 * Provider to provide an assertion. The representation of the Service Provider, the
	 * relying party, and the remote Identity Provider, the asserting party is contained
	 * within {@link RelyingPartyRegistration}. <br>
	 * <br>
	 *
	 * {@link RelyingPartyRegistration}(s) are composed within a
	 * {@link RelyingPartyRegistrationRepository}, which is <b>required</b> and must be
	 * registered with the {@link ApplicationContext} or configured via
	 * <code>saml2Login().relyingPartyRegistrationRepository(..)</code>. <br>
	 * <br>
	 *
	 * The default configuration provides an auto-generated login page at
	 * <code>&quot;/login&quot;</code> and redirects to
	 * <code>&quot;/login?error&quot;</code> when an authentication error occurs. The
	 * login page will display each of the identity providers with a link that is capable
	 * of initiating the &quot;authentication flow&quot;. <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using SimpleSamlPhp
	 * as the Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class Saml2LoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.saml2Login(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 *	&#064;Bean
	 *	public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 *		return new InMemoryRelyingPartyRegistrationRepository(this.getSaml2RelyingPartyRegistration());
	 *	}
	 *
	 * 	private RelyingPartyRegistration getSaml2RelyingPartyRegistration() {
	 * 		//remote IDP entity ID
	 * 		String idpEntityId = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php";
	 * 		//remote WebSSO Endpoint - Where to Send AuthNRequests to
	 * 		String webSsoEndpoint = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php";
	 * 		//local registration ID
	 * 		String registrationId = "simplesamlphp";
	 * 		//local entity ID - autogenerated based on URL
	 * 		String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
	 * 		//local signing (and decryption key)
	 * 		Saml2X509Credential signingCredential = getSigningCredential();
	 * 		//IDP certificate for verification of incoming messages
	 * 		Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();
	 * 		return RelyingPartyRegistration.withRegistrationId(registrationId)
	 * 				.remoteIdpEntityId(idpEntityId)
	 * 				.idpWebSsoUrl(webSsoEndpoint)
	 * 				.credential(signingCredential)
	 * 				.credential(idpVerificationCertificate)
	 * 				.localEntityIdTemplate(localEntityIdTemplate)
	 * 				.build();
	 * 	}
	 * }
	 * </pre>
	 *
	 * <p>
	 * @param saml2LoginCustomizer the {@link Customizer} to provide more options for the
	 * {@link Saml2LoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.2
	 */
	public HttpSecurity saml2Login(Customizer<Saml2LoginConfigurer<HttpSecurity>> saml2LoginCustomizer)
			throws Exception {
		saml2LoginCustomizer.customize(getOrApply(new Saml2LoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures logout support for an SAML 2.0 Relying Party. <br>
	 * <br>
	 *
	 * Implements the <b>Single Logout Profile, using POST and REDIRECT bindings</b>, as
	 * documented in the
	 * <a target="_blank" href="https://docs.oasis-open.org/security/saml/">SAML V2.0
	 * Core, Profiles and Bindings</a> specifications. <br>
	 * <br>
	 *
	 * As a prerequisite to using this feature, is that you have a SAML v2.0 Asserting
	 * Party to sent a logout request to. The representation of the relying party and the
	 * asserting party is contained within {@link RelyingPartyRegistration}. <br>
	 * <br>
	 *
	 * {@link RelyingPartyRegistration}(s) are composed within a
	 * {@link RelyingPartyRegistrationRepository}, which is <b>required</b> and must be
	 * registered with the {@link ApplicationContext} or configured via
	 * {@link #saml2Login(Customizer)}.<br>
	 * <br>
	 *
	 * The default configuration provides an auto-generated logout endpoint at
	 * <code>&quot;/logout&quot;</code> and redirects to <code>/login?logout</code> when
	 * logout completes. <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using a
	 * hypothetical asserting party.
	 *
	 * <pre>
	 *	&#064;EnableWebSecurity
	 *	&#064;Configuration
	 *	public class Saml2LogoutSecurityConfig {
	 *		&#064;Bean
	 *		public SecurityFilterChain web(HttpSecurity http) throws Exception {
	 *			http
	 *				.authorizeRequests((authorize) -&gt; authorize
	 *					.anyRequest().authenticated()
	 *				)
	 *				.saml2Login(withDefaults())
	 *				.saml2Logout(withDefaults());
	 *			return http.build();
	 *		}
	 *
	 *		&#064;Bean
	 *		public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 *			RelyingPartyRegistration registration = RelyingPartyRegistrations
	 *					.withMetadataLocation("https://ap.example.org/metadata")
	 *					.registrationId("simple")
	 *					.build();
	 *			return new InMemoryRelyingPartyRegistrationRepository(registration);
	 *		}
	 *	}
	 * </pre>
	 *
	 * <p>
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.6
	 */
	public HttpSecurity saml2Logout(Customizer<Saml2LogoutConfigurer<HttpSecurity>> saml2LogoutCustomizer)
			throws Exception {
		saml2LogoutCustomizer.customize(getOrApply(new Saml2LogoutConfigurer<>(getContext())));
		return HttpSecurity.this;
	}

	/**
	 * Configures logout support for an SAML 2.0 Relying Party. <br>
	 * <br>
	 *
	 * Implements the <b>Single Logout Profile, using POST and REDIRECT bindings</b>, as
	 * documented in the
	 * <a target="_blank" href="https://docs.oasis-open.org/security/saml/">SAML V2.0
	 * Core, Profiles and Bindings</a> specifications. <br>
	 * <br>
	 *
	 * As a prerequisite to using this feature, is that you have a SAML v2.0 Asserting
	 * Party to sent a logout request to. The representation of the relying party and the
	 * asserting party is contained within {@link RelyingPartyRegistration}. <br>
	 * <br>
	 *
	 * {@link RelyingPartyRegistration}(s) are composed within a
	 * {@link RelyingPartyRegistrationRepository}, which is <b>required</b> and must be
	 * registered with the {@link ApplicationContext} or configured via
	 * {@link #saml2Login()}.<br>
	 * <br>
	 *
	 * The default configuration provides an auto-generated logout endpoint at
	 * <code>&quot;/logout&quot;</code> and redirects to <code>/login?logout</code> when
	 * logout completes. <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using a
	 * hypothetical asserting party.
	 *
	 * <pre>
	 *	&#064;EnableWebSecurity
	 *	&#064;Configuration
	 *	public class Saml2LogoutSecurityConfig {
	 *		&#064;Bean
	 *		public SecurityFilterChain web(HttpSecurity http) throws Exception {
	 *			http
	 *				.authorizeRequests()
	 *					.anyRequest().authenticated()
	 *					.and()
	 *				.saml2Login()
	 *					.and()
	 *				.saml2Logout();
	 *			return http.build();
	 *		}
	 *
	 *		&#064;Bean
	 *		public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 *			RelyingPartyRegistration registration = RelyingPartyRegistrations
	 *					.withMetadataLocation("https://ap.example.org/metadata")
	 *					.registrationId("simple")
	 *					.build();
	 *			return new InMemoryRelyingPartyRegistrationRepository(registration);
	 *		}
	 *	}
	 * </pre>
	 *
	 * <p>
	 * @return the {@link Saml2LoginConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.6
	 * @deprecated For removal in 7.0. Use {@link #saml2Logout(Customizer)} or
	 * {@code saml2Logout(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public Saml2LogoutConfigurer<HttpSecurity> saml2Logout() throws Exception {
		return getOrApply(new Saml2LogoutConfigurer<>(getContext()));
	}

	/**
	 * Configures a SAML 2.0 metadata endpoint that presents relying party configurations
	 * in an {@code <md:EntityDescriptor>} payload.
	 *
	 * <p>
	 * By default, the endpoints are {@code /saml2/metadata} and
	 * {@code /saml2/metadata/{registrationId}} though note that also
	 * {@code /saml2/service-provider-metadata/{registrationId}} is recognized for
	 * backward compatibility purposes.
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using a
	 * hypothetical asserting party.
	 *
	 * <pre>
	 *	&#064;EnableWebSecurity
	 *	&#064;Configuration
	 *	public class Saml2LogoutSecurityConfig {
	 *		&#064;Bean
	 *		public SecurityFilterChain web(HttpSecurity http) throws Exception {
	 *			http
	 *				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
	 *				.saml2Metadata(Customizer.withDefaults());
	 *			return http.build();
	 *		}
	 *
	 *		&#064;Bean
	 *		public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 *			RelyingPartyRegistration registration = RelyingPartyRegistrations
	 *					.withMetadataLocation("https://ap.example.org/metadata")
	 *					.registrationId("simple")
	 *					.build();
	 *			return new InMemoryRelyingPartyRegistrationRepository(registration);
	 *		}
	 *	}
	 * </pre>
	 * @param saml2MetadataConfigurer the {@link Customizer} to provide more options for
	 * the {@link Saml2MetadataConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 6.1
	 */
	public HttpSecurity saml2Metadata(Customizer<Saml2MetadataConfigurer<HttpSecurity>> saml2MetadataConfigurer)
			throws Exception {
		saml2MetadataConfigurer.customize(getOrApply(new Saml2MetadataConfigurer<>(getContext())));
		return HttpSecurity.this;
	}

	/**
	 * Configures a SAML 2.0 metadata endpoint that presents relying party configurations
	 * in an {@code <md:EntityDescriptor>} payload.
	 *
	 * <p>
	 * By default, the endpoints are {@code /saml2/metadata} and
	 * {@code /saml2/metadata/{registrationId}} though note that also
	 * {@code /saml2/service-provider-metadata/{registrationId}} is recognized for
	 * backward compatibility purposes.
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using a
	 * hypothetical asserting party.
	 *
	 * <pre>
	 *	&#064;EnableWebSecurity
	 *	&#064;Configuration
	 *	public class Saml2LogoutSecurityConfig {
	 *		&#064;Bean
	 *		public SecurityFilterChain web(HttpSecurity http) throws Exception {
	 *			http
	 *				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
	 *				.saml2Metadata(Customizer.withDefaults());
	 *			return http.build();
	 *		}
	 *
	 *		&#064;Bean
	 *		public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 *			RelyingPartyRegistration registration = RelyingPartyRegistrations
	 *					.withMetadataLocation("https://ap.example.org/metadata")
	 *					.registrationId("simple")
	 *					.build();
	 *			return new InMemoryRelyingPartyRegistrationRepository(registration);
	 *		}
	 *	}
	 * </pre>
	 * @return the {@link Saml2MetadataConfigurer} for further customizations
	 * @throws Exception
	 * @since 6.1
	 * @deprecated For removal in 7.0. Use {@link #saml2Metadata(Customizer)} or
	 * {@code saml2Metadata(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public Saml2MetadataConfigurer<HttpSecurity> saml2Metadata() throws Exception {
		return getOrApply(new Saml2MetadataConfigurer<>(getContext()));
	}

	/**
	 * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0
	 * Provider. <br>
	 * <br>
	 *
	 * The &quot;authentication flow&quot; is implemented using the <b>Authorization Code
	 * Grant</b>, as specified in the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">OAuth 2.0
	 * Authorization Framework</a> and <a target="_blank" href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">OpenID Connect
	 * Core 1.0</a> specification. <br>
	 * <br>
	 *
	 * As a prerequisite to using this feature, you must register a client with a
	 * provider. The client registration information may than be used for configuring a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration}
	 * using a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.Builder}.
	 * <br>
	 * <br>
	 *
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration}(s)
	 * are composed within a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistrationRepository},
	 * which is <b>required</b> and must be registered with the {@link ApplicationContext}
	 * or configured via <code>oauth2Login().clientRegistrationRepository(..)</code>. <br>
	 * <br>
	 *
	 * The default configuration provides an auto-generated login page at
	 * <code>&quot;/login&quot;</code> and redirects to
	 * <code>&quot;/login?error&quot;</code> when an authentication error occurs. The
	 * login page will display each of the clients with a link that is capable of
	 * initiating the &quot;authentication flow&quot;. <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using Google as the
	 * Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OAuth2LoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.anyRequest().authenticated()
	 * 				.and()
	 * 			.oauth2Login();
	 * 		return http.build();
	 * 	}
	 *
	 *	&#064;Bean
	 *	public ClientRegistrationRepository clientRegistrationRepository() {
	 *		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	 *	}
	 *
	 * 	private ClientRegistration googleClientRegistration() {
	 * 		return ClientRegistration.withRegistrationId("google")
	 * 			.clientId("google-client-id")
	 * 			.clientSecret("google-client-secret")
	 * 			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	 * 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * 			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
	 * 			.scope("openid", "profile", "email", "address", "phone")
	 * 			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
	 * 			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
	 * 			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
	 * 			.userNameAttributeName(IdTokenClaimNames.SUB)
	 * 			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
	 * 			.clientName("Google")
	 * 			.build();
	 *	}
	 * }
	 * </pre>
	 *
	 * <p>
	 * For more advanced configuration, see {@link OAuth2LoginConfigurer} for available
	 * options to customize the defaults.
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.0
	 * @deprecated For removal in 7.0. Use {@link #oauth2Login(Customizer)} or
	 * {@code oauth2Login(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code
	 * Grant</a>
	 * @see <a target="_blank" href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1
	 * Authorization Code Flow</a>
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistration
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public OAuth2LoginConfigurer<HttpSecurity> oauth2Login() throws Exception {
		return getOrApply(new OAuth2LoginConfigurer<>());
	}

	/**
	 * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0
	 * Provider. <br>
	 * <br>
	 *
	 * The &quot;authentication flow&quot; is implemented using the <b>Authorization Code
	 * Grant</b>, as specified in the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">OAuth 2.0
	 * Authorization Framework</a> and <a target="_blank" href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">OpenID Connect
	 * Core 1.0</a> specification. <br>
	 * <br>
	 *
	 * As a prerequisite to using this feature, you must register a client with a
	 * provider. The client registration information may than be used for configuring a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration}
	 * using a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.Builder}.
	 * <br>
	 * <br>
	 *
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration}(s)
	 * are composed within a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistrationRepository},
	 * which is <b>required</b> and must be registered with the {@link ApplicationContext}
	 * or configured via <code>oauth2Login().clientRegistrationRepository(..)</code>. <br>
	 * <br>
	 *
	 * The default configuration provides an auto-generated login page at
	 * <code>&quot;/login&quot;</code> and redirects to
	 * <code>&quot;/login?error&quot;</code> when an authentication error occurs. The
	 * login page will display each of the clients with a link that is capable of
	 * initiating the &quot;authentication flow&quot;. <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 *
	 * The following example shows the minimal configuration required, using Google as the
	 * Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OAuth2LoginSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oauth2Login(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 *	&#064;Bean
	 *	public ClientRegistrationRepository clientRegistrationRepository() {
	 *		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	 *	}
	 *
	 * 	private ClientRegistration googleClientRegistration() {
	 * 		return ClientRegistration.withRegistrationId("google")
	 * 			.clientId("google-client-id")
	 * 			.clientSecret("google-client-secret")
	 * 			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	 * 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * 			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
	 * 			.scope("openid", "profile", "email", "address", "phone")
	 * 			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
	 * 			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
	 * 			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
	 * 			.userNameAttributeName(IdTokenClaimNames.SUB)
	 * 			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
	 * 			.clientName("Google")
	 * 			.build();
	 *	}
	 * }
	 * </pre>
	 *
	 * <p>
	 * For more advanced configuration, see {@link OAuth2LoginConfigurer} for available
	 * options to customize the defaults.
	 * @param oauth2LoginCustomizer the {@link Customizer} to provide more options for the
	 * {@link OAuth2LoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code
	 * Grant</a>
	 * @see <a target="_blank" href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1
	 * Authorization Code Flow</a>
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistration
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
	 */
	public HttpSecurity oauth2Login(Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer)
			throws Exception {
		oauth2LoginCustomizer.customize(getOrApply(new OAuth2LoginConfigurer<>()));
		return HttpSecurity.this;
	}

	public OidcLogoutConfigurer<HttpSecurity> oidcLogout() throws Exception {
		return getOrApply(new OidcLogoutConfigurer<>());
	}

	public HttpSecurity oidcLogout(Customizer<OidcLogoutConfigurer<HttpSecurity>> oidcLogoutCustomizer)
			throws Exception {
		oidcLogoutCustomizer.customize(getOrApply(new OidcLogoutConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures OAuth 2.0 Client support.
	 * @return the {@link OAuth2ClientConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.1
	 * @deprecated For removal in 7.0. Use {@link #oauth2Client(Customizer)} or
	 * {@code oauth2Client(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization
	 * Framework</a>
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public OAuth2ClientConfigurer<HttpSecurity> oauth2Client() throws Exception {
		OAuth2ClientConfigurer<HttpSecurity> configurer = getOrApply(new OAuth2ClientConfigurer<>());
		this.postProcess(configurer);
		return configurer;
	}

	/**
	 * Configures OAuth 2.0 Client support.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following example demonstrates how to enable OAuth 2.0 Client support for all
	 * endpoints.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OAuth2ClientSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oauth2Client(withDefaults());
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param oauth2ClientCustomizer the {@link Customizer} to provide more options for
	 * the {@link OAuth2ClientConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization
	 * Framework</a>
	 */
	public HttpSecurity oauth2Client(Customizer<OAuth2ClientConfigurer<HttpSecurity>> oauth2ClientCustomizer)
			throws Exception {
		oauth2ClientCustomizer.customize(getOrApply(new OAuth2ClientConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures OAuth 2.0 Resource Server support.
	 * @return the {@link OAuth2ResourceServerConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.1
	 * @deprecated For removal in 7.0. Use {@link #oauth2ResourceServer(Customizer)}
	 * instead
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization
	 * Framework</a>
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public OAuth2ResourceServerConfigurer<HttpSecurity> oauth2ResourceServer() throws Exception {
		OAuth2ResourceServerConfigurer<HttpSecurity> configurer = getOrApply(
				new OAuth2ResourceServerConfigurer<>(getContext()));
		this.postProcess(configurer);
		return configurer;
	}

	/**
	 * Configures OAuth 2.0 Resource Server support.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The following example demonstrates how to configure a custom JWT authentication
	 * converter.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OAuth2ResourceServerSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oauth2ResourceServer((oauth2ResourceServer) -&gt;
	 * 				oauth2ResourceServer
	 * 					.jwt((jwt) -&gt;
	 * 						jwt
	 * 							.decoder(jwtDecoder())
	 * 					)
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public JwtDecoder jwtDecoder() {
	 * 		return NimbusJwtDecoder.withPublicKey(this.key).build();
	 * 	}
	 * }
	 * </pre>
	 * @param oauth2ResourceServerCustomizer the {@link Customizer} to provide more
	 * options for the {@link OAuth2ResourceServerConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization
	 * Framework</a>
	 */
	public HttpSecurity oauth2ResourceServer(
			Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer) throws Exception {
		OAuth2ResourceServerConfigurer<HttpSecurity> configurer = getOrApply(
				new OAuth2ResourceServerConfigurer<>(getContext()));
		this.postProcess(configurer);
		oauth2ResourceServerCustomizer.customize(configurer);
		return HttpSecurity.this;
	}

	/**
	 * Configures One-Time Token Login Support.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oneTimeTokenLogin(Customizer.withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public OneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler() {
	 * 		return new MyMagicLinkOneTimeTokenGenerationSuccessHandler();
	 * 	}
	 *
	 * }
	 * </pre>
	 * @param oneTimeTokenLoginConfigurerCustomizer the {@link Customizer} to provide more
	 * options for the {@link OneTimeTokenLoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity oneTimeTokenLogin(
			Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> oneTimeTokenLoginConfigurerCustomizer)
			throws Exception {
		oneTimeTokenLoginConfigurerCustomizer.customize(getOrApply(new OneTimeTokenLoginConfigurer<>(getContext())));
		return HttpSecurity.this;
	}

	/**
	 * Configures channel security. In order for this configuration to be useful at least
	 * one mapping to a required channel must be provided.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The example below demonstrates how to require HTTPs for every request. Only
	 * requiring HTTPS for some requests is supported, but not recommended since an
	 * application that allows for HTTP introduces many security vulnerabilities. For one
	 * such example, read about
	 * <a href="https://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ChannelSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.and().requiresChannel().anyRequest().requiresSecure();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link ChannelSecurityConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #requiresChannel(Customizer)} or
	 * {@code requiresChannel(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public ChannelSecurityConfigurer<HttpSecurity>.ChannelRequestMatcherRegistry requiresChannel() throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new ChannelSecurityConfigurer<>(context)).getRegistry();
	}

	/**
	 * Configures channel security. In order for this configuration to be useful at least
	 * one mapping to a required channel must be provided.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The example below demonstrates how to require HTTPs for every request. Only
	 * requiring HTTPS for some requests is supported, but not recommended since an
	 * application that allows for HTTP introduces many security vulnerabilities. For one
	 * such example, read about
	 * <a href="https://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ChannelSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			.requiresChannel((requiresChannel) -&gt;
	 * 				requiresChannel
	 * 					.anyRequest().requiresSecure()
	 * 			);
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param requiresChannelCustomizer the {@link Customizer} to provide more options for
	 * the {@link ChannelSecurityConfigurer.ChannelRequestMatcherRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity requiresChannel(
			Customizer<ChannelSecurityConfigurer<HttpSecurity>.ChannelRequestMatcherRegistry> requiresChannelCustomizer)
			throws Exception {
		ApplicationContext context = getContext();
		requiresChannelCustomizer.customize(getOrApply(new ChannelSecurityConfigurer<>(context)).getRegistry());
		return HttpSecurity.this;
	}

	/**
	 * Configures HTTP Basic authentication.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The example below demonstrates how to configure HTTP Basic authentication for an
	 * application. The default realm is "Realm", but can be customized using
	 * {@link HttpBasicConfigurer#realmName(String)}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class HttpBasicSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().httpBasic();
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link HttpBasicConfigurer} for further customizations
	 * @throws Exception
	 * @deprecated For removal in 7.0. Use {@link #httpBasic(Customizer)} or
	 * {@code httpBasic(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public HttpBasicConfigurer<HttpSecurity> httpBasic() throws Exception {
		return getOrApply(new HttpBasicConfigurer<>());
	}

	/**
	 * Configures HTTP Basic authentication.
	 *
	 * <h2>Example Configuration</h2>
	 *
	 * The example below demonstrates how to configure HTTP Basic authentication for an
	 * application. The default realm is "Realm", but can be customized using
	 * {@link HttpBasicConfigurer#realmName(String)}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class HttpBasicSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param httpBasicCustomizer the {@link Customizer} to provide more options for the
	 * {@link HttpBasicConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity httpBasic(Customizer<HttpBasicConfigurer<HttpSecurity>> httpBasicCustomizer) throws Exception {
		httpBasicCustomizer.customize(getOrApply(new HttpBasicConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Adds support for the password management.
	 *
	 * <h2>Example Configuration</h2> The example below demonstrates how to configure
	 * password management for an application. The default change password page is
	 * "/change-password", but can be customized using
	 * {@link PasswordManagementConfigurer#changePasswordPage(String)}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class PasswordManagementSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests -&gt;
	 * 				authorizeRequests
	 * 					.requestMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.passwordManagement(passwordManagement -&gt;
	 * 				passwordManagement
	 * 					.changePasswordPage(&quot;/custom-change-password-page&quot;)
	 * 			);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 * @param passwordManagementCustomizer the {@link Customizer} to provide more options
	 * for the {@link PasswordManagementConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.6
	 */
	public HttpSecurity passwordManagement(
			Customizer<PasswordManagementConfigurer<HttpSecurity>> passwordManagementCustomizer) throws Exception {
		passwordManagementCustomizer.customize(getOrApply(new PasswordManagementConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configure the default {@link AuthenticationManager}.
	 * @param authenticationManager the {@link AuthenticationManager} to use
	 * @return the {@link HttpSecurity} for further customizations
	 * @since 5.6
	 */
	public HttpSecurity authenticationManager(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		return HttpSecurity.this;
	}

	@Override
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		super.setSharedObject(sharedType, object);
	}

	@Override
	protected void beforeConfigure() throws Exception {
		if (this.authenticationManager != null) {
			setSharedObject(AuthenticationManager.class, this.authenticationManager);
		}
		else {
			ObjectPostProcessor<AuthenticationManager> postProcessor = getAuthenticationManagerPostProcessor();
			AuthenticationManager manager = getAuthenticationRegistry().build();
			if (manager != null) {
				setSharedObject(AuthenticationManager.class, postProcessor.postProcess(manager));
			}
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	protected DefaultSecurityFilterChain performBuild() {
		ExpressionUrlAuthorizationConfigurer<?> expressionConfigurer = getConfigurer(
				ExpressionUrlAuthorizationConfigurer.class);
		AuthorizeHttpRequestsConfigurer<?> httpConfigurer = getConfigurer(AuthorizeHttpRequestsConfigurer.class);
		boolean oneConfigurerPresent = expressionConfigurer == null ^ httpConfigurer == null;
		Assert.state((expressionConfigurer == null && httpConfigurer == null) || oneConfigurerPresent,
				"authorizeHttpRequests cannot be used in conjunction with authorizeRequests. Please select just one.");
		this.filters.sort(OrderComparator.INSTANCE);
		List<Filter> sortedFilters = new ArrayList<>(this.filters.size());
		for (Filter filter : this.filters) {
			sortedFilters.add(((OrderedFilter) filter).filter);
		}
		return new DefaultSecurityFilterChain(this.requestMatcher, sortedFilters);
	}

	@Override
	public HttpSecurity authenticationProvider(AuthenticationProvider authenticationProvider) {
		getAuthenticationRegistry().authenticationProvider(authenticationProvider);
		return this;
	}

	@Override
	public HttpSecurity userDetailsService(UserDetailsService userDetailsService) throws Exception {
		getAuthenticationRegistry().userDetailsService(userDetailsService);
		return this;
	}

	private AuthenticationManagerBuilder getAuthenticationRegistry() {
		return getSharedObject(AuthenticationManagerBuilder.class);
	}

	@Override
	public HttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
		return addFilterAtOffsetOf(filter, 1, afterFilter);
	}

	@Override
	public HttpSecurity addFilterBefore(Filter filter, Class<? extends Filter> beforeFilter) {
		return addFilterAtOffsetOf(filter, -1, beforeFilter);
	}

	private HttpSecurity addFilterAtOffsetOf(Filter filter, int offset, Class<? extends Filter> registeredFilter) {
		Integer registeredFilterOrder = this.filterOrders.getOrder(registeredFilter);
		if (registeredFilterOrder == null) {
			throw new IllegalArgumentException(
					"The Filter class " + registeredFilter.getName() + " does not have a registered order");
		}
		int order = registeredFilterOrder + offset;
		this.filters.add(new OrderedFilter(filter, order));
		this.filterOrders.put(filter.getClass(), order);
		return this;
	}

	@Override
	public HttpSecurity addFilter(Filter filter) {
		Integer order = this.filterOrders.getOrder(filter.getClass());
		if (order == null) {
			throw new IllegalArgumentException("The Filter class " + filter.getClass().getName()
					+ " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
		}
		this.filters.add(new OrderedFilter(filter, order));
		return this;
	}

	/**
	 * Adds the Filter at the location of the specified Filter class. For example, if you
	 * want the filter CustomFilter to be registered in the same position as
	 * {@link UsernamePasswordAuthenticationFilter}, you can invoke:
	 *
	 * <pre>
	 * addFilterAt(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
	 * </pre>
	 *
	 * Registration of multiple Filters in the same location means their ordering is not
	 * deterministic. More concretely, registering multiple Filters in the same location
	 * does not override existing Filters. Instead, do not register Filters you do not
	 * want to use.
	 * @param filter the Filter to register
	 * @param atFilter the location of another {@link Filter} that is already registered
	 * (i.e. known) with Spring Security.
	 * @return the {@link HttpSecurity} for further customizations
	 */
	public HttpSecurity addFilterAt(Filter filter, Class<? extends Filter> atFilter) {
		return addFilterAtOffsetOf(filter, 0, atFilter);
	}

	/**
	 * Allows specifying which {@link HttpServletRequest} instances this
	 * {@link HttpSecurity} will be invoked on. This method allows for easily invoking the
	 * {@link HttpSecurity} for multiple different {@link RequestMatcher} instances. If
	 * only a single {@link RequestMatcher} is necessary consider using
	 * {@link #securityMatcher(String...)}, or {@link #securityMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #securityMatchers()} will not override previous invocations of
	 * {@link #securityMatchers()}}, {@link #securityMatchers(Customizer)}
	 * {@link #securityMatcher(String...)} and {@link #securityMatcher(RequestMatcher)}
	 * </p>
	 *
	 * <h3>Example Configurations</h3>
	 *
	 * The following configuration enables the {@link HttpSecurity} for URLs that begin
	 * with "/api/" or "/oauth/".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityMatchers((matchers) -&gt; matchers
	 * 				.requestMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is the same as the previous configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityMatchers((matchers) -&gt; matchers
	 * 				.requestMatchers(&quot;/api/**&quot;)
	 * 				.requestMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is also the same as the above configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityMatchers((matchers) -&gt; matchers
	 * 				.requestMatchers(&quot;/api/**&quot;)
	 * 			)
	 *			.securityMatchers((matchers) -&gt; matchers
	 *				.requestMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link RequestMatcherConfigurer} for further customizations
	 * @deprecated For removal in 7.0. Use {@link #securityMatchers(Customizer)} or
	 * {@code securityMatchers(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public RequestMatcherConfigurer securityMatchers() {
		return this.requestMatcherConfigurer;
	}

	/**
	 * Allows specifying which {@link HttpServletRequest} instances this
	 * {@link HttpSecurity} will be invoked on. This method allows for easily invoking the
	 * {@link HttpSecurity} for multiple different {@link RequestMatcher} instances. If
	 * only a single {@link RequestMatcher} is necessary consider using
	 * {@link #securityMatcher(String...)}, or {@link #securityMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #securityMatchers(Customizer)} will not override previous
	 * invocations of {@link #securityMatchers()}}, {@link #securityMatchers(Customizer)}
	 * {@link #securityMatcher(String...)} and {@link #securityMatcher(RequestMatcher)}
	 * </p>
	 *
	 * <h3>Example Configurations</h3>
	 *
	 * The following configuration enables the {@link HttpSecurity} for URLs that begin
	 * with "/api/" or "/oauth/".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityMatchers((matchers) -&gt; matchers
	 * 				.requestMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				.anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is the same as the previous configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityMatchers((matchers) -&gt; matchers
	 * 				.requestMatchers(&quot;/api/**&quot;)
	 * 				.requestMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				.anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is also the same as the above configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityMatchers((matchers) -&gt; matchers
	 * 				.requestMatchers(&quot;/api/**&quot;)
	 * 			)
	 *			.securityMatchers((matchers) -&gt; matchers
	 *				.requestMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				.anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 		return http.build();
	 * 	}
	 *
	 * 	&#064;Bean
	 * 	public UserDetailsService userDetailsService() {
	 * 		UserDetails user = User.withDefaultPasswordEncoder()
	 * 			.username(&quot;user&quot;)
	 * 			.password(&quot;password&quot;)
	 * 			.roles(&quot;USER&quot;)
	 * 			.build();
	 * 		return new InMemoryUserDetailsManager(user);
	 * 	}
	 * }
	 * </pre>
	 * @param requestMatcherCustomizer the {@link Customizer} to provide more options for
	 * the {@link RequestMatcherConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 */
	public HttpSecurity securityMatchers(Customizer<RequestMatcherConfigurer> requestMatcherCustomizer) {
		requestMatcherCustomizer.customize(this.requestMatcherConfigurer);
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided {@link RequestMatcher}. If more advanced configuration is necessary,
	 * consider using {@link #securityMatchers(Customizer)} ()}.
	 *
	 * <p>
	 * Invoking {@link #securityMatcher(RequestMatcher)} will override previous
	 * invocations of {@link #securityMatcher(RequestMatcher)},
	 * {@link #securityMatcher(String...)}, {@link #securityMatchers(Customizer)} and
	 * {@link #securityMatchers()}
	 * </p>
	 * @param requestMatcher the {@link RequestMatcher} to use (i.e. new
	 * AntPathRequestMatcher("/admin/**","GET") )
	 * @return the {@link HttpSecurity} for further customizations
	 * @see #securityMatcher(String...)
	 */
	public HttpSecurity securityMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
		return this;
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided pattern. This method creates a {@link MvcRequestMatcher} if Spring MVC is
	 * in the classpath or creates an {@link AntPathRequestMatcher} if not. If more
	 * advanced configuration is necessary, consider using
	 * {@link #securityMatchers(Customizer)} or {@link #securityMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #securityMatcher(String...)} will override previous invocations of
	 * {@link #securityMatcher(String...)} (String)}},
	 * {@link #securityMatcher(RequestMatcher)} ()}, {@link #securityMatchers(Customizer)}
	 * (String)} and {@link #securityMatchers()} (String)}.
	 * </p>
	 * @param patterns the pattern to match on (i.e. "/admin/**")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see AntPathRequestMatcher
	 * @see MvcRequestMatcher
	 */
	public HttpSecurity securityMatcher(String... patterns) {
		if (mvcPresent) {
			this.requestMatcher = new OrRequestMatcher(createMvcMatchers(patterns));
			return this;
		}
		this.requestMatcher = new OrRequestMatcher(createAntMatchers(patterns));
		return this;
	}

	/**
	 * Specifies webAuthn/passkeys based authentication.
	 *
	 * <pre>
	 * 	&#064;Bean
	 * 	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 			// ...
	 * 			.webAuthn((webAuthn) -&gt; webAuthn
	 * 				.rpName("Spring Security Relying Party")
	 * 				.rpId("example.com")
	 * 				.allowedOrigins("https://example.com")
	 * 			);
	 * 		return http.build();
	 * 	}
	 * </pre>
	 * @param webAuthn the customizer to apply
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity webAuthn(Customizer<WebAuthnConfigurer<HttpSecurity>> webAuthn) throws Exception {
		webAuthn.customize(getOrApply(new WebAuthnConfigurer<>()));
		return HttpSecurity.this;
	}

	private List<RequestMatcher> createAntMatchers(String... patterns) {
		List<RequestMatcher> matchers = new ArrayList<>(patterns.length);
		for (String pattern : patterns) {
			matchers.add(new AntPathRequestMatcher(pattern));
		}
		return matchers;
	}

	private List<RequestMatcher> createMvcMatchers(String... mvcPatterns) {
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class, Object.class);
		ObjectProvider<ObjectPostProcessor<Object>> postProcessors = getContext().getBeanProvider(type);
		ObjectPostProcessor<Object> opp = postProcessors.getObject();
		if (!getContext().containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
			throw new NoSuchBeanDefinitionException("A Bean named " + HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME
					+ " of type " + HandlerMappingIntrospector.class.getName()
					+ " is required to use MvcRequestMatcher. Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext.");
		}
		HandlerMappingIntrospector introspector = getContext().getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME,
				HandlerMappingIntrospector.class);
		List<RequestMatcher> matchers = new ArrayList<>(mvcPatterns.length);
		for (String mvcPattern : mvcPatterns) {
			MvcRequestMatcher matcher = new MvcRequestMatcher(introspector, mvcPattern);
			opp.postProcess(matcher);
			matchers.add(matcher);
		}
		return matchers;
	}

	/**
	 * If the {@link SecurityConfigurer} has already been specified get the original,
	 * otherwise apply the new {@link SecurityConfigurerAdapter}.
	 * @param configurer the {@link SecurityConfigurer} to apply if one is not found for
	 * this {@link SecurityConfigurer} class.
	 * @return the current {@link SecurityConfigurer} for the configurer passed in
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(C configurer)
			throws Exception {
		C existingConfig = (C) getConfigurer(configurer.getClass());
		if (existingConfig != null) {
			return existingConfig;
		}
		return apply(configurer);
	}

	private ObjectPostProcessor<AuthenticationManager> getAuthenticationManagerPostProcessor() {
		ApplicationContext context = getContext();
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class,
				AuthenticationManager.class);
		ObjectProvider<ObjectPostProcessor<AuthenticationManager>> manager = context.getBeanProvider(type);
		return manager.getIfUnique(ObjectPostProcessor::identity);
	}

	/**
	 * Allows mapping HTTP requests that this {@link HttpSecurity} will be used for
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public class RequestMatcherConfigurer extends AbstractRequestMatcherRegistry<RequestMatcherConfigurer> {

		protected List<RequestMatcher> matchers = new ArrayList<>();

		RequestMatcherConfigurer(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		protected RequestMatcherConfigurer chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			setMatchers(requestMatchers);
			return this;
		}

		private void setMatchers(List<? extends RequestMatcher> requestMatchers) {
			this.matchers.addAll(requestMatchers);
			securityMatcher(new OrRequestMatcher(this.matchers));
		}

		/**
		 * Return the {@link HttpSecurity} for further customizations
		 * @return the {@link HttpSecurity} for further customizations
		 * @deprecated Use the lambda based configuration instead. For example: <pre>
		 * &#064;Configuration
		 * &#064;EnableWebSecurity
		 * public class SecurityConfig {
		 *
		 *     &#064;Bean
		 *     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		 *         http
		 *             .securityMatchers((matchers) -&gt; matchers
		 *                 .requestMatchers(&quot;/api/**&quot;)
		 *             )
		 *             .authorizeHttpRequests((authorize) -&gt; authorize
		 *                 .anyRequest().hasRole(&quot;USER&quot;)
		 *             )
		 *             .httpBasic(Customizer.withDefaults());
		 *         return http.build();
		 *     }
		 *
		 * }
		 * </pre>
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public HttpSecurity and() {
			return HttpSecurity.this;
		}

	}

	/**
	 * A Filter that implements Ordered to be sorted. After sorting occurs, the original
	 * filter is what is used by FilterChainProxy
	 */
	private static final class OrderedFilter implements Ordered, Filter {

		private final Filter filter;

		private final int order;

		private OrderedFilter(Filter filter, int order) {
			this.filter = filter;
			this.order = order;
		}

		@Override
		public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
				throws IOException, ServletException {
			this.filter.doFilter(servletRequest, servletResponse, filterChain);
		}

		@Override
		public int getOrder() {
			return this.order;
		}

		@Override
		public String toString() {
			return "OrderedFilter{" + "filter=" + this.filter + ", order=" + this.order + '}';
		}

	}

}
