/*
 * Copyright 2002-2021 the original author or authors.
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LoginConfigurer;
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
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
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
 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 * 	protected void configure(HttpSecurity http) throws Exception {
 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
 * 	}
 *
 * 	&#064;Override
 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
 * 	}
 * }
 * </pre>
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @since 3.2
 * @see EnableWebSecurity
 */
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
		implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {

	private final RequestMatcherConfigurer requestMatcherConfigurer;

	private List<OrderedFilter> filters = new ArrayList<>();

	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

	private FilterOrderRegistration filterOrders = new FilterOrderRegistration();
	
	private Map<Class<? extends Filter>, Class<? extends Filter>> filtersRegistredBefore = new HashMap<>();
	
	private Map<Class<? extends Filter>, Class<? extends Filter>> filtersRegistredAfter = new HashMap<>();

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

	private ApplicationContext getContext() {
		return getSharedObject(ApplicationContext.class);
	}

	/**
	 * Allows configuring OpenID based authentication.
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * A basic example accepting the defaults and not using attribute exchange:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().openidLogin()
	 * 				.permitAll();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication()
	 * 				// the username must match the OpenID of the user you are
	 * 				// logging in with
	 * 				.withUser(
	 * 						&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
	 * 				.password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 *
	 * A more advanced example demonstrating using attribute exchange and providing a
	 * custom AuthenticationUserDetailsService that will make any user that authenticates
	 * a valid user.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) {
	 * 		http.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;)
	 * 				.hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 				.openidLogin()
	 * 				.loginPage(&quot;/login&quot;)
	 * 				.permitAll()
	 * 				.authenticationUserDetailsService(
	 * 						new AutoProvisioningUserDetailsService())
	 * 				.attributeExchange(&quot;https://www.google.com/.*&quot;).attribute(&quot;email&quot;)
	 * 				.type(&quot;https://axschema.org/contact/email&quot;).required(true).and()
	 * 				.attribute(&quot;firstname&quot;).type(&quot;https://axschema.org/namePerson/first&quot;)
	 * 				.required(true).and().attribute(&quot;lastname&quot;)
	 * 				.type(&quot;https://axschema.org/namePerson/last&quot;).required(true).and().and()
	 * 				.attributeExchange(&quot;.*yahoo.com.*&quot;).attribute(&quot;email&quot;)
	 * 				.type(&quot;https://schema.openid.net/contact/email&quot;).required(true).and()
	 * 				.attribute(&quot;fullname&quot;).type(&quot;https://axschema.org/namePerson&quot;)
	 * 				.required(true).and().and().attributeExchange(&quot;.*myopenid.com.*&quot;)
	 * 				.attribute(&quot;email&quot;).type(&quot;https://schema.openid.net/contact/email&quot;)
	 * 				.required(true).and().attribute(&quot;fullname&quot;)
	 * 				.type(&quot;https://schema.openid.net/namePerson&quot;).required(true);
	 * 	}
	 * }
	 *
	 * public class AutoProvisioningUserDetailsService implements
	 * 		AuthenticationUserDetailsService&lt;OpenIDAuthenticationToken&gt; {
	 * 	public UserDetails loadUserDetails(OpenIDAuthenticationToken token)
	 * 			throws UsernameNotFoundException {
	 * 		return new User(token.getName(), &quot;NOTUSED&quot;,
	 * 				AuthorityUtils.createAuthorityList(&quot;ROLE_USER&quot;));
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link OpenIDLoginConfigurer} for further customizations.
	 * @throws Exception
	 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
	 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to
	 * migrate</a> to <a href="https://openid.net/connect/">OpenID Connect</a>, which is
	 * supported by <code>spring-security-oauth2</code>.
	 * @see OpenIDLoginConfigurer
	 */
	@Deprecated
	public OpenIDLoginConfigurer<HttpSecurity> openidLogin() throws Exception {
		return getOrApply(new OpenIDLoginConfigurer<>());
	}

	/**
	 * Allows configuring OpenID based authentication.
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * A basic example accepting the defaults and not using attribute exchange:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.openidLogin((openidLogin) -&gt;
	 * 				openidLogin
	 * 					.permitAll()
	 * 			);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication()
	 * 				// the username must match the OpenID of the user you are
	 * 				// logging in with
	 * 				.withUser(
	 * 						&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
	 * 				.password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 *
	 * A more advanced example demonstrating using attribute exchange and providing a
	 * custom AuthenticationUserDetailsService that will make any user that authenticates
	 * a valid user.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.openidLogin((openidLogin) -&gt;
	 * 				openidLogin
	 * 					.loginPage(&quot;/login&quot;)
	 * 					.permitAll()
	 * 					.authenticationUserDetailsService(
	 * 						new AutoProvisioningUserDetailsService())
	 * 					.attributeExchange((googleExchange) -&gt;
	 * 						googleExchange
	 * 							.identifierPattern(&quot;https://www.google.com/.*&quot;)
	 * 							.attribute((emailAttribute) -&gt;
	 * 								emailAttribute
	 * 									.name(&quot;email&quot;)
	 * 									.type(&quot;https://axschema.org/contact/email&quot;)
	 * 									.required(true)
	 * 							)
	 * 							.attribute((firstnameAttribute) -&gt;
	 * 								firstnameAttribute
	 * 									.name(&quot;firstname&quot;)
	 * 									.type(&quot;https://axschema.org/namePerson/first&quot;)
	 * 									.required(true)
	 * 							)
	 * 							.attribute((lastnameAttribute) -&gt;
	 * 								lastnameAttribute
	 * 									.name(&quot;lastname&quot;)
	 * 									.type(&quot;https://axschema.org/namePerson/last&quot;)
	 * 									.required(true)
	 * 							)
	 * 					)
	 * 					.attributeExchange((yahooExchange) -&gt;
	 * 						yahooExchange
	 * 							.identifierPattern(&quot;.*yahoo.com.*&quot;)
	 * 							.attribute((emailAttribute) -&gt;
	 * 								emailAttribute
	 * 									.name(&quot;email&quot;)
	 * 									.type(&quot;https://schema.openid.net/contact/email&quot;)
	 * 									.required(true)
	 * 							)
	 * 							.attribute((fullnameAttribute) -&gt;
	 * 								fullnameAttribute
	 * 									.name(&quot;fullname&quot;)
	 * 									.type(&quot;https://axschema.org/namePerson&quot;)
	 * 									.required(true)
	 * 							)
	 * 					)
	 * 			);
	 * 	}
	 * }
	 *
	 * public class AutoProvisioningUserDetailsService implements
	 * 		AuthenticationUserDetailsService&lt;OpenIDAuthenticationToken&gt; {
	 * 	public UserDetails loadUserDetails(OpenIDAuthenticationToken token)
	 * 			throws UsernameNotFoundException {
	 * 		return new User(token.getName(), &quot;NOTUSED&quot;,
	 * 				AuthorityUtils.createAuthorityList(&quot;ROLE_USER&quot;));
	 * 	}
	 * }
	 * </pre>
	 * @param openidLoginCustomizer the {@link Customizer} to provide more options for the
	 * {@link OpenIDLoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
	 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to
	 * migrate</a> to <a href="https://openid.net/connect/">OpenID Connect</a>, which is
	 * supported by <code>spring-security-oauth2</code>.
	 * @see OpenIDLoginConfigurer
	 */
	@Deprecated
	public HttpSecurity openidLogin(Customizer<OpenIDLoginConfigurer<HttpSecurity>> openidLoginCustomizer)
			throws Exception {
		openidLoginCustomizer.customize(getOrApply(new OpenIDLoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Adds the Security headers to the response. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor. Accepting the default
	 * provided by {@link WebSecurityConfigurerAdapter} or only invoking
	 * {@link #headers()} without invoking additional methods on it, is the equivalent of:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers()
	 *                 .contentTypeOptions()
	 *                 .and()
	 *                 .xssProtection()
	 *                 .and()
	 *                 .cacheControl()
	 *                 .and()
	 *                 .httpStrictTransportSecurity()
	 *                 .and()
	 *                 .frameOptions()
	 *                 .and()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 *
	 * You can disable the headers using the following:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers().disable()
	 *             ...;
	 *     }
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
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers()
	 *                  .defaultsDisabled()
	 *                  .cacheControl()
	 *                  .and()
	 *                  .frameOptions()
	 *                  .and()
	 *             ...;
	 *     }
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
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers()
	 *                  .frameOptions()
	 *                  	.disable()
	 *                  .and()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 * @return the {@link HeadersConfigurer} for further customizations
	 * @throws Exception
	 * @see HeadersConfigurer
	 */
	public HeadersConfigurer<HttpSecurity> headers() throws Exception {
		return getOrApply(new HeadersConfigurer<>());
	}

	/**
	 * Adds the Security headers to the response. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor.
	 *
	 * <h2>Example Configurations</h2>
	 *
	 * Accepting the default provided by {@link WebSecurityConfigurerAdapter} or only
	 * invoking {@link #headers()} without invoking additional methods on it, is the
	 * equivalent of:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 *	&#064;Override
	 *	protected void configure(HttpSecurity http) throws Exception {
	 *		http
	 *			.headers((headers) -&gt;
	 *				headers
	 *					.contentTypeOptions(withDefaults())
	 *					.xssProtection(withDefaults())
	 *					.cacheControl(withDefaults())
	 *					.httpStrictTransportSecurity(withDefaults())
	 *					.frameOptions(withDefaults()
	 *			);
	 *	}
	 * }
	 * </pre>
	 *
	 * You can disable the headers using the following:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 *	&#064;Override
	 *	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers((headers) -&gt; headers.disable());
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
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 *	&#064;Override
	 *	protected void configure(HttpSecurity http) throws Exception {
	 *		http
	 *			.headers((headers) -&gt;
	 *				headers
	 *			 		.defaultsDisabled()
	 *			 		.cacheControl(withDefaults())
	 *			 		.frameOptions(withDefaults())
	 *			);
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
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *  protected void configure(HttpSecurity http) throws Exception {
	 *  	http
	 *  		.headers((headers) -&gt;
	 *  			headers
	 *  				.frameOptions((frameOptions) -&gt; frameOptions.disable())
	 *  		);
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
	 */
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
	 * public class CorsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .cors(withDefaults());
	 *     }
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
	 * public class SessionManagementSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().anyRequest().hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and().sessionManagement().maximumSessions(1)
	 * 				.expiredUrl(&quot;/login?expired&quot;);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
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
	 */
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
	 * public class SessionManagementSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
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
	 * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and()
	 * 				// Example portMapper() configuration
	 * 				.portMapper().http(9090).mapsTo(9443).http(80).mapsTo(443);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link PortMapperConfigurer} for further customizations
	 * @throws Exception
	 * @see #requiresChannel()
	 */
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
	 * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
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
	 * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
	 * 		// Example jee() configuration
	 * 				.jee().mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;);
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
	 */
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
	 * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.jee((jee) -&gt;
	 * 				jee
	 * 					.mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;)
	 * 			);
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
	 * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
	 * 		// Example x509() configuration
	 * 				.x509();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link X509Configurer} for further customizations
	 * @throws Exception
	 */
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
	 * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.x509(withDefaults());
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
	 * {@link javax.servlet.http.HttpSession} expires.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and()
	 * 				// Example Remember Me Configuration
	 * 				.rememberMe();
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link RememberMeConfigurer} for further customizations
	 * @throws Exception
	 */
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
	 * {@link javax.servlet.http.HttpSession} expires.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			.rememberMe(withDefaults());
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
	 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;ADMIN&quot;, &quot;USER&quot;);
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
	 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;ADMIN&quot;, &quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 *
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).antMatchers(&quot;/admin/**&quot;)
	 * 		.hasRole(&quot;ADMIN&quot;)
	 * </pre>
	 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
	 * @throws Exception
	 * @see #requestMatcher(RequestMatcher)
	 */
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		 http
	 * 		 	.authorizeRequests((authorizeRequests) -&gt;
	 * 		 		authorizeRequests
	 * 			 		.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			 		.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 		 	);
	 * 	}
	 * }
	 * </pre>
	 * @param authorizeRequestsCustomizer the {@link Customizer} to provide more options
	 * for the {@link ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see #requestMatcher(RequestMatcher)
	 */
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests((authorizeHttpRequests) -&gt;
	 * 				authorizeHttpRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeHttpRequests((authorizeHttpRequests) -&gt;
	 * 				authorizeHttpRequests
	 * 					.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
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
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 		 	.authorizeHttpRequests((authorizeHttpRequests) -&gt;
	 * 		 		authorizeHttpRequests
	 * 			 		.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			 		.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 		 	);
	 * 	}
	 * }
	 * </pre>
	 * @param authorizeHttpRequestsCustomizer the {@link Customizer} to provide more
	 * options for the {@link AuthorizationManagerRequestMatcherRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.5
	 * @see #requestMatcher(RequestMatcher)
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
	 * when using {@link WebSecurityConfigurerAdapter}.
	 * @return the {@link RequestCacheConfigurer} for further customizations
	 * @throws Exception
	 */
	public RequestCacheConfigurer<HttpSecurity> requestCache() throws Exception {
		return getOrApply(new RequestCacheConfigurer<>());
	}

	/**
	 * Allows configuring the Request Cache. For example, a protected page (/protected)
	 * may be requested prior to authentication. The application will redirect the user to
	 * a login page. After authentication, Spring Security will redirect the user to the
	 * originally requested protected page (/protected). This is automatically applied
	 * when using {@link WebSecurityConfigurerAdapter}.
	 *
	 * <h2>Example Custom Configuration</h2>
	 *
	 * The following example demonstrates how to disable request caching.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestCacheDisabledSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.requestCache((requestCache) -&gt;
	 * 				requestCache.disable()
	 * 			);
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
	 * {@link WebSecurityConfigurerAdapter}.
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 * @throws Exception
	 */
	public ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling() throws Exception {
		return getOrApply(new ExceptionHandlingConfigurer<>());
	}

	/**
	 * Allows configuring exception handling. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}.
	 *
	 * <h2>Example Custom Configuration</h2>
	 *
	 * The following customization will ensure that users who are denied access are
	 * forwarded to the page "/errors/access-denied".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ExceptionHandlingSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			// sample exception handling customization
	 * 			.exceptionHandling((exceptionHandling) -&gt;
	 * 				exceptionHandling
	 * 					.accessDeniedPage(&quot;/errors/access-denied&quot;)
	 * 			);
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
	 * automatically applied when using {@link WebSecurityConfigurerAdapter}.
	 * @return the {@link SecurityContextConfigurer} for further customizations
	 * @throws Exception
	 */
	public SecurityContextConfigurer<HttpSecurity> securityContext() throws Exception {
		return getOrApply(new SecurityContextConfigurer<>());
	}

	/**
	 * Sets up management of the {@link SecurityContext} on the
	 * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
	 * automatically applied when using {@link WebSecurityConfigurerAdapter}.
	 *
	 * The following customization specifies the shared {@link SecurityContextRepository}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SecurityContextSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityContext((securityContext) -&gt;
	 * 				securityContext
	 * 					.securityContextRepository(SCR)
	 * 			);
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
	 * {@link WebSecurityConfigurerAdapter}.
	 * @return the {@link ServletApiConfigurer} for further customizations
	 * @throws Exception
	 */
	public ServletApiConfigurer<HttpSecurity> servletApi() throws Exception {
		return getOrApply(new ServletApiConfigurer<>());
	}

	/**
	 * Integrates the {@link HttpServletRequest} methods with the values found on the
	 * {@link SecurityContext}. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}. You can disable it using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ServletApiSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.servletApi((servletApi) -&gt;
	 * 				servletApi.disable()
	 * 			);
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
	 * {@link WebSecurityConfigurerAdapter}'s default constructor. You can disable it
	 * using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .csrf().disable()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @throws Exception
	 */
	public CsrfConfigurer<HttpSecurity> csrf() throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new CsrfConfigurer<>(context));
	}

	/**
	 * Enables CSRF protection. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor. You can disable it
	 * using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .csrf((csrf) -&gt; csrf.disable());
	 *     }
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
	 * {@link WebSecurityConfigurerAdapter}. The default is that accessing the URL
	 * "/logout" will log the user out by invalidating the HTTP Session, cleaning up any
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
	 * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.and()
	 * 				// sample logout customization
	 * 				.logout().deleteCookies(&quot;remove&quot;).invalidateHttpSession(false)
	 * 				.logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link LogoutConfigurer} for further customizations
	 * @throws Exception
	 */
	public LogoutConfigurer<HttpSecurity> logout() throws Exception {
		return getOrApply(new LogoutConfigurer<>());
	}

	/**
	 * Provides logout support. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}. The default is that accessing the URL
	 * "/logout" will log the user out by invalidating the HTTP Session, cleaning up any
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
	 * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample logout customization
	 * 			.logout((logout) -&gt;
	 * 				logout.deleteCookies(&quot;remove&quot;)
	 * 					.invalidateHttpSession(false)
	 * 					.logoutUrl(&quot;/custom-logout&quot;)
	 * 					.logoutSuccessUrl(&quot;/logout-success&quot;)
	 * 			);
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
	 * applied when used in conjunction with {@link WebSecurityConfigurerAdapter}. By
	 * default anonymous users will be represented with an
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
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin()
	 * 				.and()
	 * 			// sample anonymous customization
	 * 			.anonymous().authorities(&quot;ROLE_ANON&quot;);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
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
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin()
	 * 				.and()
	 * 			// sample anonymous customization
	 * 			.anonymous().disable();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link AnonymousConfigurer} for further customizations
	 * @throws Exception
	 */
	public AnonymousConfigurer<HttpSecurity> anonymous() throws Exception {
		return getOrApply(new AnonymousConfigurer<>());
	}

	/**
	 * Allows configuring how an anonymous user is represented. This is automatically
	 * applied when used in conjunction with {@link WebSecurityConfigurerAdapter}. By
	 * default anonymous users will be represented with an
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
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample anonymous customization
	 * 			.anonymous((anonymous) -&gt;
	 * 				anonymous
	 * 					.authorities(&quot;ROLE_ANON&quot;)
	 * 			)
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
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample anonymous customization
	 * 			.anonymous((anonymous) -&gt;
	 * 				anonymous.disable()
	 * 			);
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
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
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below demonstrates customizing the defaults.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.usernameParameter(&quot;username&quot;) // default is username
	 * 				.passwordParameter(&quot;password&quot;) // default is password
	 * 				.loginPage(&quot;/authentication/login&quot;) // default is /login with an HTTP get
	 * 				.failureUrl(&quot;/authentication/login?failed&quot;) // default is /login?error
	 * 				.loginProcessingUrl(&quot;/authentication/login/process&quot;); // default is /login
	 * 																		// with an HTTP
	 * 																		// post
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link FormLoginConfigurer} for further customizations
	 * @throws Exception
	 * @see FormLoginConfigurer#loginPage(String)
	 */
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
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below demonstrates customizing the defaults.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin((formLogin) -&gt;
	 * 				formLogin
	 * 					.usernameParameter(&quot;username&quot;)
	 * 					.passwordParameter(&quot;password&quot;)
	 * 					.loginPage(&quot;/authentication/login&quot;)
	 * 					.failureUrl(&quot;/authentication/login?failed&quot;)
	 * 					.loginProcessingUrl(&quot;/authentication/login/process&quot;)
	 * 			);
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
	 * public class Saml2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests()
	 * 					.anyRequest().authenticated()
	 * 					.and()
	 * 				  .saml2Login();
	 *		}
	 *	}
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
	 *  * 				.remoteIdpEntityId(idpEntityId)
	 *  * 				.idpWebSsoUrl(webSsoEndpoint)
	 *  * 				.credential(signingCredential)
	 *  * 				.credential(idpVerificationCertificate)
	 *  * 				.localEntityIdTemplate(localEntityIdTemplate)
	 *  * 				.build();
	 *	}
	 * }
	 * </pre>
	 *
	 * <p>
	 * @return the {@link Saml2LoginConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.2
	 */
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
	 * public class Saml2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests()
	 * 					.anyRequest().authenticated()
	 * 					.and()
	 * 				  .saml2Login(withDefaults());
	 *		}
	 *	}
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
	 *  * 				.remoteIdpEntityId(idpEntityId)
	 *  * 				.idpWebSsoUrl(webSsoEndpoint)
	 *  * 				.credential(signingCredential)
	 *  * 				.credential(idpVerificationCertificate)
	 *  * 				.localEntityIdTemplate(localEntityIdTemplate)
	 *  * 				.build();
	 *	}
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
	 * public class OAuth2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests()
	 * 					.anyRequest().authenticated()
	 * 					.and()
	 * 				  .oauth2Login();
	 *		}
	 *	}
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
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code
	 * Grant</a>
	 * @see <a target="_blank" href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1
	 * Authorization Code Flow</a>
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistration
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
	 */
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
	 * public class OAuth2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests((authorizeRequests) -&gt;
	 * 					authorizeRequests
	 * 						.anyRequest().authenticated()
	 * 				)
	 * 				.oauth2Login(withDefaults());
	 *		}
	 *	}
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

	/**
	 * Configures OAuth 2.0 Client support.
	 * @return the {@link OAuth2ClientConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.1
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization
	 * Framework</a>
	 */
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
	 * public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oauth2Client(withDefaults());
	 *	}
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
	 * @see <a target="_blank" href=
	 * "https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization
	 * Framework</a>
	 */
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
	 * public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * &#064;Value("${spring.security.oauth2.resourceserver.jwt.key-value}")
	 * RSAPublicKey key;
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
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
	 *	}
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
	 * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.and().requiresChannel().anyRequest().requiresSecure();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link ChannelSecurityConfigurer} for further customizations
	 * @throws Exception
	 */
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
	 * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			.requiresChannel((requiresChannel) -&gt;
	 * 				requiresChannel
	 * 					.anyRequest().requiresSecure()
	 * 			);
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
	 * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().httpBasic();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link HttpBasicConfigurer} for further customizations
	 * @throws Exception
	 */
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
	 * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
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

	@Override
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		super.setSharedObject(sharedType, object);
	}

	@Override
	protected void beforeConfigure() throws Exception {
		setSharedObject(AuthenticationManager.class, getAuthenticationRegistry().build());
	}

	@Override
	protected DefaultSecurityFilterChain performBuild() {
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
		if(this.filterOrders.getOrder(afterFilter) != null) {
			this.filtersRegistredAfter.put(filter.getClass(), afterFilter);
			return addFilterAtOffsetOf(filter, 1, afterFilter);
			
		} else if (this.filtersRegistredAfter.containsKey(afterFilter)) {
			final Class<? extends Filter> registeredFilter = this.filtersRegistredAfter.get(afterFilter);
			this.filtersRegistredAfter.put(filter.getClass(), registeredFilter);
			return addFilterAtOffsetOf(filter, 1, registeredFilter);
			
		} else if (this.filtersRegistredBefore.containsKey(afterFilter)) {
			final Class<? extends Filter> registeredFilter = this.filtersRegistredBefore.get(afterFilter);
			this.filtersRegistredBefore.put(filter.getClass(), registeredFilter);
			return addFilterAtOffsetOf(filter, -1, registeredFilter);
		}
		
		throw new IllegalArgumentException(afterFilter.getClass().getName()
				+ " is not registered in filter chain. Consider adding your filter after a registered filter.");
	}

	@Override
	public HttpSecurity addFilterBefore(Filter filter, Class<? extends Filter> beforeFilter) {
		if(this.filterOrders.getOrder(beforeFilter) != null) {
			this.filtersRegistredBefore.put(filter.getClass(), beforeFilter);
			return addFilterAtOffsetOf(filter, -1, beforeFilter);
			
		} else if (this.filtersRegistredAfter.containsKey(beforeFilter)) {
			final Class<? extends Filter> registeredFilter = this.filtersRegistredAfter.get(beforeFilter);
			this.filtersRegistredAfter.put(filter.getClass(), registeredFilter);
			return addFilterAtOffsetOf(filter, -1, registeredFilter);
			
		} else if (this.filtersRegistredBefore.containsKey(beforeFilter)) {
			final Class<? extends Filter> registeredFilter = this.filtersRegistredBefore.get(beforeFilter);
			this.filtersRegistredBefore.put(filter.getClass(), registeredFilter);
			return addFilterAtOffsetOf(filter, -2, registeredFilter);
		}
		
		throw new IllegalArgumentException(beforeFilter.getClass().getName()
				+ " is not registered in filter chain. Consider adding your filter before a registered filter.");
	}

	private HttpSecurity addFilterAtOffsetOf(Filter filter, int offset, Class<? extends Filter> registeredFilter) {
		int order = this.filterOrders.getOrder(registeredFilter) + offset;
		this.filters.add(new OrderedFilter(filter, order));
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
	 * {@link #mvcMatcher(String)}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #requestMatchers()} will not override previous invocations of
	 * {@link #mvcMatcher(String)}}, {@link #requestMatchers()},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, and
	 * {@link #requestMatcher(RequestMatcher)}.
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
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers()
	 * 				.antMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
	 * 				.and()
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.httpBasic();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth
	 * 			.inMemoryAuthentication()
	 * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is the same as the previous configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers()
	 * 				.antMatchers(&quot;/api/**&quot;)
	 * 				.antMatchers(&quot;/oauth/**&quot;)
	 * 				.and()
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.httpBasic();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth
	 * 			.inMemoryAuthentication()
	 * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is also the same as the above configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers()
	 * 				.antMatchers(&quot;/api/**&quot;)
	 * 				.and()
	 *			 .requestMatchers()
	 * 				.antMatchers(&quot;/oauth/**&quot;)
	 * 				.and()
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.httpBasic();
	 * 	}
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth
	 * 			.inMemoryAuthentication()
	 * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 * 	}
	 * }
	 * </pre>
	 * @return the {@link RequestMatcherConfigurer} for further customizations
	 */
	public RequestMatcherConfigurer requestMatchers() {
		return this.requestMatcherConfigurer;
	}

	/**
	 * Allows specifying which {@link HttpServletRequest} instances this
	 * {@link HttpSecurity} will be invoked on. This method allows for easily invoking the
	 * {@link HttpSecurity} for multiple different {@link RequestMatcher} instances. If
	 * only a single {@link RequestMatcher} is necessary consider using
	 * {@link #mvcMatcher(String)}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #requestMatchers()} will not override previous invocations of
	 * {@link #mvcMatcher(String)}}, {@link #requestMatchers()},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, and
	 * {@link #requestMatcher(RequestMatcher)}.
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
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers((requestMatchers) -&gt;
	 * 				requestMatchers
	 * 					.antMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is the same as the previous configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers((requestMatchers) -&gt;
	 * 				requestMatchers
	 * 					.antMatchers(&quot;/api/**&quot;)
	 * 					.antMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 	}
	 * }
	 * </pre>
	 *
	 * The configuration below is also the same as the above configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers((requestMatchers) -&gt;
	 * 				requestMatchers
	 * 					.antMatchers(&quot;/api/**&quot;)
	 * 			)
	 *			.requestMatchers((requestMatchers) -&gt;
	 *			requestMatchers
	 * 				.antMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeRequests((authorizeRequests) -&gt;
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 * 	}
	 * }
	 * </pre>
	 * @param requestMatcherCustomizer the {@link Customizer} to provide more options for
	 * the {@link RequestMatcherConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 */
	public HttpSecurity requestMatchers(Customizer<RequestMatcherConfigurer> requestMatcherCustomizer) {
		requestMatcherCustomizer.customize(this.requestMatcherConfigurer);
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided {@link RequestMatcher}. If more advanced configuration is necessary,
	 * consider using {@link #requestMatchers()}.
	 *
	 * <p>
	 * Invoking {@link #requestMatcher(RequestMatcher)} will override previous invocations
	 * of {@link #requestMatchers()}, {@link #mvcMatcher(String)},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, and
	 * {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 * @param requestMatcher the {@link RequestMatcher} to use (i.e. new
	 * AntPathRequestMatcher("/admin/**","GET") )
	 * @return the {@link HttpSecurity} for further customizations
	 * @see #requestMatchers()
	 * @see #antMatcher(String)
	 * @see #regexMatcher(String)
	 */
	public HttpSecurity requestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
		return this;
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided ant pattern. If more advanced configuration is necessary, consider using
	 * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #antMatcher(String)} will override previous invocations of
	 * {@link #mvcMatcher(String)}}, {@link #requestMatchers()},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, and
	 * {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 * @param antPattern the Ant Pattern to match on (i.e. "/admin/**")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see AntPathRequestMatcher
	 */
	public HttpSecurity antMatcher(String antPattern) {
		return requestMatcher(new AntPathRequestMatcher(antPattern));
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided Spring MVC pattern. If more advanced configuration is necessary, consider
	 * using {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #mvcMatcher(String)} will override previous invocations of
	 * {@link #mvcMatcher(String)}}, {@link #requestMatchers()},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, and
	 * {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 * @param mvcPattern the Spring MVC Pattern to match on (i.e. "/admin/**")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see MvcRequestMatcher
	 */
	public HttpSecurity mvcMatcher(String mvcPattern) {
		HandlerMappingIntrospector introspector = new HandlerMappingIntrospector(getContext());
		return requestMatcher(new MvcRequestMatcher(introspector, mvcPattern));
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided regex pattern. If more advanced configuration is necessary, consider using
	 * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #regexMatcher(String)} will override previous invocations of
	 * {@link #mvcMatcher(String)}}, {@link #requestMatchers()},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, and
	 * {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 * @param pattern the Regular Expression to match on (i.e. "/admin/.+")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see RegexRequestMatcher
	 */
	public HttpSecurity regexMatcher(String pattern) {
		return requestMatcher(new RegexRequestMatcher(pattern, null));
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

	/**
	 * An extension to {@link RequestMatcherConfigurer} that allows optionally configuring
	 * the servlet path.
	 *
	 * @author Rob Winch
	 */
	public final class MvcMatchersRequestMatcherConfigurer extends RequestMatcherConfigurer {

		/**
		 * Creates a new instance
		 * @param context the {@link ApplicationContext} to use
		 * @param matchers the {@link MvcRequestMatcher} instances to set the servlet path
		 * on if {@link #servletPath(String)} is set.
		 */
		private MvcMatchersRequestMatcherConfigurer(ApplicationContext context, List<MvcRequestMatcher> matchers) {
			super(context);
			this.matchers = new ArrayList<>(matchers);
		}

		public RequestMatcherConfigurer servletPath(String servletPath) {
			for (RequestMatcher matcher : this.matchers) {
				((MvcRequestMatcher) matcher).setServletPath(servletPath);
			}
			return this;
		}

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
		public MvcMatchersRequestMatcherConfigurer mvcMatchers(HttpMethod method, String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			setMatchers(mvcMatchers);
			return new MvcMatchersRequestMatcherConfigurer(getContext(), mvcMatchers);
		}

		@Override
		public MvcMatchersRequestMatcherConfigurer mvcMatchers(String... patterns) {
			return mvcMatchers(null, patterns);
		}

		@Override
		protected RequestMatcherConfigurer chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			setMatchers(requestMatchers);
			return this;
		}

		private void setMatchers(List<? extends RequestMatcher> requestMatchers) {
			this.matchers.addAll(requestMatchers);
			requestMatcher(new OrRequestMatcher(this.matchers));
		}

		/**
		 * Return the {@link HttpSecurity} for further customizations
		 * @return the {@link HttpSecurity} for further customizations
		 */
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
