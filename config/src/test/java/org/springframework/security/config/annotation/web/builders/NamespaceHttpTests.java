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

package org.springframework.security.config.annotation.web.builders;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.function.Supplier;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;http&gt; attributes are present in
 * Java Config.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test // http@access-decision-manager-ref
	public void configureWhenAccessDecisionManagerSetThenVerifyUse() throws Exception {
		this.spring.register(AccessDecisionManagerRefConfig.class).autowire();
		AccessDecisionManager accessDecisionManager = this.spring.getContext().getBean(AccessDecisionManager.class);
		given(accessDecisionManager.supports(FilterInvocation.class)).willReturn(true);
		given(accessDecisionManager.supports(any(ConfigAttribute.class))).willReturn(true);
		this.mockMvc.perform(get("/"));
		verify(accessDecisionManager, times(1)).decide(any(Authentication.class), any(), anyCollection());
	}

	@Test // http@access-denied-page
	public void configureWhenAccessDeniedPageSetAndRequestForbiddenThenForwardedToAccessDeniedPage() throws Exception {
		this.spring.register(AccessDeniedPageConfig.class).autowire();
		this.mockMvc.perform(get("/admin").with(user(PasswordEncodedUser.user())))
			.andExpect(status().isForbidden())
			.andExpect(forwardedUrl("/AccessDeniedPage"));
	}

	@Test // http@authentication-manager-ref
	public void configureWhenAuthenticationManagerProvidedThenVerifyUse() throws Exception {
		AuthenticationManagerRefConfig.AUTHENTICATION_MANAGER = mock(AuthenticationManager.class);
		this.spring.register(AuthenticationManagerRefConfig.class).autowire();
		this.mockMvc.perform(formLogin());
		verify(AuthenticationManagerRefConfig.AUTHENTICATION_MANAGER, times(1)).authenticate(any(Authentication.class));
	}

	@Test // http@create-session=always
	public void configureWhenSessionCreationPolicyAlwaysThenSessionCreatedOnRequest() throws Exception {
		this.spring.register(CreateSessionAlwaysConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(get("/")).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNotNull();
		assertThat(session.isNew()).isTrue();
	}

	@Test // http@create-session=stateless
	public void configureWhenSessionCreationPolicyStatelessThenSessionNotCreatedOnRequest() throws Exception {
		this.spring.register(CreateSessionStatelessConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(get("/")).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test // http@create-session=ifRequired
	public void configureWhenSessionCreationPolicyIfRequiredThenSessionCreatedWhenRequiredOnRequest() throws Exception {
		this.spring.register(IfRequiredConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(get("/unsecure")).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
		mvcResult = this.mockMvc.perform(formLogin()).andReturn();
		session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNotNull();
		assertThat(session.isNew()).isTrue();
	}

	@Test // http@create-session=never
	public void configureWhenSessionCreationPolicyNeverThenSessionNotCreatedOnRequest() throws Exception {
		this.spring.register(CreateSessionNeverConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(get("/")).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test // http@entry-point-ref
	public void configureWhenAuthenticationEntryPointSetAndRequestUnauthorizedThenRedirectedToAuthenticationEntryPoint()
			throws Exception {
		this.spring.register(EntryPointRefConfig.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/entry-point"));
		// @formatter:on
	}

	@Test // http@jaas-api-provision
	public void configureWhenJaasApiIntegrationFilterAddedThenJaasSubjectObtained() throws Exception {
		LoginContext loginContext = mock(LoginContext.class);
		given(loginContext.getSubject()).willReturn(new Subject());
		JaasAuthenticationToken authenticationToken = mock(JaasAuthenticationToken.class);
		given(authenticationToken.isAuthenticated()).willReturn(true);
		given(authenticationToken.getLoginContext()).willReturn(loginContext);
		this.spring.register(JaasApiProvisionConfig.class).autowire();
		this.mockMvc.perform(get("/").with(authentication(authenticationToken)));
		verify(loginContext, times(1)).getSubject();
	}

	@Test // http@realm
	public void configureWhenHttpBasicAndRequestUnauthorizedThenReturnWWWAuthenticateWithRealm() throws Exception {
		this.spring.register(RealmConfig.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"RealmConfig\", charset=\"UTF-8\""));
		// @formatter:on
	}

	@Test // http@request-matcher-ref ant
	public void configureWhenAntPatternMatchingThenPathPatternRequestMatcherUsed() {
		this.spring.register(RequestMatcherAntConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChainProxy.getFilterChains().get(0)).isInstanceOf(DefaultSecurityFilterChain.class);
		DefaultSecurityFilterChain securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains()
			.get(0);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(PathPatternRequestMatcher.class);
	}

	@Test // http@request-matcher-ref regex
	public void configureWhenRegexPatternMatchingThenRegexRequestMatcherUsed() {
		this.spring.register(RequestMatcherRegexConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChainProxy.getFilterChains().get(0)).isInstanceOf(DefaultSecurityFilterChain.class);
		DefaultSecurityFilterChain securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains()
			.get(0);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(RegexRequestMatcher.class);
	}

	@Test // http@request-matcher-ref
	public void configureWhenRequestMatcherProvidedThenRequestMatcherUsed() {
		this.spring.register(RequestMatcherRefConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChainProxy.getFilterChains().get(0)).isInstanceOf(DefaultSecurityFilterChain.class);
		DefaultSecurityFilterChain securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains()
			.get(0);
		assertThat(securityFilterChain.getRequestMatcher())
			.isInstanceOf(RequestMatcherRefConfig.MyRequestMatcher.class);
	}

	@Test // http@security=none
	public void configureWhenIgnoredAntPatternsThenPathPatternRequestMatcherUsedWithNoFilters() {
		this.spring.register(SecurityNoneConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChainProxy.getFilterChains().get(0)).isInstanceOf(DefaultSecurityFilterChain.class);
		DefaultSecurityFilterChain securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains()
			.get(0);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(PathPatternRequestMatcher.class);
		assertThat(securityFilterChain.getRequestMatcher()).isEqualTo(pathPattern("/resources/**"));
		assertThat(securityFilterChain.getFilters()).isEmpty();
		assertThat(filterChainProxy.getFilterChains().get(1)).isInstanceOf(DefaultSecurityFilterChain.class);
		securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains().get(1);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(PathPatternRequestMatcher.class);
		assertThat(securityFilterChain.getRequestMatcher()).isEqualTo(pathPattern("/public/**"));
		assertThat(securityFilterChain.getFilters()).isEmpty();
	}

	@Test // http@security-context-repository-ref
	public void configureWhenNullSecurityContextRepositoryThenSecurityContextNotSavedInSession() throws Exception {
		this.spring.register(SecurityContextRepoConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(formLogin()).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test // http@servlet-api-provision=false
	public void configureWhenServletApiDisabledThenRequestNotServletApiWrapper() throws Exception {
		this.spring.register(ServletApiProvisionConfig.class, MainController.class).autowire();
		this.mockMvc.perform(get("/"));
		assertThat(MainController.HTTP_SERVLET_REQUEST_TYPE)
			.isNotInstanceOf(SecurityContextHolderAwareRequestWrapper.class);
	}

	@Test // http@servlet-api-provision defaults to true
	public void configureWhenServletApiDefaultThenRequestIsServletApiWrapper() throws Exception {
		this.spring.register(ServletApiProvisionDefaultsConfig.class, MainController.class).autowire();
		this.mockMvc.perform(get("/"));
		assertThat(SecurityContextHolderAwareRequestWrapper.class)
			.isAssignableFrom(MainController.HTTP_SERVLET_REQUEST_TYPE);
	}

	@Configuration
	@EnableWebSecurity
	static class AccessDecisionManagerRefConfig {

		AccessDecisionManager accessDecisionManager = mock(AccessDecisionManager.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().access(new AccessAuthorizationManagerAdapter(this.accessDecisionManager, "permitAll"))
				);
			return http.build();
			// @formatter:on
		}

		@Bean
		AccessDecisionManager accessDecisionManager() {
			return this.accessDecisionManager;
		}

		private static final class AccessAuthorizationManagerAdapter
				implements AuthorizationManager<RequestAuthorizationContext> {

			private final AccessDecisionManager delegate;

			private final SecurityMetadataSource metadataSource;

			private AccessAuthorizationManagerAdapter(AccessDecisionManager delegate, String expression) {
				this.delegate = delegate;
				LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> mappings = new LinkedHashMap<>();
				mappings.put(AnyRequestMatcher.INSTANCE, SecurityConfig.createList(expression));
				DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
				this.metadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(mappings, handler);
			}

			@Override
			public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
					RequestAuthorizationContext object) {
				HttpServletRequest request = object.getRequest();
				FilterInvocation invocation = new FilterInvocation(request.getContextPath(), request.getServletPath(),
						request.getPathInfo(), request.getQueryString(), request.getMethod());
				Collection<ConfigAttribute> attributes = this.metadataSource.getAttributes(invocation);
				try {
					this.delegate.decide(authentication.get(), invocation, attributes);
					return new AuthorizationDecision(true);
				}
				catch (AccessDeniedException ex) {
					return new AuthorizationDecision(false);
				}
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class AccessDeniedPageConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.requestMatchers("/admin").hasRole("ADMIN")
					.anyRequest().authenticated())
				.exceptionHandling((handling) -> handling
					.accessDeniedPage("/AccessDeniedPage"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthenticationManagerRefConfig {

		static AuthenticationManager AUTHENTICATION_MANAGER;

		@Bean
		AuthenticationManager authenticationManager() {
			return AUTHENTICATION_MANAGER;
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.formLogin(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CreateSessionAlwaysConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().permitAll())
				.sessionManagement((management) -> management
					.sessionCreationPolicy(SessionCreationPolicy.ALWAYS));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CreateSessionStatelessConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().permitAll())
				.sessionManagement((management) -> management
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IfRequiredConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.requestMatchers("/unsecure").permitAll()
					.anyRequest().authenticated())
				.sessionManagement((management) -> management
					.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
				.formLogin(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CreateSessionNeverConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().anonymous())
				.sessionManagement((management) -> management
					.sessionCreationPolicy(SessionCreationPolicy.NEVER));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class EntryPointRefConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.exceptionHandling((handling) -> handling
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/entry-point")))
				.formLogin(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class JaasApiProvisionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilter(new JaasApiIntegrationFilter());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RealmConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.httpBasic((basic) -> basic
					.realmName("RealmConfig"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestMatcherAntConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatcher(pathPattern("/api/**"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestMatcherRegexConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatcher(new RegexRequestMatcher("/regex/.*", null));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestMatcherRefConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatcher(new MyRequestMatcher());
			return http.build();
			// @formatter:on
		}

		static class MyRequestMatcher implements RequestMatcher {

			@Override
			public boolean matches(HttpServletRequest request) {
				return true;
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityNoneConfig {

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.withDefaults();
			return (web) -> web.ignoring()
				.requestMatchers(builder.matcher("/resources/**"), builder.matcher("/public/**"));
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityContextRepoConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().authenticated())
				.securityContext((context) -> context
					.securityContextRepository(new NullSecurityContextRepository()))
				.formLogin(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ServletApiProvisionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().permitAll())
				.servletApi((api) -> api
					.disable());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ServletApiProvisionDefaultsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().permitAll());
			return http.build();
			// @formatter:on
		}

	}

	@Controller
	static class MainController {

		static Class<? extends HttpServletRequest> HTTP_SERVLET_REQUEST_TYPE;

		@GetMapping("/")
		String index(HttpServletRequest request) {
			HTTP_SERVLET_REQUEST_TYPE = request.getClass();
			return "index";
		}

	}

}
