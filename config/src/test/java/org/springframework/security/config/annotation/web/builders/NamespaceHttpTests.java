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
package org.springframework.security.config.annotation.web.builders;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;http&gt; attributes are present in
 * Java Config.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
public class NamespaceHttpTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test // http@access-decision-manager-ref
	public void configureWhenAccessDecisionManagerSetThenVerifyUse() throws Exception {
		AccessDecisionManagerRefConfig.ACCESS_DECISION_MANAGER = mock(AccessDecisionManager.class);
		given(AccessDecisionManagerRefConfig.ACCESS_DECISION_MANAGER.supports(FilterInvocation.class)).willReturn(true);
		given(AccessDecisionManagerRefConfig.ACCESS_DECISION_MANAGER.supports(any(ConfigAttribute.class)))
				.willReturn(true);

		this.spring.register(AccessDecisionManagerRefConfig.class).autowire();

		this.mockMvc.perform(get("/"));

		verify(AccessDecisionManagerRefConfig.ACCESS_DECISION_MANAGER, times(1)).decide(any(Authentication.class),
				any(), anyCollection());
	}

	@Test // http@access-denied-page
	public void configureWhenAccessDeniedPageSetAndRequestForbiddenThenForwardedToAccessDeniedPage() throws Exception {
		this.spring.register(AccessDeniedPageConfig.class).autowire();

		this.mockMvc.perform(get("/admin").with(user(PasswordEncodedUser.user()))).andExpect(status().isForbidden())
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

		this.mockMvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrlPattern("**/entry-point"));
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

		this.mockMvc.perform(get("/")).andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"RealmConfig\""));
	}

	@Test // http@request-matcher-ref ant
	public void configureWhenAntPatternMatchingThenAntPathRequestMatcherUsed() {
		this.spring.register(RequestMatcherAntConfig.class).autowire();

		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);

		assertThat(filterChainProxy.getFilterChains().get(0)).isInstanceOf(DefaultSecurityFilterChain.class);
		DefaultSecurityFilterChain securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains()
				.get(0);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(AntPathRequestMatcher.class);
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
	public void configureWhenIgnoredAntPatternsThenAntPathRequestMatcherUsedWithNoFilters() {
		this.spring.register(SecurityNoneConfig.class).autowire();

		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);

		assertThat(filterChainProxy.getFilterChains().get(0)).isInstanceOf(DefaultSecurityFilterChain.class);
		DefaultSecurityFilterChain securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains()
				.get(0);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(((AntPathRequestMatcher) securityFilterChain.getRequestMatcher()).getPattern())
				.isEqualTo("/resources/**");
		assertThat(securityFilterChain.getFilters()).isEmpty();

		assertThat(filterChainProxy.getFilterChains().get(1)).isInstanceOf(DefaultSecurityFilterChain.class);
		securityFilterChain = (DefaultSecurityFilterChain) filterChainProxy.getFilterChains().get(1);
		assertThat(securityFilterChain.getRequestMatcher()).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(((AntPathRequestMatcher) securityFilterChain.getRequestMatcher()).getPattern())
				.isEqualTo("/public/**");
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

	@Test // http@use-expressions=true
	public void configureWhenUseExpressionsEnabledThenExpressionBasedSecurityMetadataSource() {
		this.spring.register(UseExpressionsConfig.class).autowire();

		UseExpressionsConfig config = this.spring.getContext().getBean(UseExpressionsConfig.class);

		assertThat(ExpressionBasedFilterInvocationSecurityMetadataSource.class)
				.isAssignableFrom(config.filterInvocationSecurityMetadataSourceType);
	}

	@Test // http@use-expressions=false
	public void configureWhenUseExpressionsDisabledThenDefaultSecurityMetadataSource() {
		this.spring.register(DisableUseExpressionsConfig.class).autowire();

		DisableUseExpressionsConfig config = this.spring.getContext().getBean(DisableUseExpressionsConfig.class);

		assertThat(DefaultFilterInvocationSecurityMetadataSource.class)
				.isAssignableFrom(config.filterInvocationSecurityMetadataSourceType);
	}

	@EnableWebSecurity
	static class AccessDecisionManagerRefConfig extends WebSecurityConfigurerAdapter {

		static AccessDecisionManager ACCESS_DECISION_MANAGER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
				.accessDecisionManager(ACCESS_DECISION_MANAGER);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AccessDeniedPageConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/admin").hasRole("ADMIN")
					.anyRequest().authenticated()
					.and()
				.exceptionHandling()
					.accessDeniedPage("/AccessDeniedPage");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AuthenticationManagerRefConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationManager AUTHENTICATION_MANAGER;

		@Override
		protected AuthenticationManager authenticationManager() {
			return AUTHENTICATION_MANAGER;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CreateSessionAlwaysConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CreateSessionStatelessConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class IfRequiredConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/unsecure").permitAll()
					.anyRequest().authenticated()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CreateSessionNeverConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().anonymous()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.NEVER);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class EntryPointRefConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/entry-point"))
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class JaasApiProvisionConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.addFilter(new JaasApiIntegrationFilter());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RealmConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.realmName("RealmConfig");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RequestMatcherAntConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.antMatcher("/api/**");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RequestMatcherRegexConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.regexMatcher("/regex/.*");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RequestMatcherRefConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.requestMatcher(new MyRequestMatcher());
			// @formatter:on
		}

		static class MyRequestMatcher implements RequestMatcher {

			@Override
			public boolean matches(HttpServletRequest request) {
				return true;
			}

		}

	}

	@EnableWebSecurity
	static class SecurityNoneConfig extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(WebSecurity web) {
			web.ignoring().antMatchers("/resources/**", "/public/**");
		}

		@Override
		protected void configure(HttpSecurity http) {
		}

	}

	@EnableWebSecurity
	static class SecurityContextRepoConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.securityContext()
					.securityContextRepository(new NullSecurityContextRepository())
					.and()
				.formLogin();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class ServletApiProvisionConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.servletApi()
					.disable();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class ServletApiProvisionDefaultsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll();
			// @formatter:on
		}

	}

	@Controller
	static class MainController {

		static Class<? extends HttpServletRequest> HTTP_SERVLET_REQUEST_TYPE;

		@GetMapping("/")
		public String index(HttpServletRequest request) {
			HTTP_SERVLET_REQUEST_TYPE = request.getClass();
			return "index";
		}

	}

	@EnableWebSecurity
	static class UseExpressionsConfig extends WebSecurityConfigurerAdapter {

		private Class<? extends FilterInvocationSecurityMetadataSource> filterInvocationSecurityMetadataSourceType;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/users**", "/sessions/**").hasRole("USER")
					.antMatchers("/signup").permitAll()
					.anyRequest().hasRole("USER");
			// @formatter:on
		}

		@Override
		public void init(final WebSecurity web) throws Exception {
			super.init(web);
			final HttpSecurity http = this.getHttp();
			web.postBuildAction(() -> {
				FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
				UseExpressionsConfig.this.filterInvocationSecurityMetadataSourceType = securityInterceptor
						.getSecurityMetadataSource().getClass();
			});
		}

	}

	@EnableWebSecurity
	static class DisableUseExpressionsConfig extends WebSecurityConfigurerAdapter {

		private Class<? extends FilterInvocationSecurityMetadataSource> filterInvocationSecurityMetadataSourceType;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(new UrlAuthorizationConfigurer<>(getApplicationContext())).getRegistry()
					.antMatchers("/users**", "/sessions/**").hasRole("USER")
					.antMatchers("/signup").hasRole("ANONYMOUS")
					.anyRequest().hasRole("USER");
			// @formatter:on
		}

		@Override
		public void init(final WebSecurity web) throws Exception {
			super.init(web);
			final HttpSecurity http = this.getHttp();
			web.postBuildAction(() -> {
				FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
				DisableUseExpressionsConfig.this.filterInvocationSecurityMetadataSourceType = securityInterceptor
						.getSecurityMetadataSource().getClass();
			});
		}

	}

}
