/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.users.AuthenticationTestConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.RequestMatcherDelegatingWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link WebSecurityConfiguration}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @author Evgeniy Cheban
 * @author Marcus Da Coregio
 */
@ExtendWith(SpringTestContextExtension.class)
public class WebSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	public SpringTestContext child = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void loadConfigWhenSecurityFilterChainsHaveOrderThenFilterChainsOrdered() {
		this.spring.register(SortedSecurityFilterChainConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
		assertThat(filterChains).hasSize(4);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/role1/**");
		assertThat(filterChains.get(0).matches(request)).isTrue();
		request.setServletPath("/role2/**");
		assertThat(filterChains.get(1).matches(request)).isTrue();
		request.setServletPath("/role3/**");
		assertThat(filterChains.get(2).matches(request)).isTrue();
		request.setServletPath("/**");
		assertThat(filterChains.get(3).matches(request)).isTrue();
	}

	@Test
	public void loadConfigWhenSecurityFilterChainsHaveOrderOnBeanDefinitionsThenFilterChainsOrdered() {
		this.spring.register(OrderOnBeanDefinitionsSecurityFilterChainConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
		assertThat(filterChains).hasSize(2);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/role1/**");
		assertThat(filterChains.get(0).matches(request)).isTrue();
		request.setServletPath("/role2/**");
		assertThat(filterChains.get(1).matches(request)).isTrue();
	}

	@Test
	public void loadConfigWhenWebInvocationPrivilegeEvaluatorSetThenIsRegistered() {
		PrivilegeEvaluatorConfigurerAdapterConfig.PRIVILEGE_EVALUATOR = mock(WebInvocationPrivilegeEvaluator.class);
		this.spring.register(PrivilegeEvaluatorConfigurerAdapterConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
				.isSameAs(PrivilegeEvaluatorConfigurerAdapterConfig.PRIVILEGE_EVALUATOR);
	}

	@Test
	public void loadConfigWhenSecurityExpressionHandlerSetThenIsRegistered() {
		WebSecurityExpressionHandlerConfig.EXPRESSION_HANDLER = mock(SecurityExpressionHandler.class);
		given(WebSecurityExpressionHandlerConfig.EXPRESSION_HANDLER.getExpressionParser())
				.willReturn(mock(ExpressionParser.class));
		this.spring.register(WebSecurityExpressionHandlerConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(SecurityExpressionHandler.class))
				.isSameAs(WebSecurityExpressionHandlerConfig.EXPRESSION_HANDLER);
	}

	@Test
	public void loadConfigWhenSecurityExpressionHandlerIsNullThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullWebSecurityExpressionHandlerConfig.class).autowire())
				.havingRootCause().isExactlyInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadConfigWhenDefaultSecurityExpressionHandlerThenDefaultIsRegistered() {
		this.spring.register(WebSecurityExpressionHandlerDefaultsConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(SecurityExpressionHandler.class))
				.isInstanceOf(DefaultWebSecurityExpressionHandler.class);
	}

	@Test
	public void securityExpressionHandlerWhenRoleHierarchyBeanThenRoleHierarchyUsed() {
		this.spring.register(WebSecurityExpressionHandlerRoleHierarchyBeanConfig.class).autowire();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "notused", "ROLE_ADMIN");
		FilterInvocation invocation = new FilterInvocation(new MockHttpServletRequest("GET", ""),
				new MockHttpServletResponse(), new MockFilterChain());
		AbstractSecurityExpressionHandler handler = this.spring.getContext()
				.getBean(AbstractSecurityExpressionHandler.class);
		EvaluationContext evaluationContext = handler.createEvaluationContext(authentication, invocation);
		Expression expression = handler.getExpressionParser().parseExpression("hasRole('ROLE_USER')");
		boolean granted = expression.getValue(evaluationContext, Boolean.class);
		assertThat(granted).isTrue();
	}

	@Test
	public void securityExpressionHandlerWhenPermissionEvaluatorBeanThenPermissionEvaluatorUsed() {
		this.spring.register(WebSecurityExpressionHandlerPermissionEvaluatorBeanConfig.class).autowire();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "notused");
		FilterInvocation invocation = new FilterInvocation(new MockHttpServletRequest("GET", ""),
				new MockHttpServletResponse(), new MockFilterChain());
		AbstractSecurityExpressionHandler handler = this.spring.getContext()
				.getBean(AbstractSecurityExpressionHandler.class);
		EvaluationContext evaluationContext = handler.createEvaluationContext(authentication, invocation);
		Expression expression = handler.getExpressionParser().parseExpression("hasPermission(#study,'DELETE')");
		boolean granted = expression.getValue(evaluationContext, Boolean.class);
		assertThat(granted).isTrue();
	}

	@Test
	public void loadConfigWhenDefaultWebInvocationPrivilegeEvaluatorThenRequestMatcherIsRegistered() {
		this.spring.register(WebInvocationPrivilegeEvaluatorDefaultsConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
				.isInstanceOf(RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.class);
	}

	@Test
	public void loadConfigWhenSecurityFilterChainBeanThenDefaultWebInvocationPrivilegeEvaluatorIsRegistered() {
		this.spring.register(AuthorizeRequestsFilterChainConfig.class).autowire();

		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
				.isInstanceOf(RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.class);
	}

	// SEC-2303
	@Test
	public void loadConfigWhenDefaultSecurityExpressionHandlerThenBeanResolverSet() throws Exception {
		this.spring.register(DefaultExpressionHandlerSetsBeanResolverConfig.class).autowire();
		this.mockMvc.perform(get("/")).andExpect(status().isOk());
		this.mockMvc.perform(post("/")).andExpect(status().isForbidden());
	}

	// SEC-2461
	@Test
	public void loadConfigWhenMultipleWebSecurityConfigurationThenContextLoads() {
		this.spring.register(ParentConfig.class).autowire();
		this.child.register(ChildConfig.class);
		this.child.getContext().setParent(this.spring.getContext());
		this.child.autowire();
		assertThat(this.spring.getContext().getBean("springSecurityFilterChain")).isNotNull();
		assertThat(this.child.getContext().getBean("springSecurityFilterChain")).isNotNull();
		assertThat(this.spring.getContext().containsBean("springSecurityFilterChain")).isTrue();
		assertThat(this.child.getContext().containsBean("springSecurityFilterChain")).isTrue();
	}

	// SEC-2773
	@Test
	public void getMethodDelegatingApplicationListenerWhenWebSecurityConfigurationThenIsStatic() {
		Method method = ClassUtils.getMethod(WebSecurityConfiguration.class, "delegatingApplicationListener", null);
		assertThat(Modifier.isStatic(method.getModifiers())).isTrue();
	}

	@Test
	public void loadConfigWhenOnlyWebSecurityCustomizerThenDefaultFilterChainCreated() {
		this.spring.register(WebSecurityCustomizerConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
		assertThat(filterChains).hasSize(3);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/ignore1");
		assertThat(filterChains.get(0).matches(request)).isTrue();
		assertThat(filterChains.get(0).getFilters()).isEmpty();
		request.setServletPath("/ignore2");
		assertThat(filterChains.get(1).matches(request)).isTrue();
		assertThat(filterChains.get(1).getFilters()).isEmpty();
		request.setServletPath("/test/**");
		assertThat(filterChains.get(2).matches(request)).isTrue();
	}

	@Test
	public void loadConfigWhenWebSecurityCustomizerAndFilterChainThenFilterChainsOrdered() {
		this.spring.register(CustomizerAndFilterChainConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
		assertThat(filterChains).hasSize(3);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/ignore1");
		assertThat(filterChains.get(0).matches(request)).isTrue();
		assertThat(filterChains.get(0).getFilters()).isEmpty();
		request.setServletPath("/ignore2");
		assertThat(filterChains.get(1).matches(request)).isTrue();
		assertThat(filterChains.get(1).getFilters()).isEmpty();
		request.setServletPath("/role1/**");
		assertThat(filterChains.get(2).matches(request)).isTrue();
		request.setServletPath("/test/**");
		assertThat(filterChains.get(2).matches(request)).isFalse();
	}

	@Test
	public void loadConfigWhenCustomizersHaveOrderThenCustomizersOrdered() {
		this.spring.register(OrderedCustomizerConfig.class).autowire();
		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
		assertThat(filterChains).hasSize(3);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/ignore1");
		assertThat(filterChains.get(0).matches(request)).isTrue();
		assertThat(filterChains.get(0).getFilters()).isEmpty();
		request.setServletPath("/ignore2");
		assertThat(filterChains.get(1).matches(request)).isTrue();
		assertThat(filterChains.get(1).getFilters()).isEmpty();
	}

	@Test
	public void loadConfigWhenTwoSecurityFilterChainsThenRequestMatcherDelegatingWebInvocationPrivilegeEvaluator() {
		this.spring.register(TwoSecurityFilterChainConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
				.isInstanceOf(RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.class);
	}

	@Test
	public void loadConfigWhenTwoSecurityFilterChainDebugThenRequestMatcherDelegatingWebInvocationPrivilegeEvaluator() {
		this.spring.register(TwoSecurityFilterChainConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
				.isInstanceOf(RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.class);
	}

	// gh-10554
	@Test
	public void loadConfigWhenMultipleSecurityFilterChainsThenWebInvocationPrivilegeEvaluatorApplySecurity() {
		this.spring.register(MultipleSecurityFilterChainConfig.class).autowire();
		WebInvocationPrivilegeEvaluator privilegeEvaluator = this.spring.getContext()
				.getBean(WebInvocationPrivilegeEvaluator.class);
		assertUserPermissions(privilegeEvaluator);
		assertAdminPermissions(privilegeEvaluator);
		assertAnotherUserPermission(privilegeEvaluator);
	}

	// gh-10554
	@Test
	public void loadConfigWhenMultipleSecurityFilterChainAndIgnoringThenWebInvocationPrivilegeEvaluatorAcceptsNullAuthenticationOnIgnored() {
		this.spring.register(MultipleSecurityFilterChainIgnoringConfig.class).autowire();
		WebInvocationPrivilegeEvaluator privilegeEvaluator = this.spring.getContext()
				.getBean(WebInvocationPrivilegeEvaluator.class);
		assertUserPermissions(privilegeEvaluator);
		assertAdminPermissions(privilegeEvaluator);
		assertAnotherUserPermission(privilegeEvaluator);
		// null authentication
		assertThat(privilegeEvaluator.isAllowed("/user", null)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/admin", null)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/another", null)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/ignoring1", null)).isTrue();
		assertThat(privilegeEvaluator.isAllowed("/ignoring1/child", null)).isTrue();
	}

	private void assertAnotherUserPermission(WebInvocationPrivilegeEvaluator privilegeEvaluator) {
		Authentication anotherUser = new TestingAuthenticationToken("anotherUser", "password", "ROLE_ANOTHER");
		assertThat(privilegeEvaluator.isAllowed("/user", anotherUser)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/admin", anotherUser)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/another", anotherUser)).isTrue();
	}

	private void assertAdminPermissions(WebInvocationPrivilegeEvaluator privilegeEvaluator) {
		Authentication admin = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");
		assertThat(privilegeEvaluator.isAllowed("/user", admin)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/admin", admin)).isTrue();
		assertThat(privilegeEvaluator.isAllowed("/another", admin)).isTrue();
	}

	private void assertUserPermissions(WebInvocationPrivilegeEvaluator privilegeEvaluator) {
		Authentication user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		assertThat(privilegeEvaluator.isAllowed("/user", user)).isTrue();
		assertThat(privilegeEvaluator.isAllowed("/admin", user)).isFalse();
		assertThat(privilegeEvaluator.isAllowed("/another", user)).isTrue();
	}

	@Configuration
	@EnableWebSecurity
	@Import(AuthenticationTestConfiguration.class)
	static class SortedSecurityFilterChainConfig {

		@Order(1)
		@Bean
		SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.securityMatcher(new AntPathRequestMatcher("/role1/**"))
					.authorizeRequests((authorize) -> authorize
							.anyRequest().hasRole("1")
					)
					.build();
			// @formatter:on
		}

		@Order(2)
		@Bean
		SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.securityMatcher(new AntPathRequestMatcher("/role2/**"))
					.authorizeRequests((authorize) -> authorize
							.anyRequest().hasRole("2")
					)
					.build();
			// @formatter:on
		}

		@Order(3)
		@Bean
		SecurityFilterChain filterChain3(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.securityMatcher(new AntPathRequestMatcher("/role3/**"))
					.authorizeRequests((authorize) -> authorize
							.anyRequest().hasRole("3")
					)
					.build();
			// @formatter:on
		}

		@Bean
		SecurityFilterChain filterChain4(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeRequests((authorize) -> authorize
						.anyRequest().hasRole("4")
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(AuthenticationTestConfiguration.class)
	static class OrderOnBeanDefinitionsSecurityFilterChainConfig {

		@Bean
		@Order(1)
		SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.securityMatcher(new AntPathRequestMatcher("/role1/**"))
					.authorizeRequests((authorize) -> authorize
							.anyRequest().hasRole("1")
					)
					.build();
			// @formatter:on
		}

		@Bean
		TestSecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
			return new TestSecurityFilterChain();
		}

		@Order(2)
		static class TestSecurityFilterChain implements SecurityFilterChain {

			@Override
			public boolean matches(HttpServletRequest request) {
				return true;
			}

			@Override
			public List<Filter> getFilters() {
				return new ArrayList<>();
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	static class PrivilegeEvaluatorConfigurerAdapterConfig {

		static WebInvocationPrivilegeEvaluator PRIVILEGE_EVALUATOR;

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.privilegeEvaluator(PRIVILEGE_EVALUATOR);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityExpressionHandlerConfig {

		static SecurityExpressionHandler EXPRESSION_HANDLER;

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.expressionHandler(EXPRESSION_HANDLER);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.expressionHandler(EXPRESSION_HANDLER);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NullWebSecurityExpressionHandlerConfig {

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.expressionHandler(null);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityExpressionHandlerDefaultsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityExpressionHandlerRoleHierarchyBeanConfig {

		@Bean
		RoleHierarchy roleHierarchy() {
			RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
			roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
			return roleHierarchy;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityExpressionHandlerPermissionEvaluatorBeanConfig {

		static final PermissionEvaluator PERMIT_ALL_PERMISSION_EVALUATOR = new PermissionEvaluator() {
			@Override
			public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
				return true;
			}

			@Override
			public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
					Object permission) {
				return true;
			}
		};

		@Bean
		PermissionEvaluator permissionEvaluator() {
			return PERMIT_ALL_PERMISSION_EVALUATOR;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebInvocationPrivilegeEvaluatorDefaultsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizeRequestsFilterChainConfig {

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeRequests((authorize) -> authorize
						.anyRequest().authenticated()
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultExpressionHandlerSetsBeanResolverConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().access("request.method == 'GET' ? @b.grant() : @b.deny()");
			return http.build();
			// @formatter:on
		}

		@Bean
		public MyBean b() {
			return new MyBean();
		}

		@RestController
		class HomeController {

			@GetMapping("/")
			String home() {
				return "home";
			}

		}

		static class MyBean {

			public boolean deny() {
				return false;
			}

			public boolean grant() {
				return true;
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	static class ParentConfig {

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ChildConfig {

	}

	@Configuration
	static class SubclassConfig extends WebSecurityConfiguration {

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	@Import(AuthenticationTestConfiguration.class)
	static class WebSecurityCustomizerConfig {

		@Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/ignore1", "/ignore2");
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	@Import(AuthenticationTestConfiguration.class)
	static class CustomizerAndFilterChainConfig {

		@Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/ignore1", "/ignore2");
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.securityMatcher(new AntPathRequestMatcher("/role1/**"))
					.authorizeRequests((authorize) -> authorize
							.anyRequest().hasRole("1")
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	@Import(AuthenticationTestConfiguration.class)
	static class OrderedCustomizerConfig {

		@Order(1)
		@Bean
		public WebSecurityCustomizer webSecurityCustomizer1() {
			return (web) -> web.ignoring().requestMatchers("/ignore1");
		}

		@Order(2)
		@Bean
		public WebSecurityCustomizer webSecurityCustomizer2() {
			return (web) -> web.ignoring().requestMatchers("/ignore2");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class TwoSecurityFilterChainConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		public SecurityFilterChain path1(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatchers((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/path1/**")))
				.authorizeRequests((requests) -> requests.anyRequest().authenticated());
			// @formatter:on
			return http.build();
		}

		@Bean
		@Order(Ordered.LOWEST_PRECEDENCE)
		public SecurityFilterChain permitAll(HttpSecurity http) throws Exception {
			http.authorizeRequests((requests) -> requests.anyRequest().permitAll());
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity(debug = true)
	static class TwoSecurityFilterChainDebugConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		public SecurityFilterChain path1(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.securityMatchers((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/path1/**")))
					.authorizeRequests((requests) -> requests.anyRequest().authenticated());
			// @formatter:on
			return http.build();
		}

		@Bean
		@Order(Ordered.LOWEST_PRECEDENCE)
		public SecurityFilterChain permitAll(HttpSecurity http) throws Exception {
			http.authorizeRequests((requests) -> requests.anyRequest().permitAll());
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(AuthenticationTestConfiguration.class)
	static class MultipleSecurityFilterChainConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		public SecurityFilterChain notAuthorized(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatchers((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/user")))
				.authorizeRequests((requests) -> requests.anyRequest().hasRole("USER"));
			// @formatter:on
			return http.build();
		}

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE + 1)
		public SecurityFilterChain path1(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatchers((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/admin")))
				.authorizeRequests((requests) -> requests.anyRequest().hasRole("ADMIN"));
			// @formatter:on
			return http.build();
		}

		@Bean
		@Order(Ordered.LOWEST_PRECEDENCE)
		public SecurityFilterChain permitAll(HttpSecurity http) throws Exception {
			http.authorizeRequests((requests) -> requests.anyRequest().permitAll());
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	@Import(AuthenticationTestConfiguration.class)
	static class MultipleSecurityFilterChainIgnoringConfig {

		@Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/ignoring1/**");
		}

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		public SecurityFilterChain notAuthorized(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.securityMatchers((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/user")))
					.authorizeRequests((requests) -> requests.anyRequest().hasRole("USER"));
			// @formatter:on
			return http.build();
		}

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE + 1)
		public SecurityFilterChain admin(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.securityMatchers((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/admin")))
					.authorizeRequests((requests) -> requests.anyRequest().hasRole("ADMIN"));
			// @formatter:on
			return http.build();
		}

		@Bean
		@Order(Ordered.LOWEST_PRECEDENCE)
		public SecurityFilterChain permitAll(HttpSecurity http) throws Exception {
			http.authorizeRequests((requests) -> requests.anyRequest().permitAll());
			return http.build();
		}

	}

}
