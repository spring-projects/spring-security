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
package org.springframework.security.config.annotation.web.configuration;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.config.users.AuthenticationTestConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link WebSecurityConfiguration}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
public class WebSecurityConfigurationTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void loadConfigWhenWebSecurityConfigurersHaveOrderThenFilterChainsOrdered() throws Exception {
		this.spring.register(SortedWebSecurityConfigurerAdaptersConfig.class).autowire();

		FilterChainProxy filterChainProxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
		assertThat(filterChains).hasSize(6);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");

		request.setServletPath("/ignore1");
		assertThat(filterChains.get(0).matches(request)).isTrue();
		assertThat(filterChains.get(0).getFilters()).isEmpty();

		request.setServletPath("/ignore2");
		assertThat(filterChains.get(1).matches(request)).isTrue();
		assertThat(filterChains.get(1).getFilters()).isEmpty();

		request.setServletPath("/role1/**");
		assertThat(filterChains.get(2).matches(request)).isTrue();

		request.setServletPath("/role2/**");
		assertThat(filterChains.get(3).matches(request)).isTrue();

		request.setServletPath("/role3/**");
		assertThat(filterChains.get(4).matches(request)).isTrue();

		request.setServletPath("/**");
		assertThat(filterChains.get(5).matches(request)).isTrue();
	}

	@EnableWebSecurity
	@Import(AuthenticationTestConfiguration.class)
	static class SortedWebSecurityConfigurerAdaptersConfig {

		@Configuration
		@Order(1)
		static class WebConfigurer1 extends WebSecurityConfigurerAdapter {
			@Override
			public void configure(WebSecurity web)	throws Exception {
				web
					.ignoring()
						.antMatchers("/ignore1", "/ignore2");
			}

			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role1/**")
					.authorizeRequests()
						.anyRequest().hasRole("1");
			}
		}

		@Configuration
		@Order(2)
		static class WebConfigurer2 extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role2/**")
					.authorizeRequests()
						.anyRequest().hasRole("2");
			}
		}

		@Configuration
		@Order(3)
		static class WebConfigurer3 extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role3/**")
					.authorizeRequests()
						.anyRequest().hasRole("3");
			}
		}

		@Configuration
		static class WebConfigurer4 extends WebSecurityConfigurerAdapter {

			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.authorizeRequests()
						.anyRequest().hasRole("4");
			}
		}
	}

	@Test
	public void loadConfigWhenWebSecurityConfigurersHaveSameOrderThenThrowBeanCreationException() throws Exception {
		Throwable thrown = catchThrowable(() -> this.spring.register(DuplicateOrderConfig.class).autowire());

		assertThat(thrown).isInstanceOf(BeanCreationException.class)
			.hasMessageContaining("@Order on WebSecurityConfigurers must be unique")
			.hasMessageContaining(DuplicateOrderConfig.WebConfigurer1.class.getName())
			.hasMessageContaining(DuplicateOrderConfig.WebConfigurer2.class.getName());
	}

	@EnableWebSecurity
	@Import(AuthenticationTestConfiguration.class)
	static class DuplicateOrderConfig {

		@Configuration
		static class WebConfigurer1 extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role1/**")
						.authorizeRequests()
							.anyRequest().hasRole("1");
			}
		}

		@Configuration
		static class WebConfigurer2 extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role2/**")
						.authorizeRequests()
							.anyRequest().hasRole("2");
			}
		}
	}

	@Test
	public void loadConfigWhenWebInvocationPrivilegeEvaluatorSetThenIsRegistered() throws Exception {
		PrivilegeEvaluatorConfigurerAdapterConfig.PRIVILEGE_EVALUATOR = mock(WebInvocationPrivilegeEvaluator.class);

		this.spring.register(PrivilegeEvaluatorConfigurerAdapterConfig.class).autowire();

		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
			.isSameAs(PrivilegeEvaluatorConfigurerAdapterConfig.PRIVILEGE_EVALUATOR);
	}

	@EnableWebSecurity
	static class PrivilegeEvaluatorConfigurerAdapterConfig extends WebSecurityConfigurerAdapter {
		static WebInvocationPrivilegeEvaluator PRIVILEGE_EVALUATOR;

		@Override
		public void configure(WebSecurity web) throws Exception {
			web.privilegeEvaluator(PRIVILEGE_EVALUATOR);
		}
	}

	@Test
	public void loadConfigWhenSecurityExpressionHandlerSetThenIsRegistered() throws Exception {
		WebSecurityExpressionHandlerConfig.EXPRESSION_HANDLER = mock(SecurityExpressionHandler.class);
		when(WebSecurityExpressionHandlerConfig.EXPRESSION_HANDLER.getExpressionParser()).thenReturn(mock(ExpressionParser.class));

		this.spring.register(WebSecurityExpressionHandlerConfig.class).autowire();

		assertThat(this.spring.getContext().getBean(SecurityExpressionHandler.class))
			.isSameAs(WebSecurityExpressionHandlerConfig.EXPRESSION_HANDLER);
	}

	@EnableWebSecurity
	static class WebSecurityExpressionHandlerConfig extends WebSecurityConfigurerAdapter {
		static SecurityExpressionHandler EXPRESSION_HANDLER;

		@Override
		public void configure(WebSecurity web) throws Exception {
			web.expressionHandler(EXPRESSION_HANDLER);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.expressionHandler(EXPRESSION_HANDLER);
		}
	}

	@Test
	public void loadConfigWhenDefaultSecurityExpressionHandlerThenDefaultIsRegistered() throws Exception {
		this.spring.register(WebSecurityExpressionHandlerDefaultsConfig.class).autowire();

		assertThat(this.spring.getContext().getBean(SecurityExpressionHandler.class))
			.isInstanceOf(DefaultWebSecurityExpressionHandler.class);
	}

	@EnableWebSecurity
	static class WebSecurityExpressionHandlerDefaultsConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated();
		}
	}

	@Test
	public void securityExpressionHandlerWhenPermissionEvaluatorBeanThenPermissionEvaluatorUsed() throws Exception {
		this.spring.register(WebSecurityExpressionHandlerPermissionEvaluatorBeanConfig.class).autowire();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "notused");
		FilterInvocation invocation = new FilterInvocation(new MockHttpServletRequest("GET", ""), new MockHttpServletResponse(), new MockFilterChain());

		AbstractSecurityExpressionHandler handler = this.spring.getContext().getBean(AbstractSecurityExpressionHandler.class);
		EvaluationContext evaluationContext = handler.createEvaluationContext(authentication, invocation);
		Expression expression = handler.getExpressionParser()
				.parseExpression("hasPermission(#study,'DELETE')");
		boolean granted = expression.getValue(evaluationContext, Boolean.class);
		assertThat(granted).isTrue();
	}

	@EnableWebSecurity
	static class WebSecurityExpressionHandlerPermissionEvaluatorBeanConfig extends WebSecurityConfigurerAdapter {
		static final PermissionEvaluator PERMIT_ALL_PERMISSION_EVALUATOR = new PermissionEvaluator() {
			@Override
			public boolean hasPermission(Authentication authentication,
					Object targetDomainObject, Object permission) {
				return true;
			}

			@Override
			public boolean hasPermission(Authentication authentication,
					Serializable targetId, String targetType, Object permission) {
				return true;
			}
		};

		@Bean
		public PermissionEvaluator permissionEvaluator() {
			return PERMIT_ALL_PERMISSION_EVALUATOR;
		}
	}

	@Test
	public void loadConfigWhenDefaultWebInvocationPrivilegeEvaluatorThenDefaultIsRegistered() throws Exception {
		this.spring.register(WebInvocationPrivilegeEvaluatorDefaultsConfig.class).autowire();

		assertThat(this.spring.getContext().getBean(WebInvocationPrivilegeEvaluator.class))
			.isInstanceOf(DefaultWebInvocationPrivilegeEvaluator.class);
	}

	@EnableWebSecurity
	static class WebInvocationPrivilegeEvaluatorDefaultsConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated();
		}
	}

	// SEC-2303
	@Test
	public void loadConfigWhenDefaultSecurityExpressionHandlerThenBeanResolverSet() throws Exception {
		this.spring.register(DefaultExpressionHandlerSetsBeanResolverConfig.class).autowire();

		this.mockMvc.perform(get("/")).andExpect(status().isOk());
		this.mockMvc.perform(post("/")).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class DefaultExpressionHandlerSetsBeanResolverConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().access("request.method == 'GET' ? @b.grant() : @b.deny()");
		}

		@RestController
		public class HomeController {
			@GetMapping("/")
			public String home() {
				return "home";
			}
		}

		@Bean
		public MyBean b() {
			return new MyBean();
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

	@Rule
	public SpringTestRule child = new SpringTestRule();

	// SEC-2461
	@Test
	public void loadConfigWhenMultipleWebSecurityConfigurationThenContextLoads() throws Exception {
		this.spring.register(ParentConfig.class).autowire();

		this.child.register(ChildConfig.class);
		this.child.getContext().setParent(this.spring.getContext());
		this.child.autowire();

		assertThat(this.spring.getContext().getBean("springSecurityFilterChain")).isNotNull();
		assertThat(this.child.getContext().getBean("springSecurityFilterChain")).isNotNull();

		assertThat(this.spring.getContext().containsBean("springSecurityFilterChain")).isTrue();
		assertThat(this.child.getContext().containsBean("springSecurityFilterChain")).isTrue();
	}

	@EnableWebSecurity
	static class ParentConfig extends WebSecurityConfigurerAdapter {
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication();
		}
	}

	@EnableWebSecurity
	static class ChildConfig extends WebSecurityConfigurerAdapter {
	}

	// SEC-2773
	@Test
	public void getMethodDelegatingApplicationListenerWhenWebSecurityConfigurationThenIsStatic() throws Exception {
		Method method = ClassUtils.getMethod(WebSecurityConfiguration.class, "delegatingApplicationListener", null);
		assertThat(Modifier.isStatic(method.getModifiers())).isTrue();
	}
}
