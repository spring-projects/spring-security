/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration

import java.lang.reflect.Modifier

import static org.junit.Assert.*

import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.expression.ExpressionParser
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.access.expression.SecurityExpressionHandler
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurationTests.DuplicateOrderConfig;
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.test.util.ReflectionTestUtils

/**
 * @author Rob Winch
 *
 */
class WebSecurityConfigurationTests extends BaseSpringSpec {

	def "WebSecurityConfigurers are sorted"() {
		when:
			loadConfig(SortedWebSecurityConfigurerAdaptersConfig);
			List<SecurityFilterChain> filterChains = context.getBean(FilterChainProxy).filterChains
		then:
			filterChains[0].requestMatcher.pattern == "/ignore1"
			filterChains[0].filters.empty
			filterChains[1].requestMatcher.pattern == "/ignore2"
			filterChains[1].filters.empty

			filterChains[2].requestMatcher.pattern == "/role1/**"
			filterChains[3].requestMatcher.pattern == "/role2/**"
			filterChains[4].requestMatcher.pattern == "/role3/**"
			filterChains[5].requestMatcher.class == AnyRequestMatcher
	}


	@EnableWebSecurity
	static class SortedWebSecurityConfigurerAdaptersConfig {
		public AuthenticationManager authenticationManager() throws Exception {
			return new AuthenticationManagerBuilder()
				.inMemoryAuthentication()
					.withUser("marissa").password("koala").roles("USER").and()
					.withUser("paul").password("emu").roles("USER").and()
					.and()
				.build();
		}

		@Configuration
		@Order(1)
		public static class WebConfigurer1 extends WebSecurityConfigurerAdapter {
			@Override
			public void configure(WebSecurity web)	throws Exception {
				web
					.ignoring()
						.antMatchers("/ignore1","/ignore2");
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
		public static class WebConfigurer2 extends WebSecurityConfigurerAdapter {
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
		public static class WebConfigurer3 extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role3/**")
					.authorizeRequests()
						.anyRequest().hasRole("3");
			}
		}

		@Configuration
		public static class WebConfigurer4 extends WebSecurityConfigurerAdapter {

			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.authorizeRequests()
						.anyRequest().hasRole("4");
			}
		}
	}

	def "WebSecurityConfigurers fails with duplicate order"() {
		when:
			loadConfig(DuplicateOrderConfig);
		then:
			BeanCreationException e = thrown()
			e.message.contains "@Order on WebSecurityConfigurers must be unique"
			e.message.contains DuplicateOrderConfig.WebConfigurer1.class.name
			e.message.contains DuplicateOrderConfig.WebConfigurer2.class.name
	}


	@EnableWebSecurity
	static class DuplicateOrderConfig {
		public AuthenticationManager authenticationManager() throws Exception {
			return new AuthenticationManagerBuilder()
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER").and()
					.and()
				.build();
		}

		@Configuration
		public static class WebConfigurer1 extends WebSecurityConfigurerAdapter {

			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role1/**")
					.authorizeRequests()
						.anyRequest().hasRole("1");
			}
		}

		@Configuration
		public static class WebConfigurer2 extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
					.antMatcher("/role2/**")
					.authorizeRequests()
						.anyRequest().hasRole("2");
			}
		}
	}

	def "Override privilegeEvaluator"() {
		setup:
			WebInvocationPrivilegeEvaluator privilegeEvaluator = Mock()
			PrivilegeEvaluatorConfigurerAdapterConfig.PE = privilegeEvaluator
		when:
			loadConfig(PrivilegeEvaluatorConfigurerAdapterConfig)
		then:
			context.getBean(WebInvocationPrivilegeEvaluator) == privilegeEvaluator
	}

	@EnableWebSecurity
	static class PrivilegeEvaluatorConfigurerAdapterConfig extends WebSecurityConfigurerAdapter {
		static WebInvocationPrivilegeEvaluator PE

		@Override
		public void configure(WebSecurity web) throws Exception {
			web
				.privilegeEvaluator(PE)
		}
	}

	def "Override webSecurityExpressionHandler"() {
		setup:
			SecurityExpressionHandler expressionHandler = Mock()
			ExpressionParser parser = Mock()
			WebSecurityExpressionHandlerConfig.EH = expressionHandler
		when:
			loadConfig(WebSecurityExpressionHandlerConfig)
		then:
			context.getBean(SecurityExpressionHandler) == expressionHandler
			1 * expressionHandler.getExpressionParser() >> parser
	}

	@EnableWebSecurity
	static class WebSecurityExpressionHandlerConfig extends WebSecurityConfigurerAdapter {
		static SecurityExpressionHandler EH

		@Override
		public void configure(WebSecurity web) throws Exception {
			web
				.expressionHandler(EH)
		}
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.expressionHandler(EH)
					.anyRequest().authenticated()
		}
	}

	def "#138 webSecurityExpressionHandler defaults"() {
		when:
			loadConfig(WebSecurityExpressionHandlerDefaultsConfig)
		then:
			SecurityExpressionHandler wseh = context.getBean(SecurityExpressionHandler)
			wseh instanceof DefaultWebSecurityExpressionHandler
	}

	@EnableWebSecurity
	static class WebSecurityExpressionHandlerDefaultsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
		}
	}

	def "#138 WebInvocationPrivilegeEvaluator defaults"() {
		when:
			loadConfig(WebInvocationPrivilegeEvaluatorDefaultsConfig)
		then:
			WebInvocationPrivilegeEvaluator wipe = context.getBean(WebInvocationPrivilegeEvaluator)
			wipe instanceof DefaultWebInvocationPrivilegeEvaluator
			wipe.securityInterceptor != null
	}

	@EnableWebSecurity
	static class WebInvocationPrivilegeEvaluatorDefaultsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
		}
	}

	def "SEC-2303: DefaultExpressionHandler has bean resolver set"() {
		when:
			loadConfig(DefaultExpressionHandlerSetsBeanResolverConfig)
		then: "the exposed bean has a BeanResolver set"
			ReflectionTestUtils.getField(context.getBean(SecurityExpressionHandler),"br")
		when:
			springSecurityFilterChain.doFilter(request, response, chain)
		then: "we can use the BeanResolver with a grant"
			noExceptionThrown()
		when: "we can use the Beanresolver with a deny"
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(method:'POST'), response, chain)
		then:
			noExceptionThrown()
	}

	@EnableWebSecurity
	static class DefaultExpressionHandlerSetsBeanResolverConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().access("request.method == 'GET' ? @b.grant() : @b.deny()")
		}

		@Bean
		public MyBean b() {
			new MyBean()
		}

		static class MyBean {
			boolean deny() {
				false
			}

			boolean grant() {
				true
			}
		}
	}

	def "SEC-2461: Multiple WebSecurityConfiguration instances cause null springSecurityFilterChain"() {
		setup:
			def parent = loadConfig(ParentConfig)
			def child = new AnnotationConfigApplicationContext()
			child.register(ChildConfig)
			child.parent = parent
		when:
			child.refresh()
		then: "springSecurityFilterChain can be found in parent and child"
			parent.getBean("springSecurityFilterChain")
			child.getBean("springSecurityFilterChain")
		and: "springSecurityFilterChain is defined in both parent and child (don't search parent)"
			parent.containsBeanDefinition("springSecurityFilterChain")
			child.containsBeanDefinition("springSecurityFilterChain")
		cleanup:
			child?.close()
			// parent.close() is in superclass
	}

	@EnableWebSecurity
	static class ParentConfig extends WebSecurityConfigurerAdapter {
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) {
			auth.inMemoryAuthentication()
		}
	}

	@EnableWebSecurity
	static class ChildConfig extends WebSecurityConfigurerAdapter { }

	def "SEC-2773: delegatingApplicationListener is static method"() {
		expect: 'delegatingApplicationListener to prevent premature instantiation of WebSecurityConfiguration'
		Modifier.isStatic(WebSecurityConfiguration.metaClass.methods.find { it.name == 'delegatingApplicationListener'}.modifiers)
	}
}
