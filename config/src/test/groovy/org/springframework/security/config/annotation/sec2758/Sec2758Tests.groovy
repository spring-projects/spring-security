/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.sec2758;

import javax.annotation.security.RolesAllowed;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.PriorityOrdered;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.sec2377.a.*
import org.springframework.security.config.annotation.web.configuration.sec2377.b.*
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext

public class Sec2758Tests extends BaseSpringSpec {

	def cleanup() {
		SecurityContextHolder.clearContext()
	}

	def "SEC-2758: Verify Passivity Restored with Advice from JIRA"() {
		setup:
		SecurityContextHolder.context.authentication = new TestingAuthenticationToken("user", "pass", "USER")
		loadConfig(SecurityConfig)
		Service service = context.getBean(Service)

		when:
		findFilter(FilterSecurityInterceptor).doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain())
		then:
		noExceptionThrown()

		when:
		service.doPreAuthorize()
		then:
		noExceptionThrown()

		when:
		service.doJsr250()
		then:
		noExceptionThrown()
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled=true)
	static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().hasAnyAuthority("USER");
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").authorities("USER")
		}

		@Bean
		Service service() {
			return new ServiceImpl()
		}

		@Bean
		static DefaultRolesPrefixPostProcessor defaultRolesPrefixPostProcessor() {
			new DefaultRolesPrefixPostProcessor()
		}
	}

	interface Service {
		void doPreAuthorize()
		void doJsr250()
	}

	static class ServiceImpl implements Service {
		@PreAuthorize("hasRole('USER')")
		void doPreAuthorize() {}

		@RolesAllowed("USER")
		void doJsr250() {}
	}

	static class DefaultRolesPrefixPostProcessor implements BeanPostProcessor, PriorityOrdered {

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName)
			throws BeansException {
		if(bean instanceof Jsr250MethodSecurityMetadataSource) {
			((Jsr250MethodSecurityMetadataSource) bean).setDefaultRolePrefix(null);
		}
		if(bean instanceof DefaultMethodSecurityExpressionHandler) {
			((DefaultMethodSecurityExpressionHandler) bean).setDefaultRolePrefix(null);
		}
		if(bean instanceof DefaultWebSecurityExpressionHandler) {
			((DefaultWebSecurityExpressionHandler) bean).setDefaultRolePrefix(null);
		}
		return bean;
	}

	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName)
			throws BeansException {
		return bean;
	}

	@Override
	public int getOrder() {
		return PriorityOrdered.HIGHEST_PRECEDENCE;
	}
}
}
