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
package org.springframework.security.config.annotation.method.configuration


import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl

import java.lang.reflect.Proxy;

import org.junit.After;
import org.springframework.beans.BeansException
import org.springframework.beans.factory.config.BeanPostProcessor
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter
import org.springframework.security.config.annotation.method.configuration.NamespaceGlobalMethodSecurityTests.BaseMethodConfig;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.core.GrantedAuthorityDefaults;

import javax.sql.DataSource

import static org.assertj.core.api.Assertions.*
import static org.junit.Assert.fail

import org.aopalliance.intercept.MethodInterceptor
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.AdviceMode
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.PermissionEvaluator
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.method.TestPermissionEvaluator;
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 *
 * @author Rob Winch
 */
public class GlobalMethodSecurityConfigurationTests extends BaseSpringSpec {
	def "messages set when using GlobalMethodSecurityConfiguration"() {
		when:
			loadConfig(InMemoryAuthWithGlobalMethodSecurityConfig)
		then:
			authenticationManager.messages.messageSource instanceof ApplicationContext
	}

	def "AuthenticationEventPublisher is registered GlobalMethodSecurityConfiguration"() {
		when:
			loadConfig(InMemoryAuthWithGlobalMethodSecurityConfig)
		then:
			authenticationManager.eventPublisher instanceof DefaultAuthenticationEventPublisher
		when:
			Authentication auth = new UsernamePasswordAuthenticationToken("user",null,AuthorityUtils.createAuthorityList("ROLE_USER"))
			authenticationManager.eventPublisher.publishAuthenticationSuccess(auth)
		then:
			InMemoryAuthWithGlobalMethodSecurityConfig.EVENT.authentication == auth
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class InMemoryAuthWithGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration implements ApplicationListener<AuthenticationSuccessEvent> {
		static AuthenticationSuccessEvent EVENT

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Override
		public void onApplicationEvent(AuthenticationSuccessEvent e) {
			EVENT = e
		}
	}

	AuthenticationManager getAuthenticationManager() {
		context.getBean(MethodInterceptor).authenticationManager
	}

	def "AuthenticationTrustResolver autowires"() {
		setup:
			CustomTrustResolverConfig.TR = Mock(AuthenticationTrustResolver)
		when:
			loadConfig(CustomTrustResolverConfig)
			def preAdviceVoter = context.getBean(MethodInterceptor).accessDecisionManager.decisionVoters.find { it instanceof PreInvocationAuthorizationAdviceVoter}
		then:
			preAdviceVoter.preAdvice.expressionHandler.trustResolver == CustomTrustResolverConfig.TR
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class CustomTrustResolverConfig extends GlobalMethodSecurityConfiguration {
		static AuthenticationTrustResolver TR

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public AuthenticationTrustResolver tr() {
			return TR
		}
	}

	def "SEC-2301: DefaultWebSecurityExpressionHandler has BeanResolver set"() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			loadConfig(ExpressionHandlerHasBeanResolverSetConfig)
			def service = context.getBean(ServiceImpl)
		when: "service with bean reference on PreAuthorize invoked"
			service.message()
		then: "properly throws AccessDeniedException"
			thrown(AccessDeniedException)
		when: "service with bean reference on PreAuthorize invoked"
			context.getBean(CustomAuthzService).grantAccess = true
			service.message()
		then: "grants access too"
			noExceptionThrown()
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
	static class ExpressionHandlerHasBeanResolverSetConfig extends GlobalMethodSecurityConfiguration {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public ServiceImpl service() {
			return new ServiceImpl()
		}

		@Bean
		public CustomAuthzService authz() {
			return new CustomAuthzService()
		}
	}

	static class ServiceImpl {
		@PreAuthorize("@authz.authorize()")
		public String message() {
			null
		}
	}

	static class CustomAuthzService {
		boolean grantAccess

		public boolean authorize() {
			grantAccess
		}
	}

	def "Method Security supports annotations on interface parameter names"() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			loadConfig(MethodSecurityServiceConfig)
			MethodSecurityService service = context.getBean(MethodSecurityService)
		when: "service with annotated argument"
			service.postAnnotation('deny')
		then: "properly throws AccessDeniedException"
			thrown(AccessDeniedException)
		when: "service with annotated argument"
			service.postAnnotation('grant')
		then: "properly throws AccessDeniedException"
			noExceptionThrown()
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class MethodSecurityServiceConfig extends GlobalMethodSecurityConfiguration {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}
	}

	def "GlobalMethodSecurityConfiguration autowires PermissionEvaluator"() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			PermissionEvaluator evaluator = Mock()
			AutowirePermissionEvaluatorConfig.PE = evaluator
			loadConfig(AutowirePermissionEvaluatorConfig)
			MethodSecurityService service = context.getBean(MethodSecurityService)
		when:
			service.hasPermission("something")
		then:
			1 * evaluator.hasPermission(_, "something", "read") >> true
		when:
			service.hasPermission("something")
		then:
			1 * evaluator.hasPermission(_, "something", "read") >> false
			thrown(AccessDeniedException)
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class AutowirePermissionEvaluatorConfig extends GlobalMethodSecurityConfiguration {
		static PermissionEvaluator PE

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public PermissionEvaluator pe() {
			PE
		}

		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}
	}

	def "GlobalMethodSecurityConfiguration does not failw with multiple PermissionEvaluator"() {
		when:
			loadConfig(MultiPermissionEvaluatorConfig)
		then:
			noExceptionThrown()
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class MultiPermissionEvaluatorConfig extends GlobalMethodSecurityConfiguration {
		static PermissionEvaluator PE = new TestPermissionEvaluator()

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public PermissionEvaluator pe() {
			PE
		}

		@Bean
		public PermissionEvaluator pe2() {
			PE
		}

		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}
	}

	def "SEC-2425: EnableGlobalMethodSecurity works on superclass"() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			loadConfig(ParentConfig)
			MethodSecurityService service = context.getBean(MethodSecurityService)
		when:
			service.preAuthorize()
		then:
			thrown(AccessDeniedException)
	}

	static class ChildConfig extends ParentConfig {}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class ParentConfig {

		@Autowired
		protected void configurGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}
	}

	def "SEC-2479: Support AuthenticationManager in parent"() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			loadConfig(Sec2479ParentConfig)
			def child = new AnnotationConfigApplicationContext()
			child.register(Sec2479ChildConfig)
			child.parent = context
			child.refresh()
			MethodSecurityService service = child.getBean(MethodSecurityService)
		when:
			service.preAuthorize()
		then:
			thrown(AccessDeniedException)
		cleanup:
			child?.close()
	}

	@Configuration
	static class Sec2479ParentConfig {
		static AuthenticationManager AM

		@Bean
		public AuthenticationManager am() {
			AM
		}
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec2479ChildConfig {
		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}
	}

	def "SEC-2815: @EnableGlobalMethodSecurity does not trigger eager initialization of Beans in GlobalAuthenticationConfigurer"() {
		setup:
		Sec2815Config.dataSource = Mock(DataSource)
		when: 'load a Configuration that uses a Bean (DataSource) in a GlobalAuthenticationConfigurerAdapter'
		loadConfig(Sec2815Config)
		then: 'The Bean (DataSource) is still properly post processed with all BeanPostProcessor'
		context.getBean(MockBeanPostProcessor).beforeInit['dataSource']
		context.getBean(MockBeanPostProcessor).afterInit['dataSource']
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec2815Config {
		static DataSource dataSource;

		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}

		@Bean
		public MockBeanPostProcessor mockBeanPostProcessor() {
			new MockBeanPostProcessor()
		}

		@Bean
		public DataSource dataSource() {
			dataSource
		}

		@Configuration
		static class AuthConfig extends GlobalAuthenticationConfigurerAdapter {
			@Autowired
			DataSource dataSource

			@Override
			void init(AuthenticationManagerBuilder auth) throws Exception {
				auth.inMemoryAuthentication()
			}
		}
	}


	static class MockBeanPostProcessor implements BeanPostProcessor {
		Map<String,Object> beforeInit = new HashMap<String,Object>()
		Map<String,Object> afterInit = new HashMap<String,Object>()

		@Override
		Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
			beforeInit[beanName] = bean
			bean
		}

		@Override
		Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
			afterInit[beanName] = bean
			bean
		}
	}

	def "SEC-3045: Global Security proxies security"() {
		setup:
		when: 'load a Configuration that uses a Bean (DataSource) in a GlobalAuthenticationConfigurerAdapter'
		loadConfig(Sec3005Config)
		MethodSecurityService service = context.getBean(MethodSecurityService)
		then: 'The Bean (DataSource) is still properly post processed with all BeanPostProcessor'
		!Proxy.isProxyClass(service.getClass())
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true, mode= AdviceMode.ASPECTJ)
	@EnableTransactionManagement
	static class Sec3005Config {
		static DataSource dataSource;

		@Bean
		public MethodSecurityService service() {
			new MethodSecurityServiceImpl()
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) {
			auth.inMemoryAuthentication()
		}
	}

	// gh-3797
	def preAuthorizeBeanSpel() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			context = new AnnotationConfigApplicationContext(PreAuthorizeBeanSpelConfig)
			BeanSpelService service = context.getBean(BeanSpelService)
		when:
			service.run(true)
		then:
			noExceptionThrown()
		when:
			service.run(false)
		then:
			thrown(AccessDeniedException)
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Configuration
	public static class PreAuthorizeBeanSpelConfig extends BaseMethodConfig {
		@Bean
		BeanSpelService service() {
			return new BeanSpelService();
		}
		@Bean
		BeanSpelSecurity security() {
			return new BeanSpelSecurity();
		}
	}

	static class BeanSpelService {
		@PreAuthorize("@security.check(#arg)")
		void run(boolean arg) {}
	}

	static class BeanSpelSecurity {
		public boolean check(boolean arg) {
			return arg;
		}
	}

	// gh-3394
	def roleHierarchy() {
		setup:
			SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password","ROLE_USER"))
			context = new AnnotationConfigApplicationContext(RoleHierarchyConfig)
			MethodSecurityService service = context.getBean(MethodSecurityService)
		when:
			service.preAuthorizeAdmin()
		then:
			noExceptionThrown()
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Configuration
	public static class RoleHierarchyConfig extends BaseMethodConfig {
		@Bean
		RoleHierarchy roleHierarchy() {
			return new RoleHierarchyImpl(hierarchy:"ROLE_USER > ROLE_ADMIN")
		}
	}

	def "GrantedAuthorityDefaults autowires"() {
		when:
			loadConfig(CustomGrantedAuthorityConfig)
			def preAdviceVoter = context.getBean(MethodInterceptor).accessDecisionManager.decisionVoters.find { it instanceof PreInvocationAuthorizationAdviceVoter}
		then:
		preAdviceVoter.preAdvice.expressionHandler.defaultRolePrefix == "ROLE:"
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class CustomGrantedAuthorityConfig extends GlobalMethodSecurityConfiguration {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
		}

		@Bean
		public GrantedAuthorityDefaults ga() {
			return new GrantedAuthorityDefaults("ROLE:")
		}
	}
}
