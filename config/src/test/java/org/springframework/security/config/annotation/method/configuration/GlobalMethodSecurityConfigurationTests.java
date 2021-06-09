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

package org.springframework.security.config.annotation.method.configuration;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.aopalliance.intercept.MethodInterceptor;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.config.MockEventListener;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @author Artsiom Yudovin
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class GlobalMethodSecurityConfigurationTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired(required = false)
	private MethodSecurityService service;

	private AuthenticationManager authenticationManager;

	@Autowired
	public void setMethodInterceptor(MethodSecurityInterceptor interceptor) {
		this.authenticationManager = interceptor.getAuthenticationManager();
	}

	@Autowired(required = false)
	MockEventListener<AbstractAuthenticationEvent> events;

	@Test
	public void configureWhenGlobalMethodSecurityIsMissingMetadataSourceThenException() {
		assertThatExceptionOfType(UnsatisfiedDependencyException.class)
				.isThrownBy(() -> this.spring.register(IllegalStateGlobalMethodSecurityConfig.class).autowire());
	}

	@Test
	public void configureWhenGlobalMethodSecurityHasCustomMetadataSourceThenNoEnablingAttributeIsNeeded() {
		this.spring.register(CustomMetadataSourceConfig.class).autowire();
	}

	@Test
	public void methodSecurityAuthenticationManagerPublishesEvent() {
		this.spring.register(InMemoryAuthWithGlobalMethodSecurityConfig.class).autowire();
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(
				() -> this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("foo", "bar")));
		assertThat(this.events.getEvents()).extracting(Object::getClass)
				.containsOnly((Class) AuthenticationFailureBadCredentialsEvent.class);
	}

	@Test
	@WithMockUser
	public void methodSecurityWhenAuthenticationTrustResolverIsBeanThenAutowires() {
		this.spring.register(CustomTrustResolverConfig.class).autowire();
		AuthenticationTrustResolver trustResolver = this.spring.getContext().getBean(AuthenticationTrustResolver.class);
		given(trustResolver.isAnonymous(any())).willReturn(true, false);
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.service.preAuthorizeNotAnonymous());
		this.service.preAuthorizeNotAnonymous();
		verify(trustResolver, atLeastOnce()).isAnonymous(any());
	}

	// SEC-2301
	@Test
	@WithMockUser
	public void defaultWebSecurityExpressionHandlerHasBeanResolverSet() {
		this.spring.register(ExpressionHandlerHasBeanResolverSetConfig.class).autowire();
		Authz authz = this.spring.getContext().getBean(Authz.class);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.preAuthorizeBean(false));
		this.service.preAuthorizeBean(true);
	}

	@Test
	@WithMockUser
	public void methodSecuritySupportsAnnotaitonsOnInterfaceParamerNames() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.postAnnotation("deny"));
		this.service.postAnnotation("grant");
		// no exception
	}

	@Test
	@WithMockUser
	public void globalMethodSecurityConfigurationAutowiresPermissionEvaluator() {
		this.spring.register(AutowirePermissionEvaluatorConfig.class).autowire();
		PermissionEvaluator permission = this.spring.getContext().getBean(PermissionEvaluator.class);
		given(permission.hasPermission(any(), eq("something"), eq("read"))).willReturn(true, false);
		this.service.hasPermission("something");
		// no exception
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.service.hasPermission("something"));
	}

	@Test
	public void multiPermissionEvaluatorConfig() {
		this.spring.register(MultiPermissionEvaluatorConfig.class).autowire();
		// no exception
	}

	// SEC-2425
	@Test
	@WithMockUser
	public void enableGlobalMethodSecurityWorksOnSuperclass() {
		this.spring.register(ChildConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.preAuthorize());
	}

	// SEC-2479
	@Test
	@WithMockUser
	public void supportAuthenticationManagerInParent() {
		try (AnnotationConfigWebApplicationContext parent = new AnnotationConfigWebApplicationContext()) {
			parent.register(Sec2479ParentConfig.class);
			parent.refresh();
			try (AnnotationConfigWebApplicationContext child = new AnnotationConfigWebApplicationContext()) {
				child.setParent(parent);
				child.register(Sec2479ChildConfig.class);
				child.refresh();
				this.spring.context(child).autowire();
				assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.preAuthorize());
			}
		}
	}

	@Test
	public void enableGlobalMethodSecurityDoesNotTriggerEagerInitializationOfBeansInGlobalAuthenticationConfigurer() {
		this.spring.register(Sec2815Config.class).autowire();
		MockBeanPostProcessor pp = this.spring.getContext().getBean(MockBeanPostProcessor.class);
		assertThat(pp.beforeInit).containsKeys("dataSource");
		assertThat(pp.afterInit).containsKeys("dataSource");
	}

	// SEC-9845
	@Test
	public void enableGlobalMethodSecurityWhenBeanPostProcessorThenInvokedForDefaultMethodSecurityExpressionHandler() {
		this.spring.register(Sec9845Config.class).autowire();
		MockBeanPostProcessor pp = this.spring.getContext().getBean(MockBeanPostProcessor.class);
		assertThat(pp.beforeInitClass).containsKeys(DefaultMethodSecurityExpressionHandler.class);
		assertThat(pp.afterInitClass).containsKeys(DefaultMethodSecurityExpressionHandler.class);
	}

	// SEC-3045
	@Test
	public void globalSecurityProxiesSecurity() {
		this.spring.register(Sec3005Config.class).autowire();
		assertThat(this.service.getClass()).matches((c) -> !Proxy.isProxyClass(c), "is not proxy class");
	}

	//
	// // gh-3797
	// def preAuthorizeBeanSpel() {
	// setup:
	// SecurityContextHolder.getContext().setAuthentication(
	// new TestingAuthenticationToken("user", "password","ROLE_USER"))
	// context = new AnnotationConfigApplicationContext(PreAuthorizeBeanSpelConfig)
	// BeanSpelService service = context.getBean(BeanSpelService)
	// when:
	// service.run(true)
	// then:
	// noExceptionThrown()
	// when:
	// service.run(false)
	// then:
	// thrown(AccessDeniedException)
	// }
	//
	@Test
	@WithMockUser
	public void preAuthorizeBeanSpel() {
		this.spring.register(PreAuthorizeBeanSpelConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.preAuthorizeBean(false));
		this.service.preAuthorizeBean(true);
	}

	// gh-3394
	@Test
	@WithMockUser
	public void roleHierarchy() {
		this.spring.register(RoleHierarchyConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.preAuthorize());
		this.service.preAuthorizeAdmin();
	}

	@Test
	@WithMockUser(authorities = "ROLE:USER")
	public void grantedAuthorityDefaultsAutowires() {
		this.spring.register(CustomGrantedAuthorityConfig.class).autowire();
		CustomGrantedAuthorityConfig.CustomAuthorityService customService = this.spring.getContext()
				.getBean(CustomGrantedAuthorityConfig.CustomAuthorityService.class);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.preAuthorize());
		customService.customPrefixRoleUser();
		// no exception
	}

	@Test
	@WithMockUser(authorities = "USER")
	public void grantedAuthorityDefaultsWithEmptyRolePrefix() {
		this.spring.register(EmptyRolePrefixGrantedAuthorityConfig.class).autowire();
		EmptyRolePrefixGrantedAuthorityConfig.CustomAuthorityService customService = this.spring.getContext()
				.getBean(EmptyRolePrefixGrantedAuthorityConfig.CustomAuthorityService.class);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.service.securedUser());
		customService.emptyPrefixRoleUser();
		// no exception
	}

	@Test
	public void methodSecurityInterceptorUsesMetadataSourceBeanWhenProxyingDisabled() {
		this.spring.register(CustomMetadataSourceBeanProxyEnabledConfig.class).autowire();
		MethodSecurityInterceptor methodInterceptor = (MethodSecurityInterceptor) this.spring.getContext()
				.getBean(MethodInterceptor.class);
		MethodSecurityMetadataSource methodSecurityMetadataSource = this.spring.getContext()
				.getBean(MethodSecurityMetadataSource.class);
		assertThat(methodInterceptor.getSecurityMetadataSource()).isSameAs(methodSecurityMetadataSource);
	}

	@EnableGlobalMethodSecurity
	public static class IllegalStateGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	}

	@EnableGlobalMethodSecurity
	public static class CustomMetadataSourceConfig extends GlobalMethodSecurityConfiguration {

		@Bean
		@Override
		protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
			return mock(MethodSecurityMetadataSource.class);
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class InMemoryAuthWithGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
			.inMemoryAuthentication();
			// @formatter:on
		}

		@Bean
		public MockEventListener<AbstractAuthenticationEvent> listener() {
			return new MockEventListener<AbstractAuthenticationEvent>() {
			};
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class CustomTrustResolverConfig {

		@Bean
		AuthenticationTrustResolver trustResolver() {
			return mock(AuthenticationTrustResolver.class);
		}

		@Bean
		MethodSecurityServiceImpl service() {
			return new MethodSecurityServiceImpl();
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
	static class ExpressionHandlerHasBeanResolverSetConfig {

		@Bean
		MethodSecurityServiceImpl service() {
			return new MethodSecurityServiceImpl();
		}

		@Bean
		Authz authz() {
			return new Authz();
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class MethodSecurityServiceConfig {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class AutowirePermissionEvaluatorConfig {

		@Bean
		PermissionEvaluator permissionEvaluator() {
			return mock(PermissionEvaluator.class);
		}

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class MultiPermissionEvaluatorConfig {

		@Bean
		PermissionEvaluator permissionEvaluator() {
			return mock(PermissionEvaluator.class);
		}

		@Bean
		PermissionEvaluator permissionEvaluator2() {
			return mock(PermissionEvaluator.class);
		}

	}

	@Configuration
	static class ChildConfig extends ParentConfig {

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class ParentConfig {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

	}

	@Configuration
	static class Sec2479ParentConfig {

		@Bean
		AuthenticationManager am() {
			return mock(AuthenticationManager.class);
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec2479ChildConfig {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec2815Config {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

		@Bean
		MockBeanPostProcessor mockBeanPostProcessor() {
			return new MockBeanPostProcessor();
		}

		@Bean
		DataSource dataSource() {
			return mock(DataSource.class);
		}

		@Configuration
		static class AuthConfig extends GlobalAuthenticationConfigurerAdapter {

			@Autowired
			DataSource dataSource;

			@Override
			public void init(AuthenticationManagerBuilder auth) throws Exception {
				auth.inMemoryAuthentication();
			}

		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec9845Config {

		@Bean
		BeanPostProcessor mockBeanPostProcessor() {
			return new MockBeanPostProcessor();
		}

	}

	static class MockBeanPostProcessor implements BeanPostProcessor {

		Map<String, Object> beforeInit = new HashMap<>();

		Map<String, Object> afterInit = new HashMap<>();

		Map<Class<?>, Object> beforeInitClass = new HashMap<>();

		Map<Class<?>, Object> afterInitClass = new HashMap<>();

		@Override
		public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
			this.beforeInit.put(beanName, bean);
			this.beforeInitClass.put(bean.getClass(), bean);
			return bean;
		}

		@Override
		public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
			this.afterInit.put(beanName, bean);
			this.afterInitClass.put(bean.getClass(), bean);
			return bean;
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true, mode = AdviceMode.ASPECTJ)
	@EnableTransactionManagement
	static class Sec3005Config {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication();
		}

	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class PreAuthorizeBeanSpelConfig {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

		@Bean
		Authz authz() {
			return new Authz();
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Configuration
	public static class RoleHierarchyConfig {

		@Bean
		MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

		@Bean
		RoleHierarchy roleHierarchy() {
			RoleHierarchyImpl result = new RoleHierarchyImpl();
			result.setHierarchy("ROLE_USER > ROLE_ADMIN");
			return result;
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class CustomGrantedAuthorityConfig {

		@Bean
		GrantedAuthorityDefaults ga() {
			return new GrantedAuthorityDefaults("ROLE:");
		}

		@Bean
		CustomAuthorityService service() {
			return new CustomAuthorityService();
		}

		@Bean
		MethodSecurityServiceImpl methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

		static class CustomAuthorityService {

			@PreAuthorize("hasRole('ROLE:USER')")
			void customPrefixRoleUser() {
			}

		}

	}

	@EnableGlobalMethodSecurity(securedEnabled = true)
	static class EmptyRolePrefixGrantedAuthorityConfig {

		@Bean
		GrantedAuthorityDefaults ga() {
			return new GrantedAuthorityDefaults("");
		}

		@Bean
		CustomAuthorityService service() {
			return new CustomAuthorityService();
		}

		@Bean
		MethodSecurityServiceImpl methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

		static class CustomAuthorityService {

			@Secured("USER")
			void emptyPrefixRoleUser() {
			}

		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Configuration
	public static class CustomMetadataSourceBeanProxyEnabledConfig extends GlobalMethodSecurityConfiguration {

	}

}
