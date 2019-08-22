/*
 * Copyright 2002-2019 the original author or authors.
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
import org.junit.rules.ExpectedException;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 * @author Rob Winch
 * @author Artsiom Yudovin
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class GlobalMethodSecurityConfigurationTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

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
		this.thrown.expect(UnsatisfiedDependencyException.class);
		this.spring.register(IllegalStateGlobalMethodSecurityConfig.class).autowire();
	}

	@EnableGlobalMethodSecurity
	public static class IllegalStateGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	}

	@Test
	public void configureWhenGlobalMethodSecurityHasCustomMetadataSourceThenNoEnablingAttributeIsNeeded() {
		this.spring.register(CustomMetadataSourceConfig.class).autowire();
	}

	@EnableGlobalMethodSecurity
	public static class CustomMetadataSourceConfig extends GlobalMethodSecurityConfiguration {
		@Bean
		@Override
		protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
			return mock(MethodSecurityMetadataSource.class);
		}
	}

	@Test
	public void methodSecurityAuthenticationManagerPublishesEvent() {
		this.spring.register(InMemoryAuthWithGlobalMethodSecurityConfig.class).autowire();

		try {
			this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("foo", "bar"));
		} catch(AuthenticationException e) {}

		assertThat(this.events.getEvents()).extracting(Object::getClass).containsOnly((Class) AuthenticationFailureBadCredentialsEvent.class);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class InMemoryAuthWithGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration {
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication();
		}

		@Bean
		public MockEventListener<AbstractAuthenticationEvent> listener() {
			return new MockEventListener<AbstractAuthenticationEvent>() {};
		}
	}

	@Test
	@WithMockUser
	public void methodSecurityWhenAuthenticationTrustResolverIsBeanThenAutowires() {
		this.spring.register(CustomTrustResolverConfig.class).autowire();

		AuthenticationTrustResolver trustResolver = this.spring.getContext().getBean(AuthenticationTrustResolver.class);
		when(trustResolver.isAnonymous(any())).thenReturn(true, false);

		assertThatThrownBy(() -> this.service.preAuthorizeNotAnonymous())
			.isInstanceOf(AccessDeniedException.class);

		this.service.preAuthorizeNotAnonymous();

		verify(trustResolver, atLeastOnce()).isAnonymous(any());
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class CustomTrustResolverConfig {

		@Bean
		public AuthenticationTrustResolver trustResolver() {
			return mock(AuthenticationTrustResolver.class);
		}

		@Bean
		public MethodSecurityServiceImpl service() {
			return new MethodSecurityServiceImpl();
		}
	}

	// SEC-2301
	@Test
	@WithMockUser
	public void defaultWebSecurityExpressionHandlerHasBeanResolverSet() {
		this.spring.register(ExpressionHandlerHasBeanResolverSetConfig.class).autowire();
		Authz authz = this.spring.getContext().getBean(Authz.class);

		assertThatThrownBy(() -> this.service.preAuthorizeBean(false))
			.isInstanceOf(AccessDeniedException.class);

		this.service.preAuthorizeBean(true);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
	static class ExpressionHandlerHasBeanResolverSetConfig {

		@Bean
		public MethodSecurityServiceImpl service() {
			return new MethodSecurityServiceImpl();
		}

		@Bean
		public Authz authz() {
			return new Authz();
		}
	}

	@Test
	@WithMockUser
	public void methodSecuritySupportsAnnotaitonsOnInterfaceParamerNames() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();

		assertThatThrownBy(() -> this.service.postAnnotation("deny"))
			.isInstanceOf(AccessDeniedException.class);

		this.service.postAnnotation("grant");
		// no exception
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class MethodSecurityServiceConfig {

		@Bean
		public MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}
	}

	@Test
	@WithMockUser
	public void globalMethodSecurityConfigurationAutowiresPermissionEvaluator() {
		this.spring.register(AutowirePermissionEvaluatorConfig.class).autowire();
		PermissionEvaluator permission = this.spring.getContext().getBean(PermissionEvaluator.class);
		when(permission.hasPermission(any(), eq("something"), eq("read"))).thenReturn(true, false);

		this.service.hasPermission("something");
		// no exception

		assertThatThrownBy(() -> this.service.hasPermission("something"))
			.isInstanceOf(AccessDeniedException.class);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class AutowirePermissionEvaluatorConfig {

		@Bean
		public PermissionEvaluator permissionEvaluator() {
			return mock(PermissionEvaluator.class);
		}

		@Bean
		public MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}
	}

	@Test
	public void multiPermissionEvaluatorConfig() {
		this.spring.register(MultiPermissionEvaluatorConfig.class).autowire();

		// no exception
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class MultiPermissionEvaluatorConfig {

		@Bean
		public PermissionEvaluator permissionEvaluator() {
			return mock(PermissionEvaluator.class);
		}

		@Bean
		public PermissionEvaluator permissionEvaluator2() {
			return mock(PermissionEvaluator.class);
		}
	}

	// SEC-2425
	@Test
	@WithMockUser
	public void enableGlobalMethodSecurityWorksOnSuperclass() {
		this.spring.register(ChildConfig.class).autowire();

		assertThatThrownBy(() -> this.service.preAuthorize())
			.isInstanceOf(AccessDeniedException.class);
	}

	@Configuration
	static class ChildConfig extends ParentConfig {}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class ParentConfig {

		@Bean
		public MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}
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

				assertThatThrownBy(() -> this.service.preAuthorize())
					.isInstanceOf(AccessDeniedException.class);
			}
		}
	}

	@Configuration
	static class Sec2479ParentConfig {
		@Bean
		public AuthenticationManager am() {
			return mock(AuthenticationManager.class);
		}
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec2479ChildConfig {
		@Bean
		public MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}
	}

	@Test
	public void enableGlobalMethodSecurityDoesNotTriggerEagerInitializationOfBeansInGlobalAuthenticationConfigurer() {
		this.spring.register(Sec2815Config.class).autowire();

		MockBeanPostProcessor pp = this.spring.getContext().getBean(MockBeanPostProcessor.class);

		assertThat(pp.beforeInit).containsKeys("dataSource");
		assertThat(pp.afterInit).containsKeys("dataSource");
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class Sec2815Config {
		@Bean
		public MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

		@Bean
		public MockBeanPostProcessor mockBeanPostProcessor() {
			return new MockBeanPostProcessor();
		}

		@Bean
		public DataSource dataSource() {
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

	static class MockBeanPostProcessor implements BeanPostProcessor {
		Map<String, Object> beforeInit = new HashMap<>();
		Map<String, Object> afterInit = new HashMap<>();

		@Override
		public Object postProcessBeforeInitialization(Object bean, String beanName) throws
			BeansException {
			this.beforeInit.put(beanName, bean);
			return bean;
		}

		@Override
		public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
			this.afterInit.put(beanName, bean);
			return bean;
		}
	}

	// SEC-3045
	@Test
	public void globalSecurityProxiesSecurity() {
		this.spring.register(Sec3005Config.class).autowire();

		assertThat(this.service.getClass()).matches(c-> !Proxy.isProxyClass(c), "is not proxy class");
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true, mode= AdviceMode.ASPECTJ)
	@EnableTransactionManagement
	static class Sec3005Config {
		@Bean
		public MethodSecurityService service() {
			return new MethodSecurityServiceImpl();
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication();
		}
	}

	//
	//	// gh-3797
	//	def preAuthorizeBeanSpel() {
	//		setup:
	//			SecurityContextHolder.getContext().setAuthentication(
	//				new TestingAuthenticationToken("user", "password","ROLE_USER"))
	//			context = new AnnotationConfigApplicationContext(PreAuthorizeBeanSpelConfig)
	//			BeanSpelService service = context.getBean(BeanSpelService)
	//		when:
	//			service.run(true)
	//		then:
	//			noExceptionThrown()
	//		when:
	//			service.run(false)
	//		then:
	//			thrown(AccessDeniedException)
	//	}
	//

	@Test
	@WithMockUser
	public void preAuthorizeBeanSpel() {
		this.spring.register(PreAuthorizeBeanSpelConfig.class).autowire();

		assertThatThrownBy(() -> this.service.preAuthorizeBean(false))
			.isInstanceOf(AccessDeniedException.class);

		this.service.preAuthorizeBean(true);
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

	// gh-3394
	@Test
	@WithMockUser
	public void roleHierarchy() {
		this.spring.register(RoleHierarchyConfig.class).autowire();

		assertThatThrownBy(() -> this.service.preAuthorize())
			.isInstanceOf(AccessDeniedException.class);
		this.service.preAuthorizeAdmin();
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

	@Test
	@WithMockUser(authorities = "ROLE:USER")
	public void grantedAuthorityDefaultsAutowires() {
		this.spring.register(CustomGrantedAuthorityConfig.class).autowire();

		CustomGrantedAuthorityConfig.CustomAuthorityService customService = this.spring.getContext().getBean(
			CustomGrantedAuthorityConfig.CustomAuthorityService.class);

		assertThatThrownBy(() -> this.service.preAuthorize())
			.isInstanceOf(AccessDeniedException.class);

		customService.customPrefixRoleUser();
		// no exception
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class CustomGrantedAuthorityConfig {

		@Bean
		public GrantedAuthorityDefaults ga() {
			return new GrantedAuthorityDefaults("ROLE:");
		}

		@Bean
		public CustomAuthorityService service() {
			return new CustomAuthorityService();
		}

		@Bean
		public MethodSecurityServiceImpl methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

		static class CustomAuthorityService {
			@PreAuthorize("hasRole('ROLE:USER')")
			public void customPrefixRoleUser() {}
		}
	}

	@Test
	@WithMockUser(authorities = "USER")
	public void grantedAuthorityDefaultsWithEmptyRolePrefix() {
		this.spring.register(EmptyRolePrefixGrantedAuthorityConfig.class).autowire();

		EmptyRolePrefixGrantedAuthorityConfig.CustomAuthorityService customService = this.spring.getContext()
				.getBean(EmptyRolePrefixGrantedAuthorityConfig.CustomAuthorityService.class);

		assertThatThrownBy(() -> this.service.securedUser())
				.isInstanceOf(AccessDeniedException.class);

		customService.emptyPrefixRoleUser();
		// no exception
	}

	@EnableGlobalMethodSecurity(securedEnabled = true)
	static class EmptyRolePrefixGrantedAuthorityConfig {
		@Bean
		public GrantedAuthorityDefaults ga() {
			return new GrantedAuthorityDefaults("");
		}

		@Bean
		public CustomAuthorityService service() {
			return new CustomAuthorityService();
		}

		@Bean
		public MethodSecurityServiceImpl methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

		static class CustomAuthorityService {
			@Secured("USER")
			public void emptyPrefixRoleUser() {}
		}
	}

	@Test
	public void methodSecurityInterceptorUsesMetadataSourceBeanWhenProxyingDisabled() {
		this.spring.register(CustomMetadataSourceBeanProxyEnabledConfig.class).autowire();
		MethodSecurityInterceptor methodInterceptor =
				(MethodSecurityInterceptor) this.spring.getContext().getBean(MethodInterceptor.class);
		MethodSecurityMetadataSource methodSecurityMetadataSource =
				this.spring.getContext().getBean(MethodSecurityMetadataSource.class);

		assertThat(methodInterceptor.getSecurityMetadataSource()).isSameAs(methodSecurityMetadataSource);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Configuration
	public static class CustomMetadataSourceBeanProxyEnabledConfig extends GlobalMethodSecurityConfiguration {
	}
}
