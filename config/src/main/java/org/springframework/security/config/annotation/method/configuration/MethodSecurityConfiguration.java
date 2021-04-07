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

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerMethodAfterAdvice;
import org.springframework.security.authorization.method.AuthorizationManagerMethodBeforeAdvice;
import org.springframework.security.authorization.method.AuthorizationMethodAfterAdvice;
import org.springframework.security.authorization.method.AuthorizationMethodBeforeAdvice;
import org.springframework.security.authorization.method.DelegatingAuthorizationMethodAfterAdvice;
import org.springframework.security.authorization.method.DelegatingAuthorizationMethodBeforeAdvice;
import org.springframework.security.authorization.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodAfterAdvice;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodBeforeAdvice;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @see EnableMethodSecurity
 * @since 5.5
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class MethodSecurityConfiguration implements ImportAware {

	private MethodSecurityExpressionHandler methodSecurityExpressionHandler;

	private GrantedAuthorityDefaults grantedAuthorityDefaults;

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> authorizationMethodBeforeAdvice;

	private AuthorizationMethodAfterAdvice<MethodAuthorizationContext> authorizationMethodAfterAdvice;

	private AnnotationAttributes enableMethodSecurity;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	DefaultPointcutAdvisor methodSecurityAdvisor(AuthorizationMethodInterceptor interceptor) {
		Pointcut pointcut = Pointcuts.union(getAuthorizationMethodBeforeAdvice(), getAuthorizationMethodAfterAdvice());
		DefaultPointcutAdvisor advisor = new DefaultPointcutAdvisor(pointcut, interceptor);
		advisor.setOrder(order());
		return advisor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	AuthorizationMethodInterceptor authorizationMethodInterceptor() {
		return new AuthorizationMethodInterceptor(getAuthorizationMethodBeforeAdvice(),
				getAuthorizationMethodAfterAdvice());
	}

	private MethodSecurityExpressionHandler getMethodSecurityExpressionHandler() {
		if (this.methodSecurityExpressionHandler == null) {
			this.methodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
		}
		return this.methodSecurityExpressionHandler;
	}

	@Autowired(required = false)
	void setMethodSecurityExpressionHandler(MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		this.methodSecurityExpressionHandler = methodSecurityExpressionHandler;
	}

	@Autowired(required = false)
	void setGrantedAuthorityDefaults(GrantedAuthorityDefaults grantedAuthorityDefaults) {
		this.grantedAuthorityDefaults = grantedAuthorityDefaults;
	}

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> getAuthorizationMethodBeforeAdvice() {
		if (this.authorizationMethodBeforeAdvice == null) {
			this.authorizationMethodBeforeAdvice = createDefaultAuthorizationMethodBeforeAdvice();
		}
		return this.authorizationMethodBeforeAdvice;
	}

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> createDefaultAuthorizationMethodBeforeAdvice() {
		List<AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>> beforeAdvices = new ArrayList<>();
		beforeAdvices.add(getPreFilterAuthorizationMethodBeforeAdvice());
		beforeAdvices.add(getPreAuthorizeAuthorizationMethodBeforeAdvice());
		if (securedEnabled()) {
			beforeAdvices.add(getSecuredAuthorizationMethodBeforeAdvice());
		}
		if (jsr250Enabled()) {
			beforeAdvices.add(getJsr250AuthorizationMethodBeforeAdvice());
		}
		return new DelegatingAuthorizationMethodBeforeAdvice(beforeAdvices);
	}

	private PreFilterAuthorizationMethodBeforeAdvice getPreFilterAuthorizationMethodBeforeAdvice() {
		PreFilterAuthorizationMethodBeforeAdvice preFilterBeforeAdvice = new PreFilterAuthorizationMethodBeforeAdvice();
		preFilterBeforeAdvice.setExpressionHandler(getMethodSecurityExpressionHandler());
		return preFilterBeforeAdvice;
	}

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> getPreAuthorizeAuthorizationMethodBeforeAdvice() {
		MethodMatcher methodMatcher = new SecurityAnnotationsStaticMethodMatcher(PreAuthorize.class);
		PreAuthorizeAuthorizationManager authorizationManager = new PreAuthorizeAuthorizationManager();
		authorizationManager.setExpressionHandler(getMethodSecurityExpressionHandler());
		return new AuthorizationManagerMethodBeforeAdvice<>(methodMatcher, authorizationManager);
	}

	private AuthorizationManagerMethodBeforeAdvice<MethodAuthorizationContext> getSecuredAuthorizationMethodBeforeAdvice() {
		MethodMatcher methodMatcher = new SecurityAnnotationsStaticMethodMatcher(Secured.class);
		SecuredAuthorizationManager authorizationManager = new SecuredAuthorizationManager();
		return new AuthorizationManagerMethodBeforeAdvice<>(methodMatcher, authorizationManager);
	}

	private AuthorizationManagerMethodBeforeAdvice<MethodAuthorizationContext> getJsr250AuthorizationMethodBeforeAdvice() {
		MethodMatcher methodMatcher = new SecurityAnnotationsStaticMethodMatcher(DenyAll.class, PermitAll.class,
				RolesAllowed.class);
		Jsr250AuthorizationManager authorizationManager = new Jsr250AuthorizationManager();
		if (this.grantedAuthorityDefaults != null) {
			authorizationManager.setRolePrefix(this.grantedAuthorityDefaults.getRolePrefix());
		}
		return new AuthorizationManagerMethodBeforeAdvice<>(methodMatcher, authorizationManager);
	}

	@Autowired(required = false)
	void setAuthorizationMethodBeforeAdvice(
			AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> authorizationMethodBeforeAdvice) {
		this.authorizationMethodBeforeAdvice = authorizationMethodBeforeAdvice;
	}

	private AuthorizationMethodAfterAdvice<MethodAuthorizationContext> getAuthorizationMethodAfterAdvice() {
		if (this.authorizationMethodAfterAdvice == null) {
			this.authorizationMethodAfterAdvice = createDefaultAuthorizationMethodAfterAdvice();
		}
		return this.authorizationMethodAfterAdvice;
	}

	private AuthorizationMethodAfterAdvice<MethodAuthorizationContext> createDefaultAuthorizationMethodAfterAdvice() {
		List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> afterAdvices = new ArrayList<>();
		afterAdvices.add(getPostFilterAuthorizationMethodAfterAdvice());
		afterAdvices.add(getPostAuthorizeAuthorizationMethodAfterAdvice());
		return new DelegatingAuthorizationMethodAfterAdvice(afterAdvices);
	}

	private PostFilterAuthorizationMethodAfterAdvice getPostFilterAuthorizationMethodAfterAdvice() {
		PostFilterAuthorizationMethodAfterAdvice postFilterAfterAdvice = new PostFilterAuthorizationMethodAfterAdvice();
		postFilterAfterAdvice.setExpressionHandler(getMethodSecurityExpressionHandler());
		return postFilterAfterAdvice;
	}

	private AuthorizationManagerMethodAfterAdvice<MethodAuthorizationContext> getPostAuthorizeAuthorizationMethodAfterAdvice() {
		MethodMatcher methodMatcher = new SecurityAnnotationsStaticMethodMatcher(PostAuthorize.class);
		PostAuthorizeAuthorizationManager authorizationManager = new PostAuthorizeAuthorizationManager();
		authorizationManager.setExpressionHandler(getMethodSecurityExpressionHandler());
		return new AuthorizationManagerMethodAfterAdvice<>(methodMatcher, authorizationManager);
	}

	@Autowired(required = false)
	void setAuthorizationMethodAfterAdvice(
			AuthorizationMethodAfterAdvice<MethodAuthorizationContext> authorizationMethodAfterAdvice) {
		this.authorizationMethodAfterAdvice = authorizationMethodAfterAdvice;
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> attributes = importMetadata.getAnnotationAttributes(EnableMethodSecurity.class.getName());
		this.enableMethodSecurity = AnnotationAttributes.fromMap(attributes);
	}

	private boolean securedEnabled() {
		return this.enableMethodSecurity.getBoolean("securedEnabled");
	}

	private boolean jsr250Enabled() {
		return this.enableMethodSecurity.getBoolean("jsr250Enabled");
	}

	private int order() {
		return this.enableMethodSecurity.getNumber("order");
	}

	private static final class SecurityAnnotationsStaticMethodMatcher extends StaticMethodMatcher {

		private final Set<Class<? extends Annotation>> annotationClasses;

		@SafeVarargs
		private SecurityAnnotationsStaticMethodMatcher(Class<? extends Annotation>... annotationClasses) {
			this.annotationClasses = new HashSet<>(Arrays.asList(annotationClasses));
		}

		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
			return hasAnnotations(specificMethod) || hasAnnotations(specificMethod.getDeclaringClass());
		}

		private boolean hasAnnotations(AnnotatedElement annotatedElement) {
			Set<Annotation> annotations = AnnotatedElementUtils.findAllMergedAnnotations(annotatedElement,
					this.annotationClasses);
			return !annotations.isEmpty();
		}

	}

}
