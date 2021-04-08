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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationMethodInterceptors;
import org.springframework.security.authorization.method.DelegatingAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.util.Assert;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @see EnableMethodSecurity
 * @since 5.5
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class MethodSecurityConfiguration implements ImportAware, InitializingBean {

	private MethodSecurityExpressionHandler methodSecurityExpressionHandler;

	private GrantedAuthorityDefaults grantedAuthorityDefaults;

	private AuthorizationMethodInterceptor interceptor;

	private AnnotationAttributes enableMethodSecurity;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	DefaultPointcutAdvisor methodSecurityAdvisor() {
		AuthorizationMethodInterceptor interceptor = getInterceptor();
		DefaultPointcutAdvisor advisor = new DefaultPointcutAdvisor(interceptor.getPointcut(), interceptor);
		advisor.setOrder(order());
		return advisor;
	}

	private MethodSecurityExpressionHandler getMethodSecurityExpressionHandler() {
		if (this.methodSecurityExpressionHandler == null) {
			DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
			if (this.grantedAuthorityDefaults != null) {
				methodSecurityExpressionHandler.setDefaultRolePrefix(this.grantedAuthorityDefaults.getRolePrefix());
			}
			this.methodSecurityExpressionHandler = methodSecurityExpressionHandler;
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

	private AuthorizationMethodInterceptor getInterceptor() {
		if (this.interceptor != null) {
			return this.interceptor;
		}
		List<AuthorizationMethodInterceptor> interceptors = new ArrayList<>();
		interceptors.addAll(createDefaultAuthorizationMethodBeforeAdvice());
		interceptors.addAll(createDefaultAuthorizationMethodAfterAdvice());
		return new DelegatingAuthorizationMethodInterceptor(interceptors);
	}

	private List<AuthorizationMethodInterceptor> createDefaultAuthorizationMethodBeforeAdvice() {
		List<AuthorizationMethodInterceptor> beforeAdvices = new ArrayList<>();
		beforeAdvices.add(getPreFilterAuthorizationMethodBeforeAdvice());
		beforeAdvices.add(getPreAuthorizeAuthorizationMethodBeforeAdvice());
		if (securedEnabled()) {
			beforeAdvices.add(getSecuredAuthorizationMethodBeforeAdvice());
		}
		if (jsr250Enabled()) {
			beforeAdvices.add(getJsr250AuthorizationMethodBeforeAdvice());
		}
		return beforeAdvices;
	}

	private PreFilterAuthorizationMethodInterceptor getPreFilterAuthorizationMethodBeforeAdvice() {
		PreFilterAuthorizationMethodInterceptor interceptor = new PreFilterAuthorizationMethodInterceptor();
		interceptor.setExpressionHandler(getMethodSecurityExpressionHandler());
		return interceptor;
	}

	private AuthorizationMethodInterceptor getPreAuthorizeAuthorizationMethodBeforeAdvice() {
		PreAuthorizeAuthorizationManager authorizationManager = new PreAuthorizeAuthorizationManager();
		authorizationManager.setExpressionHandler(getMethodSecurityExpressionHandler());
		return AuthorizationMethodInterceptors.preAuthorize(authorizationManager);
	}

	private AuthorizationMethodInterceptor getSecuredAuthorizationMethodBeforeAdvice() {
		return AuthorizationMethodInterceptors.secured(new SecuredAuthorizationManager());
	}

	private AuthorizationMethodInterceptor getJsr250AuthorizationMethodBeforeAdvice() {
		Jsr250AuthorizationManager authorizationManager = new Jsr250AuthorizationManager();
		if (this.grantedAuthorityDefaults != null) {
			authorizationManager.setRolePrefix(this.grantedAuthorityDefaults.getRolePrefix());
		}
		return AuthorizationMethodInterceptors.jsr250(authorizationManager);
	}

	@Autowired(required = false)
	void setAuthorizationMethodInterceptor(AuthorizationMethodInterceptor interceptor) {
		this.interceptor = interceptor;
	}

	private List<AuthorizationMethodInterceptor> createDefaultAuthorizationMethodAfterAdvice() {
		List<AuthorizationMethodInterceptor> afterAdvices = new ArrayList<>();
		afterAdvices.add(getPostFilterAuthorizationMethodAfterAdvice());
		afterAdvices.add(getPostAuthorizeAuthorizationMethodAfterAdvice());
		return afterAdvices;
	}

	private AuthorizationMethodInterceptor getPostFilterAuthorizationMethodAfterAdvice() {
		PostFilterAuthorizationMethodInterceptor interceptor = new PostFilterAuthorizationMethodInterceptor();
		interceptor.setExpressionHandler(getMethodSecurityExpressionHandler());
		return interceptor;
	}

	private AuthorizationMethodInterceptor getPostAuthorizeAuthorizationMethodAfterAdvice() {
		PostAuthorizeAuthorizationManager authorizationManager = new PostAuthorizeAuthorizationManager();
		authorizationManager.setExpressionHandler(getMethodSecurityExpressionHandler());
		return AuthorizationMethodInterceptors.postAuthorize(authorizationManager);
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> attributes = importMetadata.getAnnotationAttributes(EnableMethodSecurity.class.getName());
		this.enableMethodSecurity = AnnotationAttributes.fromMap(attributes);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		if (!securedEnabled() && !jsr250Enabled()) {
			return;
		}
		Assert.isNull(this.interceptor,
				"You have specified your own advice, meaning that the annotation attributes securedEnabled and jsr250Enabled will be ignored. Please choose one or the other.");
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

}
