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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.aopalliance.intercept.MethodInterceptor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdvice;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.util.Assert;

/**
 * Base {@link Configuration} for enabling global method security. Classes may extend this
 * class to customize the defaults, but must be sure to specify the
 * {@link EnableGlobalMethodSecurity} annotation on the subclass.
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 3.2
 * @see EnableGlobalMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
public class GlobalMethodSecurityConfiguration implements ImportAware, SmartInitializingSingleton, BeanFactoryAware {

	private static final Log logger = LogFactory.getLog(GlobalMethodSecurityConfiguration.class);

	private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
		public <T> T postProcess(T object) {
			throw new IllegalStateException(ObjectPostProcessor.class.getName()
					+ " is a required bean. Ensure you have used @" + EnableGlobalMethodSecurity.class.getName());
		}
	};

	private DefaultMethodSecurityExpressionHandler defaultMethodExpressionHandler = new DefaultMethodSecurityExpressionHandler();

	private AuthenticationManager authenticationManager;

	private AuthenticationManagerBuilder auth;

	private boolean disableAuthenticationRegistry;

	private AnnotationAttributes enableMethodSecurity;

	private BeanFactory context;

	private MethodSecurityExpressionHandler expressionHandler;

	private MethodSecurityInterceptor methodSecurityInterceptor;

	/**
	 * Creates the default MethodInterceptor which is a MethodSecurityInterceptor using
	 * the following methods to construct it.
	 * <ul>
	 * <li>{@link #accessDecisionManager()}</li>
	 * <li>{@link #afterInvocationManager()}</li>
	 * <li>{@link #authenticationManager()}</li>
	 * <li>{@link #runAsManager()}</li>
	 *
	 * </ul>
	 *
	 * <p>
	 * Subclasses can override this method to provide a different
	 * {@link MethodInterceptor}.
	 * </p>
	 * @param methodSecurityMetadataSource the default
	 * {@link MethodSecurityMetadataSource}.
	 * @return the {@link MethodInterceptor}.
	 */
	@Bean
	public MethodInterceptor methodSecurityInterceptor(MethodSecurityMetadataSource methodSecurityMetadataSource) {
		this.methodSecurityInterceptor = isAspectJ() ? new AspectJMethodSecurityInterceptor()
				: new MethodSecurityInterceptor();
		this.methodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		this.methodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
		this.methodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
		RunAsManager runAsManager = runAsManager();
		if (runAsManager != null) {
			this.methodSecurityInterceptor.setRunAsManager(runAsManager);
		}

		return this.methodSecurityInterceptor;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.beans.factory.SmartInitializingSingleton#
	 * afterSingletonsInstantiated()
	 */
	@Override
	public void afterSingletonsInstantiated() {
		try {
			initializeMethodSecurityInterceptor();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}

		PermissionEvaluator permissionEvaluator = getSingleBeanOrNull(PermissionEvaluator.class);
		if (permissionEvaluator != null) {
			this.defaultMethodExpressionHandler.setPermissionEvaluator(permissionEvaluator);
		}

		RoleHierarchy roleHierarchy = getSingleBeanOrNull(RoleHierarchy.class);
		if (roleHierarchy != null) {
			this.defaultMethodExpressionHandler.setRoleHierarchy(roleHierarchy);
		}

		AuthenticationTrustResolver trustResolver = getSingleBeanOrNull(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			this.defaultMethodExpressionHandler.setTrustResolver(trustResolver);
		}

		GrantedAuthorityDefaults grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
		if (grantedAuthorityDefaults != null) {
			this.defaultMethodExpressionHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}
	}

	private <T> T getSingleBeanOrNull(Class<T> type) {
		try {
			return this.context.getBean(type);
		}
		catch (NoSuchBeanDefinitionException e) {
		}
		return null;
	}

	private void initializeMethodSecurityInterceptor() throws Exception {
		if (this.methodSecurityInterceptor == null) {
			return;
		}
		this.methodSecurityInterceptor.setAuthenticationManager(authenticationManager());
	}

	/**
	 * Provide a custom {@link AfterInvocationManager} for the default implementation of
	 * {@link #methodSecurityInterceptor(MethodSecurityMetadataSource)}. The default is
	 * null if pre post is not enabled. Otherwise, it returns a
	 * {@link AfterInvocationProviderManager}.
	 *
	 * <p>
	 * Subclasses should override this method to provide a custom
	 * {@link AfterInvocationManager}
	 * </p>
	 * @return the {@link AfterInvocationManager} to use
	 */
	protected AfterInvocationManager afterInvocationManager() {
		if (prePostEnabled()) {
			AfterInvocationProviderManager invocationProviderManager = new AfterInvocationProviderManager();
			ExpressionBasedPostInvocationAdvice postAdvice = new ExpressionBasedPostInvocationAdvice(
					getExpressionHandler());
			PostInvocationAdviceProvider postInvocationAdviceProvider = new PostInvocationAdviceProvider(postAdvice);
			List<AfterInvocationProvider> afterInvocationProviders = new ArrayList<>();
			afterInvocationProviders.add(postInvocationAdviceProvider);
			invocationProviderManager.setProviders(afterInvocationProviders);
			return invocationProviderManager;
		}
		return null;
	}

	/**
	 * Provide a custom {@link RunAsManager} for the default implementation of
	 * {@link #methodSecurityInterceptor(MethodSecurityMetadataSource)}. The default is
	 * null.
	 * @return the {@link RunAsManager} to use
	 */
	protected RunAsManager runAsManager() {
		return null;
	}

	/**
	 * Allows subclasses to provide a custom {@link AccessDecisionManager}. The default is
	 * a {@link AffirmativeBased} with the following voters:
	 *
	 * <ul>
	 * <li>{@link PreInvocationAuthorizationAdviceVoter}</li>
	 * <li>{@link RoleVoter}</li>
	 * <li>{@link AuthenticatedVoter}</li>
	 * </ul>
	 * @return the {@link AccessDecisionManager} to use
	 */
	protected AccessDecisionManager accessDecisionManager() {
		List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
		if (prePostEnabled()) {
			ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
			expressionAdvice.setExpressionHandler(getExpressionHandler());
			decisionVoters.add(new PreInvocationAuthorizationAdviceVoter(expressionAdvice));
		}
		if (jsr250Enabled()) {
			decisionVoters.add(new Jsr250Voter());
		}
		RoleVoter roleVoter = new RoleVoter();
		GrantedAuthorityDefaults grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
		if (grantedAuthorityDefaults != null) {
			roleVoter.setRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}
		decisionVoters.add(roleVoter);
		decisionVoters.add(new AuthenticatedVoter());
		return new AffirmativeBased(decisionVoters);
	}

	/**
	 * Provide a {@link MethodSecurityExpressionHandler} that is registered with the
	 * {@link ExpressionBasedPreInvocationAdvice}. The default is
	 * {@link DefaultMethodSecurityExpressionHandler} which optionally will Autowire an
	 * {@link AuthenticationTrustResolver}.
	 *
	 * <p>
	 * Subclasses may override this method to provide a custom
	 * {@link MethodSecurityExpressionHandler}
	 * </p>
	 * @return the {@link MethodSecurityExpressionHandler} to use
	 */
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		return this.defaultMethodExpressionHandler;
	}

	/**
	 * Gets the {@link MethodSecurityExpressionHandler} or creates it using
	 * {@link #expressionHandler}.
	 * @return a non {@code null} {@link MethodSecurityExpressionHandler}
	 */
	protected final MethodSecurityExpressionHandler getExpressionHandler() {
		if (this.expressionHandler == null) {
			this.expressionHandler = createExpressionHandler();
		}
		return this.expressionHandler;
	}

	/**
	 * Provides a custom {@link MethodSecurityMetadataSource} that is registered with the
	 * {@link #methodSecurityMetadataSource()}. Default is null.
	 * @return a custom {@link MethodSecurityMetadataSource} that is registered with the
	 * {@link #methodSecurityMetadataSource()}
	 */
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		return null;
	}

	/**
	 * Allows providing a custom {@link AuthenticationManager}. The default is to use any
	 * authentication mechanisms registered by
	 * {@link #configure(AuthenticationManagerBuilder)}. If
	 * {@link #configure(AuthenticationManagerBuilder)} was not overridden, then an
	 * {@link AuthenticationManager} is attempted to be autowired by type.
	 * @return the {@link AuthenticationManager} to use
	 */
	protected AuthenticationManager authenticationManager() throws Exception {
		if (this.authenticationManager == null) {
			DefaultAuthenticationEventPublisher eventPublisher = this.objectPostProcessor
					.postProcess(new DefaultAuthenticationEventPublisher());
			this.auth = new AuthenticationManagerBuilder(this.objectPostProcessor);
			this.auth.authenticationEventPublisher(eventPublisher);
			configure(this.auth);
			if (this.disableAuthenticationRegistry) {
				this.authenticationManager = getAuthenticationConfiguration().getAuthenticationManager();
			}
			else {
				this.authenticationManager = this.auth.build();
			}
		}
		return this.authenticationManager;
	}

	/**
	 * Sub classes can override this method to register different types of authentication.
	 * If not overridden, {@link #configure(AuthenticationManagerBuilder)} will attempt to
	 * autowire by type.
	 * @param auth the {@link AuthenticationManagerBuilder} used to register different
	 * authentication mechanisms for the global method security.
	 * @throws Exception
	 */
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		this.disableAuthenticationRegistry = true;
	}

	/**
	 * Provides the default {@link MethodSecurityMetadataSource} that will be used. It
	 * creates a {@link DelegatingMethodSecurityMetadataSource} based upon
	 * {@link #customMethodSecurityMetadataSource()} and the attributes on
	 * {@link EnableGlobalMethodSecurity}.
	 * @return the {@link MethodSecurityMetadataSource}
	 */
	@Bean
	public MethodSecurityMetadataSource methodSecurityMetadataSource() {
		List<MethodSecurityMetadataSource> sources = new ArrayList<>();
		ExpressionBasedAnnotationAttributeFactory attributeFactory = new ExpressionBasedAnnotationAttributeFactory(
				getExpressionHandler());
		MethodSecurityMetadataSource customMethodSecurityMetadataSource = customMethodSecurityMetadataSource();
		if (customMethodSecurityMetadataSource != null) {
			sources.add(customMethodSecurityMetadataSource);
		}

		boolean hasCustom = customMethodSecurityMetadataSource != null;
		boolean isPrePostEnabled = prePostEnabled();
		boolean isSecuredEnabled = securedEnabled();
		boolean isJsr250Enabled = jsr250Enabled();

		if (!isPrePostEnabled && !isSecuredEnabled && !isJsr250Enabled && !hasCustom) {
			throw new IllegalStateException("In the composition of all global method configuration, "
					+ "no annotation support was actually activated");
		}

		if (isPrePostEnabled) {
			sources.add(new PrePostAnnotationSecurityMetadataSource(attributeFactory));
		}
		if (isSecuredEnabled) {
			sources.add(new SecuredAnnotationSecurityMetadataSource());
		}
		if (isJsr250Enabled) {
			GrantedAuthorityDefaults grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
			Jsr250MethodSecurityMetadataSource jsr250MethodSecurityMetadataSource = this.context
					.getBean(Jsr250MethodSecurityMetadataSource.class);
			if (grantedAuthorityDefaults != null) {
				jsr250MethodSecurityMetadataSource.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
			sources.add(jsr250MethodSecurityMetadataSource);
		}
		return new DelegatingMethodSecurityMetadataSource(sources);
	}

	/**
	 * Creates the {@link PreInvocationAuthorizationAdvice} to be used. The default is
	 * {@link ExpressionBasedPreInvocationAdvice}.
	 * @return the {@link PreInvocationAuthorizationAdvice}
	 */
	@Bean
	public PreInvocationAuthorizationAdvice preInvocationAuthorizationAdvice() {
		ExpressionBasedPreInvocationAdvice preInvocationAdvice = new ExpressionBasedPreInvocationAdvice();
		preInvocationAdvice.setExpressionHandler(getExpressionHandler());
		return preInvocationAdvice;
	}

	/**
	 * Obtains the attributes from {@link EnableGlobalMethodSecurity} if this class was
	 * imported using the {@link EnableGlobalMethodSecurity} annotation.
	 */
	public final void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> annotationAttributes = importMetadata
				.getAnnotationAttributes(EnableGlobalMethodSecurity.class.getName());
		this.enableMethodSecurity = AnnotationAttributes.fromMap(annotationAttributes);
	}

	@Autowired(required = false)
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
		this.defaultMethodExpressionHandler = objectPostProcessor.postProcess(this.defaultMethodExpressionHandler);
	}

	@Autowired(required = false)
	public void setMethodSecurityExpressionHandler(List<MethodSecurityExpressionHandler> handlers) {
		if (handlers.size() != 1) {
			logger.debug("Not autowiring MethodSecurityExpressionHandler since size != 1. Got " + handlers);
			return;
		}
		this.expressionHandler = handlers.get(0);
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.context = beanFactory;
	}

	private AuthenticationConfiguration getAuthenticationConfiguration() {
		return this.context.getBean(AuthenticationConfiguration.class);
	}

	private boolean prePostEnabled() {
		return enableMethodSecurity().getBoolean("prePostEnabled");
	}

	private boolean securedEnabled() {
		return enableMethodSecurity().getBoolean("securedEnabled");
	}

	private boolean jsr250Enabled() {
		return enableMethodSecurity().getBoolean("jsr250Enabled");
	}

	private int order() {
		return (Integer) enableMethodSecurity().get("order");
	}

	private boolean isAspectJ() {
		return enableMethodSecurity().getEnum("mode") == AdviceMode.ASPECTJ;
	}

	private AnnotationAttributes enableMethodSecurity() {
		if (this.enableMethodSecurity == null) {
			// if it is null look at this instance (i.e. a subclass was used)
			EnableGlobalMethodSecurity methodSecurityAnnotation = AnnotationUtils.findAnnotation(getClass(),
					EnableGlobalMethodSecurity.class);
			Assert.notNull(methodSecurityAnnotation, () -> EnableGlobalMethodSecurity.class.getName() + " is required");
			Map<String, Object> methodSecurityAttrs = AnnotationUtils.getAnnotationAttributes(methodSecurityAnnotation);
			this.enableMethodSecurity = AnnotationAttributes.fromMap(methodSecurityAttrs);
		}
		return this.enableMethodSecurity;
	}

}
