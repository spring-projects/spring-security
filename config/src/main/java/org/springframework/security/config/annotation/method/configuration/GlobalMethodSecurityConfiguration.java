/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
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
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
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
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.util.Assert;

/**
 * Base {@link Configuration} for enabling global method security. Classes may
 * extend this class to customize the defaults, but must be sure to specify the
 * {@link EnableGlobalMethodSecurity} annotation on the subclass.
 *
 * @author Rob Winch
 * @since 3.2
 * @see EnableGlobalMethodSecurity
 */
@Configuration
public class GlobalMethodSecurityConfiguration implements ImportAware {
    private ApplicationContext context;
    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        @Override
        public <T> T postProcess(T object) {
            throw new IllegalStateException(ObjectPostProcessor.class.getName()+ " is a required bean. Ensure you have used @"+EnableGlobalMethodSecurity.class.getName());
        }
    };
    private AuthenticationManager authenticationManager;
    private AuthenticationManagerBuilder auth = new AuthenticationManagerBuilder();
    private boolean disableAuthenticationRegistry;
    private AnnotationAttributes enableMethodSecurity;
    private MethodSecurityExpressionHandler expressionHandler;

    /**
     * Creates the default MethodInterceptor which is a MethodSecurityInterceptor using the following methods to
     * construct it.
     * <ul>
     *     <li>{@link #accessDecisionManager()}</li>
     *     <li>{@link #afterInvocationManager()}</li>
     *     <li>{@link #authenticationManager()}</li>
     *     <li>{@link #methodSecurityMetadataSource()}</li>
     *     <li>{@link #runAsManager()}</li>
     *
     * </ul>
     *
     * <p>
     *     Subclasses can override this method to provide a different {@link MethodInterceptor}.
     * </p>
     *
     * @return
     * @throws Exception
     */
    @Bean
    public MethodInterceptor methodSecurityInterceptor() throws Exception {
        MethodSecurityInterceptor methodSecurityInterceptor = new MethodSecurityInterceptor();
        methodSecurityInterceptor
                .setAccessDecisionManager(accessDecisionManager());
        methodSecurityInterceptor
                .setAfterInvocationManager(afterInvocationManager());
        methodSecurityInterceptor
                .setAuthenticationManager(authenticationManager());
        methodSecurityInterceptor
                .setSecurityMetadataSource(methodSecurityMetadataSource());
        RunAsManager runAsManager = runAsManager();
        if (runAsManager != null) {
            methodSecurityInterceptor.setRunAsManager(runAsManager);
        }
        return methodSecurityInterceptor;
    }

    /**
     * Provide a custom {@link AfterInvocationManager} for the default
     * implementation of {@link #methodSecurityInterceptor()}. The default is
     * null if pre post is not enabled. Otherwise, it returns a {@link AfterInvocationProviderManager}.
     *
     * <p>
     * Subclasses should override this method to provide a custom {@link AfterInvocationManager}
     * </p>
     *
     * @return
     */
    protected AfterInvocationManager afterInvocationManager() {
        if(prePostEnabled()) {
            AfterInvocationProviderManager invocationProviderManager = new AfterInvocationProviderManager();
            ExpressionBasedPostInvocationAdvice postAdvice = new ExpressionBasedPostInvocationAdvice(getExpressionHandler());
            PostInvocationAdviceProvider postInvocationAdviceProvider = new PostInvocationAdviceProvider(postAdvice);
            List<AfterInvocationProvider> afterInvocationProviders = new ArrayList<AfterInvocationProvider>();
            afterInvocationProviders.add(postInvocationAdviceProvider);
            invocationProviderManager.setProviders(afterInvocationProviders);
            return invocationProviderManager;
        }
        return null;
    }

    /**
     * Provide a custom {@link RunAsManager} for the default implementation of
     * {@link #methodSecurityInterceptor()}. The default is null.
     *
     * @return
     */
    protected RunAsManager runAsManager() {
        return null;
    }

    /**
     * Allows subclasses to provide a custom {@link AccessDecisionManager}. The default is a {@link AffirmativeBased}
     * with the following voters:
     *
     * <ul>
     *     <li>{@link PreInvocationAuthorizationAdviceVoter}</li>
     *     <li>{@link RoleVoter} </li>
     *     <li>{@link AuthenticatedVoter} </li>
     * </ul>
     *
     * @return
     */
    @SuppressWarnings("rawtypes")
    protected AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
        expressionAdvice.setExpressionHandler(getExpressionHandler());

        decisionVoters.add(new PreInvocationAuthorizationAdviceVoter(
                expressionAdvice));
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return new AffirmativeBased(decisionVoters);
    }

    /**
     * Provide a {@link MethodSecurityExpressionHandler} that is
     * registered with the {@link ExpressionBasedPreInvocationAdvice}. The default is
     * {@link DefaultMethodSecurityExpressionHandler}
     *
     * <p>Subclasses may override this method to provide a custom {@link MethodSecurityExpressionHandler}</p>
     *
     * @return
     */
    protected MethodSecurityExpressionHandler expressionHandler() {
        return new DefaultMethodSecurityExpressionHandler();
    }

    /**
     * Gets the {@link MethodSecurityExpressionHandler} or creates it using {@link #expressionHandler}.
     *
     * @return a non {@code null} {@link MethodSecurityExpressionHandler}
     */
    protected final MethodSecurityExpressionHandler getExpressionHandler() {
        if(expressionHandler == null) {
            expressionHandler = expressionHandler();
        }
        return expressionHandler;
    }

    /**
     * Provides a custom {@link MethodSecurityMetadataSource} that is registered
     * with the {@link #methodSecurityMetadataSource()}. Default is null.
     *
     * @return a custom {@link MethodSecurityMetadataSource} that is registered
     * with the {@link #methodSecurityMetadataSource()}
     */
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return null;
    }

    /**
     * Allows providing a custom {@link AuthenticationManager}. The default is
     * to use any authentication mechanisms registered by {@link #registerAuthentication(AuthenticationManagerBuilder)}. If
     * {@link #registerAuthentication(AuthenticationManagerBuilder)} was not overriden, then an {@link AuthenticationManager}
     * is attempted to be autowired by type.
     *
     * @return
     */
    protected AuthenticationManager authenticationManager() throws Exception {
        if(authenticationManager == null) {
            DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
            auth.authenticationEventPublisher(eventPublisher);
            auth.objectPostProcessor(objectPostProcessor);
            registerAuthentication(auth);
            if(!disableAuthenticationRegistry) {
                authenticationManager = auth.build();
            }
            if(authenticationManager == null) {
                authenticationManager = lazyBean(AuthenticationManager.class);
            }
        }
        return authenticationManager;
    }

    /**
     * Sub classes can override this method to register different types of authentication. If not overridden,
     * {@link #registerAuthentication(AuthenticationManagerBuilder)} will attempt to autowire by type.
     *
     * @param auth the {@link AuthenticationManagerBuilder} used to register different authentication mechanisms for the
     *                 global method security.
     * @throws Exception
     */
    protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        this.disableAuthenticationRegistry = true;
    }

    /**
     * Provides the default {@link MethodSecurityMetadataSource} that will be
     * used. It creates a {@link DelegatingMethodSecurityMetadataSource} based
     * upon {@link #customMethodSecurityMetadataSource()} and the attributes on
     * {@link EnableGlobalMethodSecurity}.
     *
     * @return
     */
    @Bean
    public MethodSecurityMetadataSource methodSecurityMetadataSource() {
        List<MethodSecurityMetadataSource> sources = new ArrayList<MethodSecurityMetadataSource>();
        ExpressionBasedAnnotationAttributeFactory attributeFactory = new ExpressionBasedAnnotationAttributeFactory(
                methodExpressionHandler());
        MethodSecurityMetadataSource customMethodSecurityMetadataSource = customMethodSecurityMetadataSource();
        if (customMethodSecurityMetadataSource != null) {
            sources.add(customMethodSecurityMetadataSource);
        }
        if (prePostEnabled()) {
            sources.add(new PrePostAnnotationSecurityMetadataSource(
                    attributeFactory));
        }
        if (securedEnabled()) {
            sources.add(new SecuredAnnotationSecurityMetadataSource());
        }
        if (jsr250Enabled()) {
            sources.add(new Jsr250MethodSecurityMetadataSource());
        }
        return new DelegatingMethodSecurityMetadataSource(sources);
    }

    /**
     * Creates the {@link MethodSecurityExpressionHandler} to be used.
     *
     * @return
     */
    @Bean
    public MethodSecurityExpressionHandler methodExpressionHandler() {
        return new DefaultMethodSecurityExpressionHandler();
    }

    /**
     * Creates the {@link PreInvocationAuthorizationAdvice} to be used. The
     * default is {@link ExpressionBasedPreInvocationAdvice}.
     *
     * @return
     */
    @Bean
    public PreInvocationAuthorizationAdvice preInvocationAuthorizationAdvice() {
        ExpressionBasedPreInvocationAdvice preInvocationAdvice = new ExpressionBasedPreInvocationAdvice();
        preInvocationAdvice.setExpressionHandler(methodExpressionHandler());
        return preInvocationAdvice;
    }

    /**
     * Obtains the {@link MethodSecurityMetadataSourceAdvisor} to be used.
     *
     * @return
     */
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @Bean
    public MethodSecurityMetadataSourceAdvisor metaDataSourceAdvisor() {
        MethodSecurityMetadataSourceAdvisor methodAdvisor = new MethodSecurityMetadataSourceAdvisor(
                "methodSecurityInterceptor", methodSecurityMetadataSource(),
                "methodSecurityMetadataSource");
        methodAdvisor.setOrder(order());
        return methodAdvisor;
    }

    /**
     * Obtains the attributes from {@link EnableGlobalMethodSecurity} if this class was imported using the {@link EnableGlobalMethodSecurity} annotation.
     */
    @Override
    public final void setImportMetadata(AnnotationMetadata importMetadata) {
        Map<String, Object> annotationAttributes = importMetadata
                .getAnnotationAttributes(EnableGlobalMethodSecurity.class
                        .getName());
        enableMethodSecurity = AnnotationAttributes
                .fromMap(annotationAttributes);
    }

    @Autowired
    public void setApplicationContext(ApplicationContext context) {
        this.context = context;
    }

    @Autowired(required=false)
    public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }

    @SuppressWarnings("unchecked")
    private <T> T lazyBean(Class<T> interfaceName) {
        LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
        String[] beanNamesForType = context.getBeanNamesForType(interfaceName);
        Assert.isTrue(beanNamesForType.length == 1 , "Expecting to only find a single bean for type " + interfaceName + ", but found " + Arrays.asList(beanNamesForType));
        lazyTargetSource.setTargetBeanName(beanNamesForType[0]);
        lazyTargetSource.setBeanFactory(context);
        ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
        proxyFactory.setTargetSource(lazyTargetSource);
        proxyFactory.setInterfaces(new Class[] { interfaceName });
        return (T) proxyFactory.getObject();
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

    private AnnotationAttributes enableMethodSecurity() {
        if (enableMethodSecurity == null) {
            // if it is null look at this instance (i.e. a subclass was used)
            EnableGlobalMethodSecurity methodSecurityAnnotation = AnnotationUtils
                    .findAnnotation(getClass(),
                            EnableGlobalMethodSecurity.class);
            Assert.notNull(methodSecurityAnnotation,
                    EnableGlobalMethodSecurity.class.getName() + " is required");
            Map<String, Object> methodSecurityAttrs = AnnotationUtils
                    .getAnnotationAttributes(methodSecurityAnnotation);
            this.enableMethodSecurity = AnnotationAttributes
                    .fromMap(methodSecurityAttrs);
        }
        return this.enableMethodSecurity;
    }

}
