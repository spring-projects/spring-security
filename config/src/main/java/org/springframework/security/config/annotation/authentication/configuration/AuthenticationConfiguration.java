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
package org.springframework.security.config.annotation.authentication.configuration;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.util.Assert;

/**
 * Exports the authentication {@link Configuration}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@Configuration
public class AuthenticationConfiguration {
    private ApplicationContext applicationContext;

    private AuthenticationManager authenticationManager;

    private boolean authenticationManagerInitialized;

    private List<GlobalAuthenticationConfigurerAdapter> globalAuthConfigures = Collections.emptyList();

    private ObjectPostProcessor<Object> objectPostProcessor;

    @Bean
    public AuthenticationManagerBuilder authenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        return new AuthenticationManagerBuilder(objectPostProcessor);
    }

    @Bean
    public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
        return new EnableGlobalAuthenticationAutowiredConfigurer(context);
    }

    public AuthenticationManager getAuthenticationManager() throws Exception {
        if(authenticationManagerInitialized) {
            return authenticationManager;
        }

        AuthenticationManagerBuilder authBuilder = authenticationManagerBuilder(objectPostProcessor);
        for(GlobalAuthenticationConfigurerAdapter config : globalAuthConfigures) {
            authBuilder.apply(config);
        }

        authenticationManager = authBuilder.build();

        if(authenticationManager == null) {
            authenticationManager = getAuthenticationMangerBean();
        }

        this.authenticationManagerInitialized = true;
        return authenticationManager;
    }

    @Autowired(required = false)
    public void setGlobalAuthenticationConfigurers(List<GlobalAuthenticationConfigurerAdapter> configurers) throws Exception {
        Collections.sort(configurers, AnnotationAwareOrderComparator.INSTANCE);
        this.globalAuthConfigures = configurers;
    }

    @Autowired
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Autowired
    public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }


    @SuppressWarnings("unchecked")
    private <T> T lazyBean(Class<T> interfaceName) {
        LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
        String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(applicationContext, interfaceName);
        if(beanNamesForType.length == 0) {
            return null;
        }
        Assert.isTrue(beanNamesForType.length == 1 , "Expecting to only find a single bean for type " + interfaceName + ", but found " + Arrays.asList(beanNamesForType));
        lazyTargetSource.setTargetBeanName(beanNamesForType[0]);
        lazyTargetSource.setBeanFactory(applicationContext);
        ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
        proxyFactory = objectPostProcessor.postProcess(proxyFactory);
        proxyFactory.setTargetSource(lazyTargetSource);
        return (T) proxyFactory.getObject();
    }

    private AuthenticationManager getAuthenticationMangerBean() {
        return lazyBean(AuthenticationManager.class);
    }

    private static class EnableGlobalAuthenticationAutowiredConfigurer extends GlobalAuthenticationConfigurerAdapter {
        private final ApplicationContext context;
        private static final Log logger = LogFactory.getLog(EnableGlobalAuthenticationAutowiredConfigurer.class);

        public EnableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
            this.context = context;
        }

        @Override
        public void init(AuthenticationManagerBuilder auth) {
            Map<String, Object> beansWithAnnotation = context.getBeansWithAnnotation(EnableGlobalAuthentication.class);
            if(logger.isDebugEnabled()) {
                logger.debug("Eagerly initializing " + beansWithAnnotation);
            }
        }
    }
}