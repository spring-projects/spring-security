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

import java.util.Map;

import org.springframework.aop.config.AopConfigUtils;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Registers an
 * {@link org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator
 * AnnotationAwareAspectJAutoProxyCreator} against the current
 * {@link BeanDefinitionRegistry} as appropriate based on a given @
 * {@link EnableGlobalMethodSecurity} annotation.
 *
 * <p>
 * Note: This class is necessary because AspectJAutoProxyRegistrar only supports
 * EnableAspectJAutoProxy.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
class GlobalMethodSecurityAspectJAutoProxyRegistrar implements
        ImportBeanDefinitionRegistrar {

    /**
     * Register, escalate, and configure the AspectJ auto proxy creator based on
     * the value of the @{@link EnableGlobalMethodSecurity#proxyTargetClass()}
     * attribute on the importing {@code @Configuration} class.
     */
    public void registerBeanDefinitions(
            AnnotationMetadata importingClassMetadata,
            BeanDefinitionRegistry registry) {

        AopConfigUtils
                .registerAspectJAnnotationAutoProxyCreatorIfNecessary(registry);

        Map<String, Object> annotationAttributes = importingClassMetadata
                .getAnnotationAttributes(EnableGlobalMethodSecurity.class
                        .getName());
        AnnotationAttributes enableAJAutoProxy = AnnotationAttributes
                .fromMap(annotationAttributes);

        if (enableAJAutoProxy.getBoolean("proxyTargetClass")) {
            AopConfigUtils.forceAutoProxyCreatorToUseClassProxying(registry);
        }
    }

}