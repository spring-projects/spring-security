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
package org.springframework.security.config.annotation.method.configuration;

import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.intercept.aspectj.aspect.AnnotationSecurityAspect;

/**
 * Creates the AnnotationSecurityAspect for use with AspectJ based security.
 *
 * @author Rob Winch
 * @since 3.2
 */
class GlobalMethodSecurityAspectJConfiguration {

    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @Bean
    public AnnotationSecurityAspect annotationSecurityAspect(@Qualifier("methodSecurityInterceptor") MethodInterceptor methodSecurityInterceptor) {
        AnnotationSecurityAspect result = AnnotationSecurityAspect.aspectOf();
        result.setSecurityInterceptor((AspectJMethodSecurityInterceptor )methodSecurityInterceptor);
        return result;
    }
}