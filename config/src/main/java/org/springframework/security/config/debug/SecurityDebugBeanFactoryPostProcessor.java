/*
 * Copyright 2002-2011 the original author or authors.
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
package org.springframework.security.config.debug;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.security.config.BeanIds;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class SecurityDebugBeanFactoryPostProcessor implements BeanDefinitionRegistryPostProcessor {

    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        Logger.logger.warn("\n\n" +
                "********************************************************************\n" +
                "**********        Security debugging is enabled.       *************\n" +
                "**********    This may include sensitive information.  *************\n" +
                "**********      Do not use in a production system!     *************\n" +
                "********************************************************************\n\n");
        // SPRING_SECURITY_FILTER_CHAIN does not exist yet since it is an alias that has not been processed, so use FILTER_CHAIN_PROXY
        if (registry.containsBeanDefinition(BeanIds.FILTER_CHAIN_PROXY)) {
            BeanDefinition fcpBeanDef = registry.getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
            BeanDefinitionBuilder debugFilterBldr = BeanDefinitionBuilder.genericBeanDefinition(DebugFilter.class);
            debugFilterBldr.addConstructorArgValue(fcpBeanDef);
            // Remove the alias to SPRING_SECURITY_FILTER_CHAIN, so that it does not override the new
            // SPRING_SECURITY_FILTER_CHAIN definition
            registry.removeAlias(BeanIds.SPRING_SECURITY_FILTER_CHAIN);
            registry.registerBeanDefinition(BeanIds.SPRING_SECURITY_FILTER_CHAIN, debugFilterBldr.getBeanDefinition());
        }
    }

    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
    }
}