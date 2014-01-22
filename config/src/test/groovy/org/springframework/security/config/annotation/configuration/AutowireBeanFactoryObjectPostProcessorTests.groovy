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
package org.springframework.security.config.annotation.configuration

import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.beans.factory.BeanFactoryAware
import org.springframework.beans.factory.DisposableBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.config.AutowireCapableBeanFactory
import org.springframework.beans.factory.support.BeanNameGenerator;
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.context.EnvironmentAware
import org.springframework.context.MessageSourceAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.ClassPathXmlApplicationContext
import org.springframework.mock.web.MockServletConfig
import org.springframework.mock.web.MockServletContext
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.web.context.ServletConfigAware
import org.springframework.web.context.ServletContextAware
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext

/**
 *
 * @author Rob Winch
 */
class AutowireBeanFactoryObjectPostProcessorTests extends BaseSpringSpec {

    def "Verify All Aware methods are invoked"() {
        setup:
            ApplicationContextAware contextAware = Mock(ApplicationContextAware)
            ApplicationEventPublisherAware publisher = Mock(ApplicationEventPublisherAware)
            BeanClassLoaderAware classloader = Mock(BeanClassLoaderAware)
            BeanFactoryAware beanFactory = Mock(BeanFactoryAware)
            EnvironmentAware environment = Mock(EnvironmentAware)
            MessageSourceAware messageSource = Mock(MessageSourceAware)
            ServletConfigAware servletConfig = Mock(ServletConfigAware)
            ServletContextAware servletContext = Mock(ServletContextAware)
            DisposableBean disposable = Mock(DisposableBean)

            context = new AnnotationConfigWebApplicationContext([servletConfig:new MockServletConfig(),servletContext:new MockServletContext()])
            context.register(Config)
            context.refresh()
            context.start()

            ObjectPostProcessor opp = context.getBean(ObjectPostProcessor)
        when:
            opp.postProcess(contextAware)
        then:
            1 * contextAware.setApplicationContext(!null)

        when:
            opp.postProcess(publisher)
        then:
            1 * publisher.setApplicationEventPublisher(!null)

        when:
            opp.postProcess(classloader)
        then:
            1 * classloader.setBeanClassLoader(!null)

        when:
            opp.postProcess(beanFactory)
        then:
            1 * beanFactory.setBeanFactory(!null)

        when:
            opp.postProcess(environment)
        then:
            1 * environment.setEnvironment(!null)

        when:
            opp.postProcess(messageSource)
        then:
            1 * messageSource.setMessageSource(!null)

        when:
            opp.postProcess(servletConfig)
        then:
            1 * servletConfig.setServletConfig(!null)

        when:
            opp.postProcess(servletContext)
        then:
            1 * servletContext.setServletContext(!null)

        when:
            opp.postProcess(disposable)
            context.close()
            context = null
        then:
            1 * disposable.destroy()
    }

    @Configuration
    static class Config {
        @Bean
        public ObjectPostProcessor objectPostProcessor(AutowireCapableBeanFactory beanFactory) {
            return new AutowireBeanFactoryObjectPostProcessor(beanFactory);
        }
    }

    def "SEC-2382: AutowireBeanFactoryObjectPostProcessor works with BeanNameAutoProxyCreator"() {
        when:
            // must load with XML for BeanPostProcessors to work
            context = new ClassPathXmlApplicationContext("AutowireBeanFactoryObjectPostProcessorTests-aopconfig.xml", getClass());
        then:
            noExceptionThrown()
        and: "make sure autoproxying was actually enabled"
            context.getBean(MyAdvisedBean).doStuff() == "null"
    }

    @Configuration
    static class WithBanNameAutoProxyCreatorConfig {
        @Bean
        public ObjectPostProcessor objectPostProcessor(AutowireCapableBeanFactory beanFactory) {
            return new AutowireBeanFactoryObjectPostProcessor(beanFactory)
        }

        @Autowired
        public void configure(ObjectPostProcessor<Object> p) {
            p.postProcess(new Object())
        }
    }
}
