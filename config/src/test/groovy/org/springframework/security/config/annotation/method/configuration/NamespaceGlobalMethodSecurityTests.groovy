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
package org.springframework.security.config.annotation.method.configuration

import static org.fest.assertions.Assertions.assertThat
import static org.junit.Assert.fail

import java.lang.reflect.Method

import org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator
import org.springframework.beans.factory.BeanCreationException
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.AdviceMode
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.Ordered
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.access.intercept.AfterInvocationManager
import org.springframework.security.access.intercept.RunAsManager
import org.springframework.security.access.intercept.RunAsManagerImpl
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource
import org.springframework.security.access.method.MethodSecurityMetadataSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.BaseAuthenticationConfig;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder

/**
 *
 * @author Rob Winch
 */
public class NamespaceGlobalMethodSecurityTests extends BaseSpringSpec {
    def setup() {
        SecurityContextHolder.getContext().setAuthentication(
                        new TestingAuthenticationToken("user", "password","ROLE_USER"))
    }

    // --- access-decision-manager-ref ---

    def "custom AccessDecisionManager can be used"() {
        setup: "Create an instance with an AccessDecisionManager that always denies access"
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,CustomAccessDecisionManagerConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
            service.preAuthorize()
        then:
            thrown(AccessDeniedException)
        when:
            service.secured()
        then:
            thrown(AccessDeniedException)
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
    public static class CustomAccessDecisionManagerConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected AccessDecisionManager accessDecisionManager() {
            return new DenyAllAccessDecisionManager()
        }

        public static class DenyAllAccessDecisionManager implements AccessDecisionManager {
            public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) {
                throw new AccessDeniedException("Always Denied")
            }
            public boolean supports(ConfigAttribute attribute) {
                return true
            }
            public boolean supports(Class<?> clazz) {
                return true
            }
        }
    }

    // --- authentication-manager-ref ---

    def "custom AuthenticationManager can be used"() {
        when:
            context = new AnnotationConfigApplicationContext(CustomAuthenticationConfig)
        MethodSecurityInterceptor interceptor = context.getBean(MethodSecurityInterceptor)
            interceptor.authenticationManager.authenticate(SecurityContextHolder.context.authentication)
        then:
            thrown(UnsupportedOperationException)
    }

    @Configuration
    @EnableGlobalMethodSecurity
    public static class CustomAuthenticationConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected AuthenticationManager authenticationManager() {
            return new AuthenticationManager() {
                Authentication authenticate(Authentication authentication) {
                    throw new UnsupportedOperationException()
                }
            }
        }
    }

    // --- jsr250-annotations ---

    def "enable jsr250"() {
        when:
            context = new AnnotationConfigApplicationContext(Jsr250Config)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        then: "@Secured and @PreAuthorize are ignored"
            service.secured() == null
            service.preAuthorize() ==  null

        when: "@DenyAll method invoked"
            service.jsr250()
        then: "access is denied"
            thrown(AccessDeniedException)
        when: "@PermitAll method invoked"
            String jsr250PermitAll = service.jsr250PermitAll()
        then: "access is allowed"
            jsr250PermitAll == null
    }

    @EnableGlobalMethodSecurity(jsr250Enabled = true)
    @Configuration
    public static class Jsr250Config extends BaseMethodConfig {
    }

    // --- metadata-source-ref ---

    def "custom MethodSecurityMetadataSource can be used with higher priority than other sources"() {
        setup:
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,CustomMethodSecurityMetadataSourceConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
            service.preAuthorize()
        then:
            thrown(AccessDeniedException)
        when:
            service.secured()
        then:
            thrown(AccessDeniedException)
        when:
            service.jsr250()
        then:
            thrown(AccessDeniedException)
    }

    @Configuration
    @EnableGlobalMethodSecurity
    public static class CustomMethodSecurityMetadataSourceConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
            return new AbstractMethodSecurityMetadataSource() {
                public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
                    // require ROLE_NOBODY for any method on MethodSecurityService class
                    return MethodSecurityService.isAssignableFrom(targetClass) ? [new SecurityConfig("ROLE_NOBODY")] : []
                }
                public Collection<ConfigAttribute> getAllConfigAttributes() {
                    return null
                }
            }
        }
    }

    // --- mode ---

    def "aspectj mode works"() {
        when:
            context = new AnnotationConfigApplicationContext(AspectJModeConfig)
        then:
            AnnotationAwareAspectJAutoProxyCreator autoProxyCreator = context.getBean(AnnotationAwareAspectJAutoProxyCreator)
            autoProxyCreator.proxyTargetClass == true
    }

    @Configuration
    @EnableGlobalMethodSecurity(mode = AdviceMode.ASPECTJ, proxyTargetClass = true)
    public static class AspectJModeConfig extends BaseMethodConfig {
    }

    def "aspectj mode works extending GlobalMethodSecurityConfiguration"() {
        when:
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,AspectJModeExtendsGMSCConfig)
        then:
            AnnotationAwareAspectJAutoProxyCreator autoProxyCreator = context.getBean(AnnotationAwareAspectJAutoProxyCreator)
            autoProxyCreator.proxyTargetClass == false
    }

    @Configuration
    @EnableGlobalMethodSecurity(mode = AdviceMode.ASPECTJ)
    public static class AspectJModeExtendsGMSCConfig extends GlobalMethodSecurityConfiguration {
    }

    // --- order ---

    def order() {
        when:
            context = new AnnotationConfigApplicationContext(CustomOrderConfig)
            MethodSecurityMetadataSourceAdvisor advisor = context.getBean(MethodSecurityMetadataSourceAdvisor)
        then:
            advisor.order == 135
    }

    @Configuration
    @EnableGlobalMethodSecurity(order = 135)
    public static class CustomOrderConfig extends BaseMethodConfig {
    }

    def "order is defaulted to Ordered.LOWEST_PRECEDENCE when using @EnableGlobalMethodSecurity"() {
        when:
            context = new AnnotationConfigApplicationContext(DefaultOrderConfig)
            MethodSecurityMetadataSourceAdvisor advisor = context.getBean(MethodSecurityMetadataSourceAdvisor)
        then:
            advisor.order == Ordered.LOWEST_PRECEDENCE
    }

    @Configuration
    @EnableGlobalMethodSecurity
    public static class DefaultOrderConfig extends BaseMethodConfig {
    }

    def "order is defaulted to Ordered.LOWEST_PRECEDENCE when extending GlobalMethodSecurityConfiguration"() {
        when:
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,DefaultOrderExtendsMethodSecurityConfig)
            MethodSecurityMetadataSourceAdvisor advisor = context.getBean(MethodSecurityMetadataSourceAdvisor)
        then:
            advisor.order == Ordered.LOWEST_PRECEDENCE
    }

    @Configuration
    @EnableGlobalMethodSecurity
    public static class DefaultOrderExtendsMethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    }

    // --- pre-post-annotations ---

    def preAuthorize() {
        when:
            context = new AnnotationConfigApplicationContext(PreAuthorizeConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        then:
            service.secured() == null
            service.jsr250() == null

        when:
            service.preAuthorize()
        then:
            thrown(AccessDeniedException)
    }

    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @Configuration
    public static class PreAuthorizeConfig extends BaseMethodConfig {
    }

    def "prePostEnabled extends GlobalMethodSecurityConfiguration"() {
        when:
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,PreAuthorizeExtendsGMSCConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        then:
            service.secured() == null
            service.jsr250() == null

        when:
            service.preAuthorize()
        then:
            thrown(AccessDeniedException)
    }

    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @Configuration
    public static class PreAuthorizeExtendsGMSCConfig extends GlobalMethodSecurityConfiguration {
    }

    // --- proxy-target-class ---

    def "proxying classes works"() {
        when:
            context = new AnnotationConfigApplicationContext(ProxyTargetClass)
            MethodSecurityServiceImpl service = context.getBean(MethodSecurityServiceImpl)
        then:
            noExceptionThrown()
    }

    @EnableGlobalMethodSecurity(proxyTargetClass = true)
    @Configuration
    public static class ProxyTargetClass extends BaseMethodConfig {
    }

    def "proxying interfaces works"() {
        when:
            context = new AnnotationConfigApplicationContext(PreAuthorizeConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        then: "we get an instance of the interface"
            noExceptionThrown()
        when: "try to cast to the class"
            MethodSecurityServiceImpl serviceImpl = service
        then: "we get a class cast exception"
            thrown(ClassCastException)
    }

    // --- run-as-manager-ref ---

    def "custom RunAsManager"() {
        when:
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,CustomRunAsManagerConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        then:
            service.runAs().authorities.find { it.authority == "ROLE_RUN_AS_SUPER"}
    }

    @Configuration
    @EnableGlobalMethodSecurity(securedEnabled = true)
    public static class CustomRunAsManagerConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected RunAsManager runAsManager() {
            RunAsManagerImpl runAsManager = new RunAsManagerImpl()
            runAsManager.setKey("some key")
            return runAsManager
        }
    }

    // --- secured-annotation ---

    def "secured enabled"() {
        setup:
            context = new AnnotationConfigApplicationContext(SecuredConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
            service.secured()
        then:
            thrown(AccessDeniedException)
        and: "service with ROLE_USER allowed"
            service.securedUser() == null
        and:
            service.preAuthorize() == null
            service.jsr250() == null
    }

    @EnableGlobalMethodSecurity(securedEnabled = true)
    @Configuration
    public static class SecuredConfig extends BaseMethodConfig {
    }

    // --- after-invocation-provider

    def "custom AfterInvocationManager"() {
        setup:
            context = new AnnotationConfigApplicationContext(BaseMethodConfig,CustomAfterInvocationManagerConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
            service.preAuthorizePermitAll()
        then:
            AccessDeniedException e = thrown()
            e.message == "custom AfterInvocationManager"
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class CustomAfterInvocationManagerConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected AfterInvocationManager afterInvocationManager() {
            return new AfterInvocationManagerStub()
        }

        public static class AfterInvocationManagerStub implements AfterInvocationManager {
            Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> attributes,
                Object returnedObject) throws AccessDeniedException {
                throw new AccessDeniedException("custom AfterInvocationManager")
            }

            boolean supports(ConfigAttribute attribute) {
                return true
            }
            boolean supports(Class<?> clazz) {
                return true
            }
        }
    }

    // --- misc ---

    def "good error message when no Enable annotation"() {
        when:
            context = new AnnotationConfigApplicationContext(ExtendsNoEnableAnntotationConfig)
            MethodSecurityInterceptor interceptor = context.getBean(MethodSecurityInterceptor)
            interceptor.authenticationManager.authenticate(SecurityContextHolder.context.authentication)
        then:
            BeanCreationException e = thrown()
            e.message.contains(EnableGlobalMethodSecurity.class.getName() + " is required")
    }

    @Configuration
    public static class ExtendsNoEnableAnntotationConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected AuthenticationManager authenticationManager() {
            return new AuthenticationManager() {
                Authentication authenticate(Authentication authentication) {
                    throw new UnsupportedOperationException()
                }
            }
        }
    }

    def "import subclass of GlobalMethodSecurityConfiguration"() {
        when:
            context = new AnnotationConfigApplicationContext(ImportSubclassGMSCConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        then:
            service.secured() == null
            service.jsr250() == null

        when:
            service.preAuthorize()
        then:
            thrown(AccessDeniedException)
    }

    @Configuration
    @Import(PreAuthorizeExtendsGMSCConfig)
    public static class ImportSubclassGMSCConfig extends BaseMethodConfig {
    }

    @Configuration
    public static class BaseMethodConfig extends BaseAuthenticationConfig {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }
    }
}
