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

import org.aopalliance.intercept.MethodInterceptor
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.PermissionEvaluator
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextHolder

/**
 *
 * @author Rob Winch
 */
public class GlobalMethodSecurityConfigurationTests extends BaseSpringSpec {
    def "messages set when using GlobalMethodSecurityConfiguration"() {
        when:
            loadConfig(InMemoryAuthWithGlobalMethodSecurityConfig)
        then:
            authenticationManager.messages.messageSource instanceof ApplicationContext
    }

    def "AuthenticationEventPublisher is registered GlobalMethodSecurityConfiguration"() {
        when:
            loadConfig(InMemoryAuthWithGlobalMethodSecurityConfig)
        then:
            authenticationManager.eventPublisher instanceof DefaultAuthenticationEventPublisher
        when:
            Authentication auth = new UsernamePasswordAuthenticationToken("user",null,AuthorityUtils.createAuthorityList("ROLE_USER"))
            authenticationManager.eventPublisher.publishAuthenticationSuccess(auth)
        then:
            InMemoryAuthWithGlobalMethodSecurityConfig.EVENT.authentication == auth
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class InMemoryAuthWithGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration implements ApplicationListener<AuthenticationSuccessEvent> {
        static AuthenticationSuccessEvent EVENT

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Override
        public void onApplicationEvent(AuthenticationSuccessEvent e) {
            EVENT = e
        }
    }

    AuthenticationManager getAuthenticationManager() {
        context.getBean(MethodInterceptor).authenticationManager
    }

    def "AuthenticationTrustResolver autowires"() {
        setup:
            CustomTrustResolverConfig.TR = Mock(AuthenticationTrustResolver)
        when:
            loadConfig(CustomTrustResolverConfig)
            def preAdviceVoter = context.getBean(MethodInterceptor).accessDecisionManager.decisionVoters.find { it instanceof PreInvocationAuthorizationAdviceVoter}
        then:
            preAdviceVoter.preAdvice.expressionHandler.trustResolver == CustomTrustResolverConfig.TR
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    static class CustomTrustResolverConfig extends GlobalMethodSecurityConfiguration {
        static AuthenticationTrustResolver TR

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Bean
        public AuthenticationTrustResolver tr() {
            return TR
        }
    }

    def "SEC-2301: DefaultWebSecurityExpressionHandler has BeanResolver set"() {
        setup:
            SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user", "password","ROLE_USER"))
            loadConfig(ExpressionHandlerHasBeanResolverSetConfig)
            def service = context.getBean(ServiceImpl)
        when: "service with bean reference on PreAuthorize invoked"
            service.message()
        then: "properly throws AccessDeniedException"
            thrown(AccessDeniedException)
        when: "service with bean reference on PreAuthorize invoked"
            context.getBean(CustomAuthzService).grantAccess = true
            service.message()
        then: "grants access too"
            noExceptionThrown()
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
    static class ExpressionHandlerHasBeanResolverSetConfig extends GlobalMethodSecurityConfiguration {

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Bean
        public ServiceImpl service() {
            return new ServiceImpl()
        }

        @Bean
        public CustomAuthzService authz() {
            return new CustomAuthzService()
        }
    }

    static class ServiceImpl {
        @PreAuthorize("@authz.authorize()")
        public String message() {
            null
        }
    }

    static class CustomAuthzService {
        boolean grantAccess

        public boolean authorize() {
            grantAccess
        }
    }

    def "Method Security supports annotations on interface parameter names"() {
        setup:
            SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user", "password","ROLE_USER"))
            loadConfig(MethodSecurityServiceConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        when: "service with annotated argument"
            service.postAnnotation('deny')
        then: "properly throws AccessDeniedException"
            thrown(AccessDeniedException)
        when: "service with annotated argument"
            service.postAnnotation('grant')
        then: "properly throws AccessDeniedException"
            noExceptionThrown()
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    static class MethodSecurityServiceConfig extends GlobalMethodSecurityConfiguration {

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Bean
        public MethodSecurityService service() {
            new MethodSecurityServiceImpl()
        }
    }

    def "GlobalMethodSecurityConfiguration autowires PermissionEvaluator"() {
        setup:
            SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user", "password","ROLE_USER"))
            PermissionEvaluator evaluator = Mock()
            AutowirePermissionEvaluatorConfig.PE = evaluator
            loadConfig(AutowirePermissionEvaluatorConfig)
            MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
            service.hasPermission("something")
        then:
            1 * evaluator.hasPermission(_, "something", "read") >> true
        when:
            service.hasPermission("something")
        then:
            1 * evaluator.hasPermission(_, "something", "read") >> false
            thrown(AccessDeniedException)
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class AutowirePermissionEvaluatorConfig extends GlobalMethodSecurityConfiguration {
        static PermissionEvaluator PE

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Bean
        public PermissionEvaluator pe() {
            PE
        }

        @Bean
        public MethodSecurityService service() {
            new MethodSecurityServiceImpl()
        }
    }

    def "GlobalMethodSecurityConfiguration does not failw with multiple PermissionEvaluator"() {
        when:
            loadConfig(MultiPermissionEvaluatorConfig)
        then:
            noExceptionThrown()
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class MultiPermissionEvaluatorConfig extends GlobalMethodSecurityConfiguration {
        static PermissionEvaluator PE

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Bean
        public PermissionEvaluator pe() {
            PE
        }

        @Bean
        public PermissionEvaluator pe2() {
            PE
        }

        @Bean
        public MethodSecurityService service() {
            new MethodSecurityServiceImpl()
        }
    }
}
