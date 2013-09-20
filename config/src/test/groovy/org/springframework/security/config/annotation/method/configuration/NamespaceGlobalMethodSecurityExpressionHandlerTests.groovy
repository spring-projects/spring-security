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

import java.io.Serializable;

import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.method.configuration.NamespaceGlobalMethodSecurityTests.BaseMethodConfig;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder

/**
 *
 * @author Rob Winch
 */
public class NamespaceGlobalMethodSecurityExpressionHandlerTests extends BaseSpringSpec {
    def setup() {
        SecurityContextHolder.getContext().setAuthentication(
                        new TestingAuthenticationToken("user", "password","ROLE_USER"))
    }

    def "global-method-security/expression-handler @PreAuthorize"() {
        setup:
        context = new AnnotationConfigApplicationContext(BaseMethodConfig,CustomAccessDecisionManagerConfig)
        MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
        service.hasPermission("granted")
        then:
        noExceptionThrown()
        when:
        service.hasPermission("denied")
        then:
        thrown(AccessDeniedException)
    }

    def "global-method-security/expression-handler @PostAuthorize"() {
        setup:
        context = new AnnotationConfigApplicationContext(BaseMethodConfig,CustomAccessDecisionManagerConfig)
        MethodSecurityService service = context.getBean(MethodSecurityService)
        when:
        service.postHasPermission("granted")
        then:
        noExceptionThrown()
        when:
        service.postHasPermission("denied")
        then:
        thrown(AccessDeniedException)
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class CustomAccessDecisionManagerConfig extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler()
            expressionHandler.permissionEvaluator = new PermissionEvaluator() {
                boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
                    "granted" == targetDomainObject
                }
                boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
                    throw new UnsupportedOperationException()
                }
            }
            return expressionHandler
        }
    }
}
