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

import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapterTests.InMemoryAuthWithWebSecurityConfigurerAdapter
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils

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
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
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
}
