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
package org.springframework.security.config.annotation.web;

import static org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapterTestsConfigs.*
import static org.junit.Assert.*

import javax.sql.DataSource

import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.ldap.core.support.BaseLdapPathContextSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.ldap.DefaultSpringSecurityContextSource
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * @author Rob Winch
 *
 */
class WebSecurityConfigurerAdapterTests extends BaseSpringSpec {

    def "MessageSources populated on AuthenticationProviders"() {
        when:
            loadConfig(MessageSourcesPopulatedConfig)
            List<AuthenticationProvider> providers = authenticationProviders()
        then:
            providers*.messages*.messageSource == [context,context,context,context]
    }

    def "messages set when using WebSecurityConfigurerAdapter"() {
        when:
            loadConfig(InMemoryAuthWithWebSecurityConfigurerAdapter)
        then:
            authenticationManager.messages.messageSource instanceof ApplicationContext
    }

    def "AuthenticationEventPublisher is registered for Web registerAuthentication"() {
        when:
            loadConfig(InMemoryAuthWithWebSecurityConfigurerAdapter)
        then:
            authenticationManager.parent.eventPublisher instanceof DefaultAuthenticationEventPublisher
        when:
            Authentication token = new UsernamePasswordAuthenticationToken("user","password")
            authenticationManager.authenticate(token)
        then: "We only receive the AuthenticationSuccessEvent once"
            InMemoryAuthWithWebSecurityConfigurerAdapter.EVENTS.size() == 1
            InMemoryAuthWithWebSecurityConfigurerAdapter.EVENTS[0].authentication.name == token.principal
    }

    @EnableWebSecurity
    @Configuration
    static class InMemoryAuthWithWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationListener<AuthenticationSuccessEvent> {
        static List<AuthenticationSuccessEvent> EVENTS = []
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }

        @Override
        public void onApplicationEvent(AuthenticationSuccessEvent e) {
            EVENTS.add(e)
        }
    }

    def "Override ContentNegotiationStrategy with @Bean"() {
        setup:
            OverrideContentNegotiationStrategySharedObjectConfig.CNS = Mock(ContentNegotiationStrategy)
        when:
            loadConfig(OverrideContentNegotiationStrategySharedObjectConfig)
        then:
            context.getBean(OverrideContentNegotiationStrategySharedObjectConfig).http.getSharedObject(ContentNegotiationStrategy) == OverrideContentNegotiationStrategySharedObjectConfig.CNS
    }

    @EnableWebSecurity
    @Configuration
    static class OverrideContentNegotiationStrategySharedObjectConfig extends WebSecurityConfigurerAdapter {
        static ContentNegotiationStrategy CNS

        @Bean
        public ContentNegotiationStrategy cns() {
            return CNS
        }
    }

    def "ContentNegotiationStrategy shareObject defaults to Header with no @Bean"() {
        when:
            loadConfig(ContentNegotiationStrategyDefaultSharedObjectConfig)
        then:
            context.getBean(ContentNegotiationStrategyDefaultSharedObjectConfig).http.getSharedObject(ContentNegotiationStrategy).class == HeaderContentNegotiationStrategy
    }

    @EnableWebSecurity
    @Configuration
    static class ContentNegotiationStrategyDefaultSharedObjectConfig extends WebSecurityConfigurerAdapter {}
}
