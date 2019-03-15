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
package org.springframework.security.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.FatalBeanException;
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

public class Sec2515Tests extends BaseSpringSpec {

    def "SEC-2515: Prevent StackOverflow with bean graph cycle"() {
        when:
           loadConfig(StackOverflowSecurityConfig)
        then:
            thrown(FatalBeanException)
    }

    @EnableWebSecurity
    @Configuration
    static class StackOverflowSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        @Bean
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }
    }

    def "Custom Name Prevent StackOverflow with bean graph cycle"() {
        when:
           loadConfig(StackOverflowSecurityConfig)
        then:
            thrown(FatalBeanException)
    }

    @EnableWebSecurity
    @Configuration
    static class CustomBeanNameStackOverflowSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        @Bean(name="custom")
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }
    }

    def "SEC-2549: Can load with child classloader"() {
        setup:
            CanLoadWithChildConfig.AM = Mock(AuthenticationManager)
            context = new AnnotationConfigApplicationContext()
            context.classLoader = new URLClassLoader(new URL[0], context.classLoader)
            context.register(CanLoadWithChildConfig)
            context.refresh()
        when:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
        then:
            noExceptionThrown()
            1 * CanLoadWithChildConfig.AM.authenticate(_) >> new TestingAuthenticationToken("user","password","ROLE_USER")
    }

    @EnableWebSecurity
    @Configuration
    static class CanLoadWithChildConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationManager AM
        @Bean
        public AuthenticationManager am() {
            AM
        }
    }

    def "SEC-2515: @Bean still works when configure(AuthenticationManagerBuilder) used"() {
        when:
           loadConfig(SecurityConfig)
        then:
            noExceptionThrown();
    }

    @EnableWebSecurity
    @Configuration
    static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        @Bean
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth)
                throws Exception {
            auth.inMemoryAuthentication()
        }
    }
}
