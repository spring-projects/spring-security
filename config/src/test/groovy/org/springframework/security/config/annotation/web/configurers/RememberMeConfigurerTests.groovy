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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter

/**
 * Tests for RememberMeConfigurer that flex edge cases. {@link NamespaceRememberMeTests} demonstrate mapping of the XML namespace to Java Config.
 *
 * @author Rob Winch
 */
public class RememberMeConfigurerTests extends BaseSpringSpec {

    def "rememberMe() null UserDetailsService provides meaningful error"() {
        when: "Load Config without UserDetailsService specified"
            loadConfig(NullUserDetailsConfig)
        then: "A good error message is provided"
            Exception success = thrown()
            success.message.contains "Invoke RememberMeConfigurer#userDetailsService(UserDetailsService) or see its javadoc for alternative approaches."
    }

    @EnableWebSecurity
    @Configuration
    static class NullUserDetailsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .and()
                .rememberMe()
        }
    }

    def "rememberMe ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .rememberMe()
                    .userDetailsService(authenticationBldr.getDefaultUserDetailsService())
                    .and()
                .build()

        then: "RememberMeAuthenticationFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as RememberMeAuthenticationFilter) >> {RememberMeAuthenticationFilter o -> o}
    }

    def "invoke rememberMe twice does not reset"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .rememberMe()
                    .userDetailsService(authenticationBldr.getDefaultUserDetailsService())
                    .and()
                .rememberMe()
        then: "RememberMeAuthenticationFilter is registered with LifecycleManager"
            http.getConfigurer(RememberMeConfigurer).userDetailsService != null
    }
}
