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
package org.springframework.security.config.annotation.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Class Containing the {@link Configuration} for
 * {@link PasswordEncoderConfigurerTests}. Separate to ensure the configuration
 * compiles in Java (i.e. we are not using hidden methods).
 *
 * @author Rob Winch
 * @since 3.2
 */
public class PasswordEncoderConfigurerConfigs {

    @EnableWebSecurity
    @Configuration
    static class PasswordEncoderConfig extends WebSecurityConfigurerAdapter {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            BCryptPasswordEncoder encoder = passwordEncoder();
            auth
                .inMemoryAuthentication()
                    .withUser("user").password(encoder.encode("password")).roles("USER").and()
                    .passwordEncoder(encoder);
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
        }

        @Bean
        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }

    @EnableWebSecurity
    @Configuration
    static class PasswordEncoderNoAuthManagerLoadsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            BCryptPasswordEncoder encoder = passwordEncoder();
            auth
                .inMemoryAuthentication()
                    .withUser("user").password(encoder.encode("password")).roles("USER").and()
                    .passwordEncoder(encoder);
        }

        @Bean
        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }
}
