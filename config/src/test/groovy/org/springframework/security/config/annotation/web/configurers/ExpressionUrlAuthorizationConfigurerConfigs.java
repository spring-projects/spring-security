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
package org.springframework.security.config.annotation.web.configurers;


import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

/**
 *
 * @author Rob Winch
 *
 */
public class ExpressionUrlAuthorizationConfigurerConfigs {

    /**
     * Ensure that All additional properties properly compile and chain properly
     */
    @EnableWebSecurity
    @Configuration
    static class AllPropertiesWorkConfig extends WebSecurityConfigurerAdapter {

        @SuppressWarnings("rawtypes")
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            SecurityExpressionHandler<FilterInvocation> handler = new DefaultWebSecurityExpressionHandler();
            WebExpressionVoter expressionVoter = new WebExpressionVoter();
            AffirmativeBased adm = new AffirmativeBased(Arrays.<AccessDecisionVoter>asList(expressionVoter));
            http
                .authorizeRequests()
                    .expressionHandler(handler)
                    .accessDecisionManager(adm)
                    .filterSecurityInterceptorOncePerRequest(true)
                    .antMatchers("/a","/b").hasRole("ADMIN")
                    .anyRequest().permitAll()
                    .and()
                .formLogin();
        }
    }

    @EnableWebSecurity
    @Configuration
    static class UseBeansInExpressions extends WebSecurityConfigurerAdapter {

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**").hasRole("USER")
                    .antMatchers("/allow/**").access("@permission.check(authentication,'user')")
                    .anyRequest().access("@permission.check(authentication,'admin')");
        }

        @Bean
        public Checker permission() {
            return new Checker();
        }

        static class Checker {
            public boolean check(Authentication authentication, String customArg) {
                return authentication.getName().contains(customArg);
            }
        }
    }

    @EnableWebSecurity
    @Configuration
    static class CustomExpressionRootConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .expressionHandler(expressionHandler())
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**").hasRole("USER")
                    .antMatchers("/allow/**").access("check('user')")
                    .anyRequest().access("check('admin')");
        }

        @Bean
        public CustomExpressionHandler expressionHandler() {
            return new CustomExpressionHandler();
        }

        static class CustomExpressionHandler extends DefaultWebSecurityExpressionHandler {

            @Override
            protected SecurityExpressionOperations createSecurityExpressionRoot(
                    Authentication authentication, FilterInvocation fi) {
                WebSecurityExpressionRoot root = new CustomExpressionRoot(authentication, fi);
                root.setPermissionEvaluator(getPermissionEvaluator());
                root.setTrustResolver(new AuthenticationTrustResolverImpl());
                root.setRoleHierarchy(getRoleHierarchy());
                return root;
            }
        }

        static class CustomExpressionRoot extends WebSecurityExpressionRoot {

            public CustomExpressionRoot(Authentication a, FilterInvocation fi) {
                super(a, fi);
            }

            public boolean check(String customArg) {
                Authentication auth = this.getAuthentication();
                return auth.getName().contains(customArg);
            }
        }
    }
}
