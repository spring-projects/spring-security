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
package org.springframework.security.config.annotation.web.configurers;


import java.util.Arrays;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

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
}
