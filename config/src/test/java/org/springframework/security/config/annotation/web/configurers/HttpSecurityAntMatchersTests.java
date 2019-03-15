/*
 * Copyright 2002-2015 the original author or authors.
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

import static org.fest.assertions.Assertions.assertThat;

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

/**
 * @author Rob Winch
 *
 */
public class HttpSecurityAntMatchersTests {
    AnnotationConfigWebApplicationContext context;

    MockHttpServletRequest request;
    MockHttpServletResponse response;
    MockFilterChain chain;

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
    }

    @After
    public void cleanup() {
        if(context != null) {
            context.close();
        }
    }

    // SEC-3135
    @Test
    public void antMatchersMethodAndNoPatterns() throws Exception {
        loadConfig(AntMatchersNoPatternsConfig.class);
        request.setMethod("POST");

        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @EnableWebSecurity
    @Configuration
    static class AntMatchersNoPatternsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                .requestMatchers()
                    .antMatchers(HttpMethod.POST)
                    .and()
                .authorizeRequests()
                    .anyRequest().denyAll();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication();
        }
    }

    public void loadConfig(Class<?>... configs) {
        context = new AnnotationConfigWebApplicationContext();
        context.register(configs);
        context.refresh();

        context.getAutowireCapableBeanFactory().autowireBean(this);
    }


}
