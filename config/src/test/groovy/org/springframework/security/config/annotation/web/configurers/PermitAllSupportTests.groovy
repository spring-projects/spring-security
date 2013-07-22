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

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.RequestMatcher

/**
 * @author Rob Winch
 *
 */
class PermitAllSupportTests extends BaseSpringSpec {
    def "PermitAllSupport.ExactUrlRequestMatcher"() {
        expect:
            RequestMatcher matcher = new PermitAllSupport.ExactUrlRequestMatcher(processUrl)
            matcher.matches(new MockHttpServletRequest(requestURI:requestURI,contextPath:contextPath,queryString: query)) == matches
        where:
           processUrl             | requestURI            | contextPath        | query      | matches
            "/login"              | "/sample/login"       | "/sample"          | null       | true
            "/login"              | "/sample/login"       | "/sample"          | "error"    | false
            "/login?error"        | "/sample/login"       | "/sample"          | "error"    | true
    }

    def "PermitAllSupport throws Exception when authorizedUrls() not invoked"() {
        when:
            loadConfig(NoAuthorizedUrlsConfig)
        then:
            BeanCreationException e = thrown()
            e.message.contains "permitAll only works with HttpSecurity.authorizeRequests"

    }

    @EnableWebSecurity
    @Configuration
    static class NoAuthorizedUrlsConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .formLogin()
                    .permitAll()
        }
    }
}
