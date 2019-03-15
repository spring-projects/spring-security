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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.context.annotation.Configuration
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.security.access.expression.SecurityExpressionHandler
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * Tests to verify that all the functionality of <anonymous> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpExpressionHandlerTests extends BaseSpringSpec {
    def "http/expression-handler@ref"() {
        when:
            def parser = new SpelExpressionParser()
            ExpressionHandlerConfig.EXPRESSION_HANDLER = Mock(SecurityExpressionHandler.class)
            ExpressionHandlerConfig.EXPRESSION_HANDLER.getExpressionParser() >> parser
            loadConfig(ExpressionHandlerConfig)
        then:
            noExceptionThrown()
    }

    @Configuration
    @EnableWebSecurity
    static class ExpressionHandlerConfig extends BaseWebConfig {
        static EXPRESSION_HANDLER;

        protected void configure(HttpSecurity http) {
            http
                .authorizeRequests()
                    .expressionHandler(EXPRESSION_HANDLER)
                    .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                    .antMatchers("/signup").permitAll()
                    .anyRequest().hasRole("USER")
        }
    }
}
