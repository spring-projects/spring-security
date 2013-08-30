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
package org.springframework.security.config.annotation.web.configuration;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.bind.support.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * Used to add a {@link RequestDataValueProcessor} for Spring MVC and Spring
 * Security CSRF integration. This configuration is added whenever
 * {@link EnableWebMvc} is added by {@link SpringWebMvcImportSelector} and the
 * DispatcherServlet is present on the classpath. It also adds the
 * {@link AuthenticationPrincipalArgumentResolver} as a
 * {@link HandlerMethodArgumentResolver}.
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
class WebMvcSecurityConfiguration extends WebMvcConfigurerAdapter {

    @Override
    public void addArgumentResolvers(
            List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
    }

    @Bean
    public RequestDataValueProcessor requestDataValueProcessor() {
        return CsrfRequestDataValueProcessor.create();
    }
}
