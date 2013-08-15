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

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.util.ClassUtils;

/**
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ClassUtils.class})
public class CsrfConfigurerNoWebMvcTests {
    ConfigurableApplicationContext context;

    @After
    public void teardown() {
        if(context != null) {
            context.close();
        }
    }

    @Test
    public void missingDispatcherServletPreventsCsrfRequestDataValueProcessor() {
        spy(ClassUtils.class);
        when(ClassUtils.isPresent(eq("org.springframework.web.servlet.DispatcherServlet"), any(ClassLoader.class))).thenReturn(false);

        loadContext(CsrfDefaultsConfig.class);

        assertThat(context.containsBeanDefinition("requestDataValueProcessor")).isFalse();
    }

    @Test
    public void findDispatcherServletPreventsCsrfRequestDataValueProcessor() {
        loadContext(CsrfDefaultsConfig.class);

        assertThat(context.containsBeanDefinition("requestDataValueProcessor")).isTrue();
    }

    @EnableWebSecurity
    @Configuration
    static class CsrfDefaultsConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
        }
    }

    private void loadContext(Class<?> configs) {
        AnnotationConfigApplicationContext annotationConfigApplicationContext = new AnnotationConfigApplicationContext();
        annotationConfigApplicationContext.register(configs);
        annotationConfigApplicationContext.refresh();
        this.context = annotationConfigApplicationContext;
    }
}
