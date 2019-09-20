/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web;

import java.util.Arrays;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 *
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ SpringFactoriesLoader.class })
@PowerMockIgnore({ "org.w3c.dom.*", "org.xml.sax.*", "org.apache.xerces.*", "javax.xml.parsers.*" })
public class WebSecurityConfigurerAdapterPowermockTests {
	ConfigurableWebApplicationContext context;

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void loadConfigWhenDefaultConfigurerAsSpringFactoryhenDefaultConfigurerApplied() {
		spy(SpringFactoriesLoader.class);
		DefaultConfigurer configurer = new DefaultConfigurer();
		when(SpringFactoriesLoader
				.loadFactories(AbstractHttpConfigurer.class, getClass().getClassLoader()))
			.thenReturn(Arrays.<AbstractHttpConfigurer>asList(configurer));

		loadConfig(Config.class);

		assertThat(configurer.init).isTrue();
		assertThat(configurer.configure).isTrue();
	}

	private void loadConfig(Class<?>... classes) {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setClassLoader(getClass().getClassLoader());
		context.register(classes);
		context.refresh();
		this.context = context;
	}

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) {
		}
	}

	static class DefaultConfigurer extends AbstractHttpConfigurer<DefaultConfigurer, HttpSecurity> {
		boolean init;
		boolean configure;

		@Override
		public void init(HttpSecurity builder) {
			this.init = true;
		}

		@Override
		public void configure(HttpSecurity builder) {
			this.configure = true;
		}
	}
}
