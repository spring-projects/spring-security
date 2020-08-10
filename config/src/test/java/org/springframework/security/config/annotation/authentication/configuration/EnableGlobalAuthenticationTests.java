/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.annotation.authentication.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.test.SpringTestRule;

/**
 * @author Rob Winch
 *
 */
public class EnableGlobalAuthenticationTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	// gh-4086
	@Test
	public void authenticationConfigurationWhenGetAuthenticationManagerThenNotNull() throws Exception {
		this.spring.register(Config.class).autowire();

		AuthenticationConfiguration auth = spring.getContext().getBean(AuthenticationConfiguration.class);

		assertThat(auth.getAuthenticationManager()).isNotNull();
	}

	@Configuration
	@EnableGlobalAuthentication
	static class Config {

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
		}

	}

	@Test
	public void enableGlobalAuthenticationWhenNoConfigurationAnnotationThenBeanProxyingEnabled() {
		this.spring.register(BeanProxyEnabledByDefaultConfig.class).autowire();

		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);

		assertThat(parentBean.getChild()).isSameAs(childBean);
	}

	@EnableGlobalAuthentication
	static class BeanProxyEnabledByDefaultConfig {

		@Bean
		public Child child() {
			return new Child();
		}

		@Bean
		public Parent parent() {
			return new Parent(child());
		}

	}

	@Test
	public void enableGlobalAuthenticationWhenProxyBeanMethodsFalseThenBeanProxyingDisabled() {
		this.spring.register(BeanProxyDisabledConfig.class).autowire();

		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);

		assertThat(parentBean.getChild()).isNotSameAs(childBean);
	}

	@Configuration(proxyBeanMethods = false)
	@EnableGlobalAuthentication
	static class BeanProxyDisabledConfig {

		@Bean
		public Child child() {
			return new Child();
		}

		@Bean
		public Parent parent() {
			return new Parent(child());
		}

	}

	static class Parent {

		private Child child;

		Parent(Child child) {
			this.child = child;
		}

		public Child getChild() {
			return child;
		}

	}

	static class Child {

		Child() {
		}

	}

}
