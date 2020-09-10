/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.ldap.server;

import javax.annotation.PreDestroy;

import org.junit.After;
import org.junit.Test;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link UnboundIdContainer}, specifically relating to LDIF file detection.
 *
 * @author Eleftheria Stein
 */
public class UnboundIdContainerLdifTests {

	AnnotationConfigApplicationContext appCtx;

	@After
	public void closeAppContext() {
		if (this.appCtx != null) {
			this.appCtx.close();
			this.appCtx = null;
		}
	}

	@Test
	public void unboundIdContainerWhenCustomLdifNameThenLdifLoaded() {
		this.appCtx = new AnnotationConfigApplicationContext(CustomLdifConfig.class);

		DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) this.appCtx
				.getBean(ContextSource.class);

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(contextSource);
		assertThat(template.compare("uid=bob,ou=people", "uid", "bob")).isTrue();
	}

	@Test
	public void unboundIdContainerWhenWildcardLdifNameThenLdifLoaded() {
		this.appCtx = new AnnotationConfigApplicationContext(WildcardLdifConfig.class);

		DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) this.appCtx
				.getBean(ContextSource.class);

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(contextSource);
		assertThat(template.compare("uid=bob,ou=people", "uid", "bob")).isTrue();
	}

	@Test
	public void unboundIdContainerWhenMalformedLdifThenException() {
		assertThatExceptionOfType(Exception.class)
				.isThrownBy(() -> this.appCtx = new AnnotationConfigApplicationContext(MalformedLdifConfig.class))
				.withCauseInstanceOf(IllegalStateException.class)
				.withMessageContaining("Unable to load LDIF classpath:test-server-malformed.txt");
	}

	@Test
	public void unboundIdContainerWhenMissingLdifThenException() {
		assertThatExceptionOfType(Exception.class)
				.isThrownBy(() -> this.appCtx = new AnnotationConfigApplicationContext(MissingLdifConfig.class))
				.withCauseInstanceOf(IllegalStateException.class)
				.withMessageContaining("Unable to load LDIF classpath:does-not-exist.ldif");
	}

	@Test
	public void unboundIdContainerWhenWildcardLdifNotFoundThenProceeds() {
		new AnnotationConfigApplicationContext(WildcardNoLdifConfig.class);
	}

	@Configuration
	static class CustomLdifConfig {

		private UnboundIdContainer container = new UnboundIdContainer("dc=springframework,dc=org",
				"classpath:test-server.ldif");

		@Bean
		UnboundIdContainer ldapContainer() {
			this.container.setPort(0);
			return this.container;
		}

		@Bean
		ContextSource contextSource(UnboundIdContainer container) {
			return new DefaultSpringSecurityContextSource(
					"ldap://127.0.0.1:" + container.getPort() + "/dc=springframework,dc=org");
		}

		@PreDestroy
		void shutdown() {
			this.container.stop();
		}

	}

	@Configuration
	static class WildcardLdifConfig {

		private UnboundIdContainer container = new UnboundIdContainer("dc=springframework,dc=org",
				"classpath*:test-server.ldif");

		@Bean
		UnboundIdContainer ldapContainer() {
			this.container.setPort(0);
			return this.container;
		}

		@Bean
		ContextSource contextSource(UnboundIdContainer container) {
			return new DefaultSpringSecurityContextSource(
					"ldap://127.0.0.1:" + container.getPort() + "/dc=springframework,dc=org");
		}

		@PreDestroy
		void shutdown() {
			this.container.stop();
		}

	}

	@Configuration
	static class MalformedLdifConfig {

		private UnboundIdContainer container = new UnboundIdContainer("dc=springframework,dc=org",
				"classpath:test-server-malformed.txt");

		@Bean
		UnboundIdContainer ldapContainer() {
			this.container.setPort(0);
			return this.container;
		}

		@PreDestroy
		void shutdown() {
			this.container.stop();
		}

	}

	@Configuration
	static class MissingLdifConfig {

		private UnboundIdContainer container = new UnboundIdContainer("dc=springframework,dc=org",
				"classpath:does-not-exist.ldif");

		@Bean
		UnboundIdContainer ldapContainer() {
			this.container.setPort(0);
			return this.container;
		}

		@PreDestroy
		void shutdown() {
			this.container.stop();
		}

	}

	@Configuration
	static class WildcardNoLdifConfig {

		private UnboundIdContainer container = new UnboundIdContainer("dc=springframework,dc=org",
				"classpath*:*.test.ldif");

		@Bean
		UnboundIdContainer ldapContainer() {
			this.container.setPort(0);
			return this.container;
		}

		@PreDestroy
		void shutdown() {
			this.container.stop();
		}

	}

}
