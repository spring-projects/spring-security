/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration.aot;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;
import org.springframework.aot.test.generate.TestGenerationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.aot.ApplicationContextAotGenerator;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AOT Tests for {@code PrePostMethodSecurityConfiguration}.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
public class EnableMethodSecurityAotTests {

	private final ApplicationContextAotGenerator generator = new ApplicationContextAotGenerator();

	private final GenerationContext context = new TestGenerationContext();

	@Test
	void whenProcessAheadOfTimeThenCreatesAuthorizationProxies() {
		AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
		context.register(AppConfig.class);
		this.generator.processAheadOfTime(context, this.context);
		RuntimeHints hints = this.context.getRuntimeHints();
		assertThat(hints.reflection().getTypeHint(TypeReference.of(cglibClassName(Message.class)))).isNotNull();
		assertThat(hints.reflection().getTypeHint(TypeReference.of(cglibClassName(User.class)))).isNotNull();
		assertThat(hints.proxies()
			.jdkProxyHints()
			.anyMatch((hint) -> hint.getProxiedInterfaces().contains(TypeReference.of(UserProjection.class)))).isTrue();
	}

	private static String cglibClassName(Class<?> clazz) {
		return clazz.getCanonicalName() + "$$SpringCGLIB$$0";
	}

	@Configuration
	@EnableMethodSecurity
	@EnableJpaRepositories
	static class AppConfig {

		@Bean
		DataSource dataSource() {
			EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
			return builder.setType(EmbeddedDatabaseType.HSQL).build();
		}

		@Bean
		LocalContainerEntityManagerFactoryBean entityManagerFactory() {
			HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
			vendorAdapter.setGenerateDdl(true);
			LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
			factory.setJpaVendorAdapter(vendorAdapter);
			factory.setPackagesToScan("org.springframework.security.config.annotation.method.configuration.aot");
			factory.setDataSource(dataSource());
			return factory;
		}

	}

}
