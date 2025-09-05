/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.aot.hint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.beans.factory.aot.BeanRegistrationAotContribution;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RegisteredBean;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerBeanRegistrationAotProcessor}.
 *
 * @author William Koch
 */
class OAuth2AuthorizationServerBeanRegistrationAotProcessorTests {

	private OAuth2AuthorizationServerBeanRegistrationAotProcessor processor;

	private DefaultListableBeanFactory defaultListableBeanFactory;

	@BeforeEach
	void setUp() {
		this.processor = new OAuth2AuthorizationServerBeanRegistrationAotProcessor();
		this.defaultListableBeanFactory = new DefaultListableBeanFactory();

	}

	@ParameterizedTest
	@ValueSource(classes = { JdbcOAuth2AuthorizationService.class, CustomJdbcOAuth2AuthorizationService.class,
			JdbcRegisteredClientRepository.class, CustomJdbcRegisteredClientRepository.class })
	void processAheadOfTimeWhenBeanTypeJdbcBasedImplThenReturnContribution(Class<?> beanClass) {
		this.defaultListableBeanFactory.registerBeanDefinition("beanName", new RootBeanDefinition(beanClass));

		BeanRegistrationAotContribution aotContribution = this.processor
			.processAheadOfTime(RegisteredBean.of(this.defaultListableBeanFactory, "beanName"));

		assertThat(aotContribution).isNotNull();
	}

	@ParameterizedTest
	@ValueSource(classes = { InMemoryOAuth2AuthorizationService.class, InMemoryRegisteredClientRepository.class,
			Object.class })
	void processAheadOfTimeWhenBeanTypeNotJdbcBasedImplThenDoesNotReturnContribution(Class<?> beanClass) {
		this.defaultListableBeanFactory.registerBeanDefinition("beanName", new RootBeanDefinition(beanClass));

		BeanRegistrationAotContribution aotContribution = this.processor
			.processAheadOfTime(RegisteredBean.of(this.defaultListableBeanFactory, "beanName"));

		assertThat(aotContribution).isNull();
	}

	@Test
	void processAheadOfTimeWhenMultipleBeanTypeJdbcBasedImplThenReturnContributionOnce() {
		this.defaultListableBeanFactory.registerBeanDefinition("oauth2AuthorizationService",
				new RootBeanDefinition(JdbcOAuth2AuthorizationService.class));

		this.defaultListableBeanFactory.registerBeanDefinition("registeredClientRepository",
				new RootBeanDefinition(CustomJdbcRegisteredClientRepository.class));

		BeanRegistrationAotContribution firstAotContribution = this.processor
			.processAheadOfTime(RegisteredBean.of(this.defaultListableBeanFactory, "oauth2AuthorizationService"));

		BeanRegistrationAotContribution secondAotContribution = this.processor
			.processAheadOfTime(RegisteredBean.of(this.defaultListableBeanFactory, "registeredClientRepository"));

		assertThat(firstAotContribution).isNotNull();
		assertThat(secondAotContribution).isNull();
	}

	static class CustomJdbcOAuth2AuthorizationService extends JdbcOAuth2AuthorizationService {

		CustomJdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			super(jdbcOperations, registeredClientRepository);
		}

	}

	static class CustomJdbcRegisteredClientRepository extends JdbcRegisteredClientRepository {

		CustomJdbcRegisteredClientRepository(JdbcOperations jdbcOperations) {
			super(jdbcOperations);
		}

	}

}
