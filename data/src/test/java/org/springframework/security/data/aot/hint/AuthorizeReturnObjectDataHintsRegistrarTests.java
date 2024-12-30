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

package org.springframework.security.data.aot.hint;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.core.support.RepositoryFactoryBeanSupport;
import org.springframework.data.repository.core.support.RepositoryFactorySupport;
import org.springframework.security.aot.hint.SecurityHintsRegistrar;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * Tests for {@link AuthorizeReturnObjectDataHintsRegistrar}
 */
public class AuthorizeReturnObjectDataHintsRegistrarTests {

	private final AuthorizationProxyFactory proxyFactory = spy(AuthorizationAdvisorProxyFactory.withDefaults());

	private final SecurityHintsRegistrar registrar = new AuthorizeReturnObjectDataHintsRegistrar(this.proxyFactory);

	@Test
	public void registerHintsWhenUsingAuthorizeReturnObjectThenRegisters() {
		GenericApplicationContext context = new AnnotationConfigApplicationContext(AppConfig.class);
		RuntimeHints hints = new RuntimeHints();
		this.registrar.registerHints(hints, context.getBeanFactory());
		assertThat(hints.reflection().typeHints().map((hint) -> hint.getType().getName())).containsOnly(
				cglibClassName(MyObject.class), cglibClassName(MySubObject.class), MyObject.class.getName(),
				MySubObject.class.getName());
	}

	private static String cglibClassName(Class<?> clazz) {
		return clazz.getName() + "$$SpringCGLIB$$0";
	}

	@AuthorizeReturnObject
	public interface MyInterface extends CrudRepository<MyObject, Long> {

		List<MyObject> findAll();

	}

	public static class MyObject {

		@AuthorizeReturnObject
		public MySubObject get() {
			return new MySubObject();
		}

	}

	public static class MySubObject {

	}

	@Configuration
	static class AppConfig {

		@Bean
		RepositoryFactoryBeanSupport<MyInterface, MyObject, Long> bean() {
			return new RepositoryFactoryBeanSupport<>(MyInterface.class) {
				@Override
				public MyInterface getObject() {
					return mock(MyInterface.class);
				}

				@Override
				public Class<? extends MyInterface> getObjectType() {
					return MyInterface.class;
				}

				@Override
				public void afterPropertiesSet() {
				}

				@Override
				protected RepositoryFactorySupport createRepositoryFactory() {
					return null;
				}
			};
		}

	}

}
