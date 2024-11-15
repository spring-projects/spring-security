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

package org.springframework.security.aot.hint;

import org.junit.jupiter.api.Test;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;

/**
 * Tests for {@link AuthorizeReturnObjectCoreHintsRegistrar}
 */
public class AuthorizeReturnObjectCoreHintsRegistrarTests {

	private final AuthorizationProxyFactory proxyFactory = spy(AuthorizationAdvisorProxyFactory.withDefaults());

	private final AuthorizeReturnObjectCoreHintsRegistrar registrar = new AuthorizeReturnObjectCoreHintsRegistrar(
			this.proxyFactory);

	@Test
	public void registerHintsWhenUsingAuthorizeReturnObjectThenRegisters() {
		GenericApplicationContext context = new GenericApplicationContext();
		context.registerBean(MyService.class, MyService::new);
		context.registerBean(MyInterface.class, MyImplementation::new);
		context.refresh();
		RuntimeHints hints = new RuntimeHints();
		this.registrar.registerHints(hints, context.getBeanFactory());
		assertThat(hints.reflection().typeHints().map((hint) -> hint.getType().getName())).containsOnly(
				cglibClassName(MyObject.class), cglibClassName(MySubObject.class), MyObject.class.getName(),
				MySubObject.class.getName());
		assertThat(hints.proxies()
			.jdkProxyHints()
			.flatMap((hint) -> hint.getProxiedInterfaces().stream())
			.map(TypeReference::getName)).contains(MyInterface.class.getName());
	}

	private static String cglibClassName(Class<?> clazz) {
		return clazz.getName() + "$$SpringCGLIB$$0";
	}

	public static class MyService {

		@AuthorizeReturnObject
		MyObject get() {
			return new MyObject();
		}

	}

	public interface MyInterface {

		MyObject get();

	}

	@AuthorizeReturnObject
	public static class MyImplementation implements MyInterface {

		@Override
		public MyObject get() {
			return new MyObject();
		}

	}

	public static class MyObject {

		@AuthorizeReturnObject
		public MySubObject get() {
			return new MySubObject();
		}

		@AuthorizeReturnObject
		public MyInterface getInterface() {
			return new MyImplementation();
		}

	}

	public static class MySubObject {

	}

}
