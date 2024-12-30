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
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;

/**
 * Tests for {@link AuthorizeReturnObjectHintsRegistrar}
 */
public class AuthorizeReturnObjectHintsRegistrarTests {

	private final AuthorizationProxyFactory proxyFactory = spy(AuthorizationAdvisorProxyFactory.withDefaults());

	@Test
	public void registerHintsWhenSpecifiedThenRegisters() {
		AuthorizeReturnObjectHintsRegistrar registrar = new AuthorizeReturnObjectHintsRegistrar(this.proxyFactory,
				MyObject.class, MyInterface.class);
		RuntimeHints hints = new RuntimeHints();
		registrar.registerHints(hints, null);
		assertThat(hints.reflection().typeHints().map((hint) -> hint.getType().getName()))
			.containsOnly(cglibClassName(MyObject.class), MyObject.class.getName());
		assertThat(hints.proxies()
			.jdkProxyHints()
			.flatMap((hint) -> hint.getProxiedInterfaces().stream())
			.map(TypeReference::getName)).contains(MyInterface.class.getName());
	}

	private static String cglibClassName(Class<?> clazz) {
		return clazz.getName() + "$$SpringCGLIB$$0";
	}

	public interface MyInterface {

		MyObject get();

	}

	public static class MyObject {

	}

}
