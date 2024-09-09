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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;

/**
 * A {@link SecurityHintsRegistrar} that scans all beans for methods that use
 * {@link AuthorizeReturnObject} and registers those return objects as
 * {@link org.springframework.aot.hint.TypeHint}s.
 *
 * <p>
 * It also traverses those found types for other return values.
 *
 * <p>
 * An instance of this class is published as an infrastructural bean by the
 * {@code spring-security-config} module. However, in the event you need to publish it
 * yourself, remember to publish it as an infrastructural bean like so:
 *
 * <pre>
 *	&#064;Bean
 *	&#064;Role(BeanDefinition.ROLE_INFRASTRUCTURE)
 *	static SecurityHintsRegistrar proxyThese(AuthorizationProxyFactory proxyFactory) {
 *		return new AuthorizeReturnObjectHintsRegistrar(proxyFactory);
 *	}
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.4
 * @see AuthorizeReturnObjectHintsRegistrar
 * @see SecurityHintsAotProcessor
 */
public final class AuthorizeReturnObjectCoreHintsRegistrar implements SecurityHintsRegistrar {

	private final AuthorizationProxyFactory proxyFactory;

	private final SecurityAnnotationScanner<AuthorizeReturnObject> scanner = SecurityAnnotationScanners
		.requireUnique(AuthorizeReturnObject.class);

	private final Set<Class<?>> visitedClasses = new HashSet<>();

	public AuthorizeReturnObjectCoreHintsRegistrar(AuthorizationProxyFactory proxyFactory) {
		Assert.notNull(proxyFactory, "proxyFactory cannot be null");
		this.proxyFactory = proxyFactory;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory) {
		List<Class<?>> toProxy = new ArrayList<>();
		for (String name : beanFactory.getBeanDefinitionNames()) {
			Class<?> clazz = beanFactory.getType(name, false);
			if (clazz == null) {
				continue;
			}
			for (Method method : clazz.getDeclaredMethods()) {
				AuthorizeReturnObject annotation = this.scanner.scan(method, clazz);
				if (annotation == null) {
					continue;
				}
				toProxy.add(method.getReturnType());
			}
		}
		new AuthorizeReturnObjectHintsRegistrar(this.proxyFactory, toProxy).registerHints(hints, beanFactory);
	}

}
