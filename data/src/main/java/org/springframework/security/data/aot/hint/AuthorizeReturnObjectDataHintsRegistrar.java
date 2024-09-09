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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.ResolvableType;
import org.springframework.data.repository.core.support.RepositoryFactoryBeanSupport;
import org.springframework.security.aot.hint.AuthorizeReturnObjectCoreHintsRegistrar;
import org.springframework.security.aot.hint.AuthorizeReturnObjectHintsRegistrar;
import org.springframework.security.aot.hint.SecurityHintsRegistrar;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;

/**
 * A {@link SecurityHintsRegistrar} that scans all beans for implementations of
 * {@link RepositoryFactoryBeanSupport}, registering the corresponding entity class as a
 * {@link org.springframework.aot.hint.TypeHint} should any if that repository's method
 * use {@link AuthorizeReturnObject}.
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
 *		return new AuthorizeReturnObjectDataHintsRegistrar(proxyFactory);
 *	}
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.4
 * @see AuthorizeReturnObjectCoreHintsRegistrar
 * @see AuthorizeReturnObjectHintsRegistrar
 */
public final class AuthorizeReturnObjectDataHintsRegistrar implements SecurityHintsRegistrar {

	private final AuthorizationProxyFactory proxyFactory;

	private final SecurityAnnotationScanner<AuthorizeReturnObject> scanner = SecurityAnnotationScanners
		.requireUnique(AuthorizeReturnObject.class);

	private final Set<Class<?>> visitedClasses = new HashSet<>();

	public AuthorizeReturnObjectDataHintsRegistrar(AuthorizationProxyFactory proxyFactory) {
		this.proxyFactory = proxyFactory;
	}

	@Override
	public void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory) {
		List<Class<?>> toProxy = new ArrayList<>();
		for (String name : beanFactory.getBeanDefinitionNames()) {
			ResolvableType type = beanFactory.getBeanDefinition(name).getResolvableType();
			if (!RepositoryFactoryBeanSupport.class.isAssignableFrom(type.toClass())) {
				continue;
			}
			Class<?>[] generics = type.resolveGenerics();
			Class<?> entity = generics[1];
			AuthorizeReturnObject authorize = beanFactory.findAnnotationOnBean(name, AuthorizeReturnObject.class);
			if (authorize != null) {
				toProxy.add(entity);
				continue;
			}
			Class<?> repository = generics[0];
			for (Method method : repository.getDeclaredMethods()) {
				AuthorizeReturnObject returnObject = this.scanner.scan(method, repository);
				if (returnObject == null) {
					continue;
				}
				// optimistically assume that the entity needs wrapping if any of the
				// repository methods use @AuthorizeReturnObject
				toProxy.add(entity);
				break;
			}
		}
		new AuthorizeReturnObjectHintsRegistrar(this.proxyFactory, toProxy).registerHints(hints, beanFactory);
	}

}
