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
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.aop.SpringProxy;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;

/**
 * A {@link SecurityHintsRegistrar} implementation that registers only the classes
 * provided in the constructor.
 *
 * <p>
 * It also traverses those found types for other return values.
 *
 * <p>
 * This may be used by an application to register specific Security-adjacent classes that
 * were otherwise missed by Spring Security's reachability scans.
 *
 * <p>
 * Remember to register this as an infrastructural bean like so:
 *
 * <pre>
 *	&#064;Bean
 *	&#064;Role(BeanDefinition.ROLE_INFRASTRUCTURE)
 *	static SecurityHintsRegistrar proxyThese(AuthorizationProxyFactory proxyFactory) {
 *		return new AuthorizationProxyFactoryHintsRegistrar(proxyFactory, MyClass.class);
 *	}
 * </pre>
 *
 * <p>
 * Note that no object graph traversal is performed in this class. As such, any classes
 * that need an authorization proxy that are missed by Security's default registrars
 * should be listed exhaustively in the constructor.
 *
 * @author Josh Cummings
 * @since 6.4
 * @see AuthorizeReturnObjectCoreHintsRegistrar
 */
public final class AuthorizeReturnObjectHintsRegistrar implements SecurityHintsRegistrar {

	private final AuthorizationProxyFactory proxyFactory;

	private final SecurityAnnotationScanner<AuthorizeReturnObject> scanner = SecurityAnnotationScanners
		.requireUnique(AuthorizeReturnObject.class);

	private final Set<Class<?>> visitedClasses = new HashSet<>();

	private final List<Class<?>> classesToProxy;

	public AuthorizeReturnObjectHintsRegistrar(AuthorizationProxyFactory proxyFactory, Class<?>... classes) {
		Assert.notNull(proxyFactory, "proxyFactory cannot be null");
		Assert.noNullElements(classes, "classes cannot contain null elements");
		this.proxyFactory = proxyFactory;
		this.classesToProxy = new ArrayList(List.of(classes));
	}

	/**
	 * Construct this registrar
	 * @param proxyFactory the proxy factory to use to produce the proxy class
	 * implementations to be registered
	 * @param classes the classes to proxy
	 */
	public AuthorizeReturnObjectHintsRegistrar(AuthorizationProxyFactory proxyFactory, List<Class<?>> classes) {
		this.proxyFactory = proxyFactory;
		this.classesToProxy = new ArrayList<>(classes);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory) {
		List<Class<?>> toProxy = new ArrayList<>();
		for (Class<?> clazz : this.classesToProxy) {
			toProxy.add(clazz);
			traverseType(toProxy, clazz);
		}
		for (Class<?> clazz : toProxy) {
			registerProxy(hints, clazz);
		}
	}

	private void registerProxy(RuntimeHints hints, Class<?> clazz) {
		Class<?> proxied = (Class<?>) this.proxyFactory.proxy(clazz);
		if (proxied == null) {
			return;
		}
		if (Proxy.isProxyClass(proxied)) {
			hints.proxies().registerJdkProxy(proxied.getInterfaces());
			return;
		}
		if (SpringProxy.class.isAssignableFrom(proxied)) {
			hints.reflection()
				.registerType(clazz, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
						MemberCategory.INVOKE_DECLARED_METHODS)
				.registerType(proxied, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
						MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.DECLARED_FIELDS);
		}
	}

	private void traverseType(List<Class<?>> toProxy, Class<?> clazz) {
		if (clazz == Object.class || this.visitedClasses.contains(clazz)) {
			return;
		}
		this.visitedClasses.add(clazz);
		for (Method m : clazz.getDeclaredMethods()) {
			AuthorizeReturnObject object = this.scanner.scan(m, clazz);
			if (object == null) {
				continue;
			}
			Class<?> returnType = m.getReturnType();
			toProxy.add(returnType);
			traverseType(toProxy, returnType);
		}
	}

}
