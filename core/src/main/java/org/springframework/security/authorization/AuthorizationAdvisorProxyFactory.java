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

package org.springframework.security.authorization;

import java.lang.reflect.Array;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

import org.springframework.aop.Advisor;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.util.ClassUtils;

/**
 * A proxy factory for applying authorization advice to an arbitrary object.
 *
 * <p>
 * For example, consider a non-Spring-managed object {@code Foo}: <pre>
 *     class Foo {
 *         &#064;PreAuthorize("hasAuthority('bar:read')")
 *         String bar() { ... }
 *     }
 * </pre>
 *
 * Use {@link AuthorizationAdvisorProxyFactory} to wrap the instance in Spring Security's
 * {@link org.springframework.security.access.prepost.PreAuthorize} method interceptor
 * like so:
 *
 * <pre>
 *     AuthorizationManagerBeforeMethodInterceptor preAuthorize = AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
 *     AuthorizationProxyFactory proxyFactory = new AuthorizationProxyFactory(preAuthorize);
 *     Foo foo = new Foo();
 *     foo.bar(); // passes
 *     Foo securedFoo = proxyFactory.proxy(foo);
 *     securedFoo.bar(); // access denied!
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.3
 */
public final class AuthorizationAdvisorProxyFactory implements AuthorizationProxyFactory {

	private final Collection<AuthorizationAdvisor> advisors;

	public AuthorizationAdvisorProxyFactory(AuthorizationAdvisor... advisors) {
		this.advisors = List.of(advisors);
	}

	public AuthorizationAdvisorProxyFactory(Collection<AuthorizationAdvisor> advisors) {
		this.advisors = List.copyOf(advisors);
	}

	/**
	 * Create a new {@link AuthorizationAdvisorProxyFactory} that includes the given
	 * advisors in addition to any advisors {@code this} instance already has.
	 *
	 * <p>
	 * All advisors are re-sorted by their advisor order.
	 * @param advisors the advisors to add
	 * @return a new {@link AuthorizationAdvisorProxyFactory} instance
	 */
	public AuthorizationAdvisorProxyFactory withAdvisors(AuthorizationAdvisor... advisors) {
		List<AuthorizationAdvisor> merged = new ArrayList<>(this.advisors.size() + advisors.length);
		merged.addAll(this.advisors);
		merged.addAll(List.of(advisors));
		AnnotationAwareOrderComparator.sort(merged);
		return new AuthorizationAdvisorProxyFactory(merged);
	}

	/**
	 * Proxy an object to enforce authorization advice.
	 *
	 * <p>
	 * Proxies any instance of a non-final class or a class that implements more than one
	 * interface.
	 *
	 * <p>
	 * If {@code target} is an {@link Iterator}, {@link Collection}, {@link Array},
	 * {@link Map}, {@link Stream}, or {@link Optional}, then the element or value type is
	 * proxied.
	 *
	 * <p>
	 * If {@code target} is a {@link Class}, then {@link ProxyFactory#getProxyClass} is
	 * invoked instead.
	 * @param target the instance to proxy
	 * @return the proxied instance
	 */
	@Override
	public Object proxy(Object target) {
		if (target == null) {
			return null;
		}
		if (target instanceof Class<?> targetClass) {
			return proxyClass(targetClass);
		}
		if (target instanceof Iterator<?> iterator) {
			return proxyIterator(iterator);
		}
		if (target instanceof Queue<?> queue) {
			return proxyQueue(queue);
		}
		if (target instanceof List<?> list) {
			return proxyList(list);
		}
		if (target instanceof SortedSet<?> set) {
			return proxySortedSet(set);
		}
		if (target instanceof Set<?> set) {
			return proxySet(set);
		}
		if (target.getClass().isArray()) {
			return proxyArray((Object[]) target);
		}
		if (target instanceof SortedMap<?, ?> map) {
			return proxySortedMap(map);
		}
		if (target instanceof Iterable<?> iterable) {
			return proxyIterable(iterable);
		}
		if (target instanceof Map<?, ?> map) {
			return proxyMap(map);
		}
		if (target instanceof Stream<?> stream) {
			return proxyStream(stream);
		}
		if (target instanceof Optional<?> optional) {
			return proxyOptional(optional);
		}
		ProxyFactory factory = new ProxyFactory(target);
		for (Advisor advisor : this.advisors) {
			factory.addAdvisors(advisor);
		}
		factory.setProxyTargetClass(!Modifier.isFinal(target.getClass().getModifiers()));
		return factory.getProxy();
	}

	@SuppressWarnings("unchecked")
	private <T> T proxyCast(T target) {
		return (T) proxy(target);
	}

	private Class<?> proxyClass(Class<?> targetClass) {
		ProxyFactory factory = new ProxyFactory();
		factory.setTargetClass(targetClass);
		factory.setInterfaces(ClassUtils.getAllInterfacesForClass(targetClass));
		factory.setProxyTargetClass(!Modifier.isFinal(targetClass.getModifiers()));
		for (Advisor advisor : this.advisors) {
			factory.addAdvisors(advisor);
		}
		return factory.getProxyClass(getClass().getClassLoader());
	}

	private <T> Iterable<T> proxyIterable(Iterable<T> iterable) {
		return () -> proxyIterator(iterable.iterator());
	}

	private <T> Iterator<T> proxyIterator(Iterator<T> iterator) {
		return new Iterator<>() {
			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

			@Override
			public T next() {
				return proxyCast(iterator.next());
			}
		};
	}

	private <T> SortedSet<T> proxySortedSet(SortedSet<T> set) {
		SortedSet<T> proxies = new TreeSet<>(set.comparator());
		for (T toProxy : set) {
			proxies.add(proxyCast(toProxy));
		}
		try {
			set.clear();
			set.addAll(proxies);
			return proxies;
		}
		catch (UnsupportedOperationException ex) {
			return Collections.unmodifiableSortedSet(proxies);
		}
	}

	private <T> Set<T> proxySet(Set<T> set) {
		Set<T> proxies = new LinkedHashSet<>(set.size());
		for (T toProxy : set) {
			proxies.add(proxyCast(toProxy));
		}
		try {
			set.clear();
			set.addAll(proxies);
			return proxies;
		}
		catch (UnsupportedOperationException ex) {
			return Collections.unmodifiableSet(proxies);
		}
	}

	private <T> Queue<T> proxyQueue(Queue<T> queue) {
		Queue<T> proxies = new LinkedList<>();
		for (T toProxy : queue) {
			proxies.add(proxyCast(toProxy));
		}
		queue.clear();
		queue.addAll(proxies);
		return proxies;
	}

	private <T> List<T> proxyList(List<T> list) {
		List<T> proxies = new ArrayList<>(list.size());
		for (T toProxy : list) {
			proxies.add(proxyCast(toProxy));
		}
		try {
			list.clear();
			list.addAll(proxies);
			return proxies;
		}
		catch (UnsupportedOperationException ex) {
			return Collections.unmodifiableList(proxies);
		}
	}

	private Object[] proxyArray(Object[] objects) {
		List<Object> retain = new ArrayList<>(objects.length);
		for (Object object : objects) {
			retain.add(proxy(object));
		}
		Object[] proxies = (Object[]) Array.newInstance(objects.getClass().getComponentType(), retain.size());
		for (int i = 0; i < retain.size(); i++) {
			proxies[i] = retain.get(i);
		}
		return proxies;
	}

	private <K, V> SortedMap<K, V> proxySortedMap(SortedMap<K, V> entries) {
		SortedMap<K, V> proxies = new TreeMap<>(entries.comparator());
		for (Map.Entry<K, V> entry : entries.entrySet()) {
			proxies.put(entry.getKey(), proxyCast(entry.getValue()));
		}
		try {
			entries.clear();
			entries.putAll(proxies);
			return entries;
		}
		catch (UnsupportedOperationException ex) {
			return Collections.unmodifiableSortedMap(proxies);
		}
	}

	private <K, V> Map<K, V> proxyMap(Map<K, V> entries) {
		Map<K, V> proxies = new LinkedHashMap<>(entries.size());
		for (Map.Entry<K, V> entry : entries.entrySet()) {
			proxies.put(entry.getKey(), proxyCast(entry.getValue()));
		}
		try {
			entries.clear();
			entries.putAll(proxies);
			return entries;
		}
		catch (UnsupportedOperationException ex) {
			return Collections.unmodifiableMap(proxies);
		}
	}

	private Stream<?> proxyStream(Stream<?> stream) {
		return stream.map(this::proxy).onClose(stream::close);
	}

	@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
	private Optional<?> proxyOptional(Optional<?> optional) {
		return optional.map(this::proxy);
	}

}
