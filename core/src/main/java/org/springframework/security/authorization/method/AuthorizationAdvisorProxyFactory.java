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

package org.springframework.security.authorization.method;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
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
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.lang.NonNull;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.util.Assert;
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
 *     AuthorizationProxyFactory proxyFactory = AuthorizationAdvisorProxyFactory.withDefaults();
 *     Foo foo = new Foo();
 *     foo.bar(); // passes
 *     Foo securedFoo = proxyFactory.proxy(foo);
 *     securedFoo.bar(); // access denied!
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.3
 */
public final class AuthorizationAdvisorProxyFactory
		implements AuthorizationProxyFactory, Iterable<AuthorizationAdvisor>, AopInfrastructureBean {

	private static final boolean isReactivePresent = ClassUtils.isPresent("reactor.core.publisher.Mono", null);

	private static final TargetVisitor DEFAULT_VISITOR = isReactivePresent
			? TargetVisitor.of(new ClassVisitor(), new ReactiveTypeVisitor(), new ContainerTypeVisitor())
			: TargetVisitor.of(new ClassVisitor(), new ContainerTypeVisitor());

	private static final TargetVisitor DEFAULT_VISITOR_SKIP_VALUE_TYPES = TargetVisitor.of(new ClassVisitor(),
			new IgnoreValueTypeVisitor(), DEFAULT_VISITOR);

	private final AuthorizationProxyMethodInterceptor authorizationProxy = new AuthorizationProxyMethodInterceptor();

	private List<AuthorizationAdvisor> advisors;

	private TargetVisitor visitor = DEFAULT_VISITOR;

	/**
	 * Construct an {@link AuthorizationAdvisorProxyFactory} with the provided advisors.
	 *
	 * <p>
	 * The list may be empty, in the case where advisors are added later using
	 * {@link #addAdvisor}.
	 * @param advisors the advisors to use
	 * @since 6.4
	 */
	public AuthorizationAdvisorProxyFactory(List<AuthorizationAdvisor> advisors) {
		this.advisors = new ArrayList<>(advisors);
		AnnotationAwareOrderComparator.sort(this.advisors);
	}

	/**
	 * Construct an {@link AuthorizationAdvisorProxyFactory} with the defaults needed for
	 * wrapping objects in Spring Security's pre-post method security support.
	 * @return an {@link AuthorizationAdvisorProxyFactory} for adding pre-post method
	 * security support
	 */
	public static AuthorizationAdvisorProxyFactory withDefaults() {
		List<AuthorizationAdvisor> advisors = new ArrayList<>();
		advisors.add(AuthorizationManagerBeforeMethodInterceptor.preAuthorize());
		advisors.add(AuthorizationManagerAfterMethodInterceptor.postAuthorize());
		advisors.add(new PreFilterAuthorizationMethodInterceptor());
		advisors.add(new PostFilterAuthorizationMethodInterceptor());
		AuthorizationAdvisorProxyFactory proxyFactory = new AuthorizationAdvisorProxyFactory(advisors);
		proxyFactory.addAdvisor(new AuthorizeReturnObjectMethodInterceptor(proxyFactory));
		return proxyFactory;
	}

	/**
	 * Construct an {@link AuthorizationAdvisorProxyFactory} with the defaults needed for
	 * wrapping objects in Spring Security's pre-post reactive method security support.
	 * @return an {@link AuthorizationAdvisorProxyFactory} for adding pre-post reactive
	 * method security support
	 */
	public static AuthorizationAdvisorProxyFactory withReactiveDefaults() {
		List<AuthorizationAdvisor> advisors = new ArrayList<>();
		advisors.add(AuthorizationManagerBeforeReactiveMethodInterceptor.preAuthorize());
		advisors.add(AuthorizationManagerAfterReactiveMethodInterceptor.postAuthorize());
		advisors.add(new PreFilterAuthorizationReactiveMethodInterceptor());
		advisors.add(new PostFilterAuthorizationReactiveMethodInterceptor());
		AuthorizationAdvisorProxyFactory proxyFactory = new AuthorizationAdvisorProxyFactory(advisors);
		proxyFactory.addAdvisor(new AuthorizeReturnObjectMethodInterceptor(proxyFactory));
		return proxyFactory;
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
		AnnotationAwareOrderComparator.sort(this.advisors);
		if (target == null) {
			return null;
		}
		if (target instanceof AuthorizationProxy proxied) {
			return proxied;
		}
		Object proxied = this.visitor.visit(this, target);
		if (proxied != null) {
			return proxied;
		}
		ProxyFactory factory = new ProxyFactory(target);
		factory.addAdvisors(this.authorizationProxy);
		for (Advisor advisor : this.advisors) {
			factory.addAdvisors(advisor);
		}
		factory.addInterface(AuthorizationProxy.class);
		factory.setOpaque(true);
		factory.setProxyTargetClass(!Modifier.isFinal(target.getClass().getModifiers()));
		return factory.getProxy();
	}

	/**
	 * Add advisors that should be included to each proxy created.
	 *
	 * <p>
	 * All advisors are re-sorted by their advisor order.
	 * @param advisors the advisors to add
	 * @deprecated Please use {@link #addAdvisor} instead
	 */
	@Deprecated
	public void setAdvisors(AuthorizationAdvisor... advisors) {
		this.advisors = new ArrayList<>(List.of(advisors));
	}

	/**
	 * Add advisors that should be included to each proxy created.
	 *
	 * <p>
	 * All advisors are re-sorted by their advisor order.
	 * @param advisors the advisors to add
	 * @deprecated Please use {@link #addAdvisor} instead
	 */
	@Deprecated
	public void setAdvisors(Collection<AuthorizationAdvisor> advisors) {
		this.advisors = new ArrayList<>(advisors);
	}

	/**
	 * Add an advisor that should be included to each proxy created.
	 *
	 * <p>
	 * This method sorts the advisors based on the order in
	 * {@link AuthorizationAdvisor#getOrder}. You can use the values in
	 * {@link AuthorizationInterceptorsOrder}to ensure advisors are located where you need
	 * them.
	 * @param advisor
	 * @since 6.4
	 */
	public void addAdvisor(AuthorizationAdvisor advisor) {
		this.advisors.add(advisor);
	}

	/**
	 * Use this visitor to navigate the proxy target's hierarchy.
	 *
	 * <p>
	 * This can be helpful when you want a specialized behavior for a type or set of
	 * types. For example, if you want to have this factory skip primitives and wrappers,
	 * then you can do:
	 *
	 * <pre>
	 * 	AuthorizationAdvisorProxyFactory proxyFactory = new AuthorizationAdvisorProxyFactory();
	 * 	proxyFactory.setTargetVisitor(TargetVisitor.defaultsSkipValueTypes());
	 * </pre>
	 *
	 * <p>
	 * The default {@link TargetVisitor} proxies {@link Class} instances as well as
	 * instances contained in reactive types (if reactor is present), collection types,
	 * and other container types like {@link Optional} and {@link Supplier}.
	 *
	 * <p>
	 * If you want to add support for another container type, you can do so in the
	 * following way:
	 *
	 * <pre>
	 * 	TargetVisitor functions = (factory, target) -> {
	 *		if (target instanceof Function function) {
	 *			return (input) -> factory.proxy(function.apply(input));
	 *		}
	 *		return null;
	 * 	};
	 * 	AuthorizationAdvisorProxyFactory proxyFactory = new AuthorizationAdvisorProxyFactory();
	 * 	proxyFactory.setTargetVisitor(TargetVisitor.of(functions, TargetVisitor.defaultsSkipValueTypes()));
	 * </pre>
	 * @param visitor the visitor to use to introduce specialized behavior for a type
	 * @see TargetVisitor#defaults
	 */
	public void setTargetVisitor(TargetVisitor visitor) {
		Assert.notNull(visitor, "delegate cannot be null");
		this.visitor = visitor;
	}

	@Override
	@NonNull
	public Iterator<AuthorizationAdvisor> iterator() {
		return this.advisors.iterator();
	}

	/**
	 * An interface to handle how the {@link AuthorizationAdvisorProxyFactory} should step
	 * through the target's object hierarchy.
	 *
	 * @author Josh Cummings
	 * @since 6.3
	 * @see AuthorizationAdvisorProxyFactory#setTargetVisitor
	 */
	public interface TargetVisitor {

		/**
		 * Visit and possibly proxy this object.
		 *
		 * <p>
		 * Visiting may take the form of walking down this object's hierarchy and proxying
		 * sub-objects.
		 *
		 * <p>
		 * An example is a visitor that proxies the elements of a {@link List} instead of
		 * the list itself
		 *
		 * <p>
		 * Returning {@code null} implies that this visitor does not want to proxy this
		 * object
		 * @param proxyFactory the proxy factory to delegate proxying to for any
		 * sub-objects
		 * @param target the object to proxy
		 * @return the visited (and possibly proxied) object
		 */
		Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object target);

		/**
		 * The default {@link TargetVisitor}, which will proxy {@link Class} instances as
		 * well as instances contained in reactive types (if reactor is present),
		 * collection types, and other container types like {@link Optional} and
		 * {@link Supplier}
		 */
		static TargetVisitor defaults() {
			return AuthorizationAdvisorProxyFactory.DEFAULT_VISITOR;
		}

		/**
		 * The default {@link TargetVisitor} that also skips any value types (for example,
		 * {@link String}, {@link Integer}). This is handy for annotations like
		 * {@link AuthorizeReturnObject} when used at the class level
		 */
		static TargetVisitor defaultsSkipValueTypes() {
			return AuthorizationAdvisorProxyFactory.DEFAULT_VISITOR_SKIP_VALUE_TYPES;
		}

		/**
		 * Compose a set of visitors. This is helpful when you are customizing for a given
		 * type and still want the defaults applied for the remaining types.
		 *
		 * <p>
		 * The resulting visitor will execute the first visitor that returns a non-null
		 * value.
		 * @param visitors the set of visitors
		 * @return a composite that executes the first visitor that returns a non-null
		 * value
		 */
		static TargetVisitor of(TargetVisitor... visitors) {
			return (proxyFactory, target) -> {
				for (TargetVisitor visitor : visitors) {
					Object result = visitor.visit(proxyFactory, target);
					if (result != null) {
						return result;
					}
				}
				return null;
			};
		}

	}

	private static final class IgnoreValueTypeVisitor implements TargetVisitor {

		@Override
		public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object object) {
			if (ClassUtils.isSimpleValueType(object.getClass())) {
				return object;
			}
			return null;
		}

	}

	private static final class ClassVisitor implements TargetVisitor {

		private final AuthorizationProxyMethodInterceptor authorizationProxy = new AuthorizationProxyMethodInterceptor();

		@Override
		public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object object) {
			if (object instanceof Class<?> targetClass) {
				if (AuthorizationProxy.class.isAssignableFrom(targetClass)) {
					return targetClass;
				}
				ProxyFactory factory = new ProxyFactory();
				factory.setTargetClass(targetClass);
				factory.setInterfaces(ClassUtils.getAllInterfacesForClass(targetClass));
				factory.setOpaque(true);
				factory.setProxyTargetClass(!Modifier.isFinal(targetClass.getModifiers()));
				factory.addAdvisor(this.authorizationProxy);
				for (Advisor advisor : proxyFactory) {
					factory.addAdvisors(advisor);
				}
				factory.addInterface(AuthorizationProxy.class);
				return factory.getProxyClass(getClass().getClassLoader());
			}
			return null;
		}

	}

	private static final class ContainerTypeVisitor implements TargetVisitor {

		@Override
		public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object target) {
			if (target instanceof Iterator<?> iterator) {
				return proxyIterator(proxyFactory, iterator);
			}
			if (target instanceof Queue<?> queue) {
				return proxyQueue(proxyFactory, queue);
			}
			if (target instanceof List<?> list) {
				return proxyList(proxyFactory, list);
			}
			if (target instanceof SortedSet<?> set) {
				return proxySortedSet(proxyFactory, set);
			}
			if (target instanceof Set<?> set) {
				return proxySet(proxyFactory, set);
			}
			if (target.getClass().isArray()) {
				return proxyArray(proxyFactory, (Object[]) target);
			}
			if (target instanceof SortedMap<?, ?> map) {
				return proxySortedMap(proxyFactory, map);
			}
			if (target instanceof Iterable<?> iterable) {
				return proxyIterable(proxyFactory, iterable);
			}
			if (target instanceof Map<?, ?> map) {
				return proxyMap(proxyFactory, map);
			}
			if (target instanceof Stream<?> stream) {
				return proxyStream(proxyFactory, stream);
			}
			if (target instanceof Optional<?> optional) {
				return proxyOptional(proxyFactory, optional);
			}
			if (target instanceof Supplier<?> supplier) {
				return proxySupplier(proxyFactory, supplier);
			}
			return null;
		}

		@SuppressWarnings("unchecked")
		private <T> T proxyCast(AuthorizationProxyFactory proxyFactory, T target) {
			return (T) proxyFactory.proxy(target);
		}

		private <T> Iterable<T> proxyIterable(AuthorizationProxyFactory proxyFactory, Iterable<T> iterable) {
			return () -> proxyIterator(proxyFactory, iterable.iterator());
		}

		private <T> Iterator<T> proxyIterator(AuthorizationProxyFactory proxyFactory, Iterator<T> iterator) {
			return new Iterator<>() {
				@Override
				public boolean hasNext() {
					return iterator.hasNext();
				}

				@Override
				public T next() {
					return proxyCast(proxyFactory, iterator.next());
				}
			};
		}

		private <T> SortedSet<T> proxySortedSet(AuthorizationProxyFactory proxyFactory, SortedSet<T> set) {
			SortedSet<T> proxies = new TreeSet<>(set.comparator());
			for (T toProxy : set) {
				proxies.add(proxyCast(proxyFactory, toProxy));
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

		private <T> Set<T> proxySet(AuthorizationProxyFactory proxyFactory, Set<T> set) {
			Set<T> proxies = new LinkedHashSet<>(set.size());
			for (T toProxy : set) {
				proxies.add(proxyCast(proxyFactory, toProxy));
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

		private <T> Queue<T> proxyQueue(AuthorizationProxyFactory proxyFactory, Queue<T> queue) {
			Queue<T> proxies = new LinkedList<>();
			for (T toProxy : queue) {
				proxies.add(proxyCast(proxyFactory, toProxy));
			}
			queue.clear();
			queue.addAll(proxies);
			return proxies;
		}

		private <T> List<T> proxyList(AuthorizationProxyFactory proxyFactory, List<T> list) {
			List<T> proxies = new ArrayList<>(list.size());
			for (T toProxy : list) {
				proxies.add(proxyCast(proxyFactory, toProxy));
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

		private Object[] proxyArray(AuthorizationProxyFactory proxyFactory, Object[] objects) {
			List<Object> retain = new ArrayList<>(objects.length);
			for (Object object : objects) {
				retain.add(proxyFactory.proxy(object));
			}
			Object[] proxies = (Object[]) Array.newInstance(objects.getClass().getComponentType(), retain.size());
			for (int i = 0; i < retain.size(); i++) {
				proxies[i] = retain.get(i);
			}
			return proxies;
		}

		private <K, V> SortedMap<K, V> proxySortedMap(AuthorizationProxyFactory proxyFactory, SortedMap<K, V> entries) {
			SortedMap<K, V> proxies = new TreeMap<>(entries.comparator());
			for (Map.Entry<K, V> entry : entries.entrySet()) {
				proxies.put(entry.getKey(), proxyCast(proxyFactory, entry.getValue()));
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

		private <K, V> Map<K, V> proxyMap(AuthorizationProxyFactory proxyFactory, Map<K, V> entries) {
			Map<K, V> proxies = new LinkedHashMap<>(entries.size());
			for (Map.Entry<K, V> entry : entries.entrySet()) {
				proxies.put(entry.getKey(), proxyCast(proxyFactory, entry.getValue()));
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

		private Stream<?> proxyStream(AuthorizationProxyFactory proxyFactory, Stream<?> stream) {
			return stream.map(proxyFactory::proxy).onClose(stream::close);
		}

		@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
		private Optional<?> proxyOptional(AuthorizationProxyFactory proxyFactory, Optional<?> optional) {
			return optional.map(proxyFactory::proxy);
		}

		private Supplier<?> proxySupplier(AuthorizationProxyFactory proxyFactory, Supplier<?> supplier) {
			return () -> proxyFactory.proxy(supplier.get());
		}

	}

	private static class ReactiveTypeVisitor implements TargetVisitor {

		@Override
		@SuppressWarnings("ReactiveStreamsUnusedPublisher")
		public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object target) {
			if (target instanceof Mono<?> mono) {
				return proxyMono(proxyFactory, mono);
			}
			if (target instanceof Flux<?> flux) {
				return proxyFlux(proxyFactory, flux);
			}
			return null;
		}

		private Mono<?> proxyMono(AuthorizationProxyFactory proxyFactory, Mono<?> mono) {
			return mono.map(proxyFactory::proxy);
		}

		private Flux<?> proxyFlux(AuthorizationProxyFactory proxyFactory, Flux<?> flux) {
			return flux.map(proxyFactory::proxy);
		}

	}

	private static final class AuthorizationProxyMethodInterceptor implements AuthorizationAdvisor {

		private static final Method GET_TARGET_METHOD = ClassUtils.getMethod(AuthorizationProxy.class,
				"toAuthorizedTarget");

		@Override
		public Object invoke(MethodInvocation invocation) throws Throwable {
			if (invocation.getMethod().equals(GET_TARGET_METHOD)) {
				return invocation.getThis();
			}
			return invocation.proceed();
		}

		@Override
		public Pointcut getPointcut() {
			return Pointcut.TRUE;
		}

		@Override
		public Advice getAdvice() {
			return this;
		}

		@Override
		public int getOrder() {
			return 0;
		}

	}

}
