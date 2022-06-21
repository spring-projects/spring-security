/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscription;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Operators;
import reactor.util.context.Context;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * {@link Configuration} that (potentially) adds a "decorating" {@code Publisher} for the
 * last operator created in every {@code Mono} or {@code Flux}.
 *
 * <p>
 * The {@code Publisher} is solely responsible for adding the current
 * {@code HttpServletRequest}, {@code HttpServletResponse} and {@code Authentication} to
 * the Reactor {@code Context} so that it's accessible in every flow, if required.
 *
 * @author Joe Grandja
 * @author Roman Matiushchenko
 * @since 5.2
 * @see OAuth2ImportSelector
 */
@Configuration(proxyBeanMethods = false)
class SecurityReactorContextConfiguration {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	@Bean
	SecurityReactorContextSubscriberRegistrar securityReactorContextSubscriberRegistrar() {
		SecurityReactorContextSubscriberRegistrar registrar = new SecurityReactorContextSubscriberRegistrar();
		registrar.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		return registrar;
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	static class SecurityReactorContextSubscriberRegistrar implements InitializingBean, DisposableBean {

		private static final String SECURITY_REACTOR_CONTEXT_OPERATOR_KEY = "org.springframework.security.SECURITY_REACTOR_CONTEXT_OPERATOR";

		private final Map<Object, Supplier<Object>> CONTEXT_ATTRIBUTE_VALUE_LOADERS = new HashMap<>();

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
				.getContextHolderStrategy();

		SecurityReactorContextSubscriberRegistrar() {
			this.CONTEXT_ATTRIBUTE_VALUE_LOADERS.put(HttpServletRequest.class,
					SecurityReactorContextSubscriberRegistrar::getRequest);
			this.CONTEXT_ATTRIBUTE_VALUE_LOADERS.put(HttpServletResponse.class,
					SecurityReactorContextSubscriberRegistrar::getResponse);
			this.CONTEXT_ATTRIBUTE_VALUE_LOADERS.put(Authentication.class, this::getAuthentication);
		}

		@Override
		public void afterPropertiesSet() throws Exception {
			Function<? super Publisher<Object>, ? extends Publisher<Object>> lifter = Operators
					.liftPublisher((pub, sub) -> createSubscriberIfNecessary(sub));
			Hooks.onLastOperator(SECURITY_REACTOR_CONTEXT_OPERATOR_KEY, lifter::apply);
		}

		@Override
		public void destroy() throws Exception {
			Hooks.resetOnLastOperator(SECURITY_REACTOR_CONTEXT_OPERATOR_KEY);
		}

		void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

		<T> CoreSubscriber<T> createSubscriberIfNecessary(CoreSubscriber<T> delegate) {
			if (delegate.currentContext().hasKey(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES)) {
				// Already enriched. No need to create Subscriber so return original
				return delegate;
			}
			return new SecurityReactorContextSubscriber<>(delegate, getContextAttributes());
		}

		private Map<Object, Object> getContextAttributes() {
			return new LoadingMap<>(this.CONTEXT_ATTRIBUTE_VALUE_LOADERS);
		}

		private static HttpServletRequest getRequest() {
			RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
			if (requestAttributes instanceof ServletRequestAttributes) {
				ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) requestAttributes;
				return servletRequestAttributes.getRequest();
			}
			return null;
		}

		private static HttpServletResponse getResponse() {
			RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
			if (requestAttributes instanceof ServletRequestAttributes) {
				ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) requestAttributes;
				return servletRequestAttributes.getResponse(); // possible null
			}
			return null;
		}

		private Authentication getAuthentication() {
			return this.securityContextHolderStrategy.getContext().getAuthentication();
		}

	}

	static class SecurityReactorContextSubscriber<T> implements CoreSubscriber<T> {

		static final String SECURITY_CONTEXT_ATTRIBUTES = "org.springframework.security.SECURITY_CONTEXT_ATTRIBUTES";

		private final CoreSubscriber<T> delegate;

		private final Context context;

		SecurityReactorContextSubscriber(CoreSubscriber<T> delegate, Map<Object, Object> attributes) {
			this.delegate = delegate;
			Context context = getOrPutContext(attributes, this.delegate.currentContext());
			this.context = context;
		}

		private Context getOrPutContext(Map<Object, Object> attributes, Context currentContext) {
			if (currentContext.hasKey(SECURITY_CONTEXT_ATTRIBUTES)) {
				return currentContext;
			}
			return currentContext.put(SECURITY_CONTEXT_ATTRIBUTES, attributes);
		}

		@Override
		public Context currentContext() {
			return this.context;
		}

		@Override
		public void onSubscribe(Subscription s) {
			this.delegate.onSubscribe(s);
		}

		@Override
		public void onNext(T t) {
			this.delegate.onNext(t);
		}

		@Override
		public void onError(Throwable ex) {
			this.delegate.onError(ex);
		}

		@Override
		public void onComplete() {
			this.delegate.onComplete();
		}

	}

	/**
	 * A map that computes each value when {@link #get} is invoked
	 */
	static class LoadingMap<K, V> implements Map<K, V> {

		private final Map<K, V> loaded = new ConcurrentHashMap<>();

		private final Map<K, Supplier<V>> loaders;

		LoadingMap(Map<K, Supplier<V>> loaders) {
			this.loaders = Collections.unmodifiableMap(new HashMap<>(loaders));
		}

		@Override
		public int size() {
			return this.loaders.size();
		}

		@Override
		public boolean isEmpty() {
			return this.loaders.isEmpty();
		}

		@Override
		public boolean containsKey(Object key) {
			return this.loaders.containsKey(key);
		}

		@Override
		public Set<K> keySet() {
			return this.loaders.keySet();
		}

		@Override
		public V get(Object key) {
			if (!this.loaders.containsKey(key)) {
				throw new IllegalArgumentException(
						"This map only supports the following keys: " + this.loaders.keySet());
			}
			return this.loaded.computeIfAbsent((K) key, (k) -> this.loaders.get(k).get());
		}

		@Override
		public V put(K key, V value) {
			if (!this.loaders.containsKey(key)) {
				throw new IllegalArgumentException(
						"This map only supports the following keys: " + this.loaders.keySet());
			}
			return this.loaded.put(key, value);
		}

		@Override
		public V remove(Object key) {
			if (!this.loaders.containsKey(key)) {
				throw new IllegalArgumentException(
						"This map only supports the following keys: " + this.loaders.keySet());
			}
			return this.loaded.remove(key);
		}

		@Override
		public void putAll(Map<? extends K, ? extends V> m) {
			for (Map.Entry<? extends K, ? extends V> entry : m.entrySet()) {
				put(entry.getKey(), entry.getValue());
			}
		}

		@Override
		public void clear() {
			this.loaded.clear();
		}

		@Override
		public boolean containsValue(Object value) {
			return this.loaded.containsValue(value);
		}

		@Override
		public Collection<V> values() {
			return this.loaded.values();
		}

		@Override
		public Set<Entry<K, V>> entrySet() {
			return this.loaded.entrySet();
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}

			LoadingMap<?, ?> that = (LoadingMap<?, ?>) o;

			return this.loaded.equals(that.loaded);
		}

		@Override
		public int hashCode() {
			return this.loaded.hashCode();
		}

	}

}
