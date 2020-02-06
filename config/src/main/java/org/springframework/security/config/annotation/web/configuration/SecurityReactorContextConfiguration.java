/*
 * Copyright 2002-2020 the original author or authors.
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

import org.reactivestreams.Publisher;
import org.reactivestreams.Subscription;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Operators;
import reactor.util.context.Context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.springframework.security.config.annotation.web.configuration.SecurityReactorContextConfiguration.SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES;

/**
 * {@link Configuration} that (potentially) adds a "decorating" {@code Publisher}
 * for the last operator created in every {@code Mono} or {@code Flux}.
 *
 * <p>
 * The {@code Publisher} is solely responsible for adding
 * the current {@code HttpServletRequest}, {@code HttpServletResponse} and {@code Authentication}
 * to the Reactor {@code Context} so that it's accessible in every flow, if required.
 *
 * @author Joe Grandja
 * @author Roman Matiushchenko
 * @since 5.2
 * @see OAuth2ImportSelector
 */
@Configuration(proxyBeanMethods = false)
class SecurityReactorContextConfiguration {

	@Bean
	SecurityReactorContextSubscriberRegistrar securityReactorContextSubscriberRegistrar() {
		return new SecurityReactorContextSubscriberRegistrar();
	}

	static class SecurityReactorContextSubscriberRegistrar implements InitializingBean, DisposableBean {
		private static final String SECURITY_REACTOR_CONTEXT_OPERATOR_KEY = "org.springframework.security.SECURITY_REACTOR_CONTEXT_OPERATOR";

		@Override
		public void afterPropertiesSet() throws Exception {
			Function<? super Publisher<Object>, ? extends Publisher<Object>> lifter =
					Operators.liftPublisher((pub, sub) -> createSubscriberIfNecessary(sub));

			Hooks.onLastOperator(SECURITY_REACTOR_CONTEXT_OPERATOR_KEY, pub -> {
				if (!contextAttributesAvailable()) {
					// No need to decorate so return original Publisher
					return pub;
				}
				return lifter.apply(pub);
			});
		}

		@Override
		public void destroy() throws Exception {
			Hooks.resetOnLastOperator(SECURITY_REACTOR_CONTEXT_OPERATOR_KEY);
		}

		<T> CoreSubscriber<T> createSubscriberIfNecessary(CoreSubscriber<T> delegate) {
			if (delegate.currentContext().hasKey(SECURITY_CONTEXT_ATTRIBUTES)) {
				// Already enriched. No need to create Subscriber so return original
				return delegate;
			}
			return new SecurityReactorContextSubscriber<>(delegate, getContextAttributes());
		}

		private static boolean contextAttributesAvailable() {
			return SecurityContextHolder.getContext().getAuthentication() != null ||
					RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes;
		}

		private static Map<Object, Object> getContextAttributes() {
			HttpServletRequest servletRequest = null;
			HttpServletResponse servletResponse = null;
			RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
			if (requestAttributes instanceof ServletRequestAttributes) {
				ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) requestAttributes;
				servletRequest = servletRequestAttributes.getRequest();
				servletResponse = servletRequestAttributes.getResponse();	// possible null
			}
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication == null && servletRequest == null) {
				return Collections.emptyMap();
			}

			Map<Object, Object> contextAttributes = new HashMap<>();
			if (servletRequest != null) {
				contextAttributes.put(HttpServletRequest.class, servletRequest);
			}
			if (servletResponse != null) {
				contextAttributes.put(HttpServletResponse.class, servletResponse);
			}
			if (authentication != null) {
				contextAttributes.put(Authentication.class, authentication);
			}

			return contextAttributes;
		}
	}

	static class SecurityReactorContextSubscriber<T> implements CoreSubscriber<T> {
		static final String SECURITY_CONTEXT_ATTRIBUTES = "org.springframework.security.SECURITY_CONTEXT_ATTRIBUTES";
		private final CoreSubscriber<T> delegate;
		private final Context context;

		SecurityReactorContextSubscriber(CoreSubscriber<T> delegate, Map<Object, Object> attributes) {
			this.delegate = delegate;
			Context currentContext = this.delegate.currentContext();
			Context context;
			if (currentContext.hasKey(SECURITY_CONTEXT_ATTRIBUTES)) {
				context = currentContext;
			} else {
				context = currentContext.put(SECURITY_CONTEXT_ATTRIBUTES, attributes);
			}
			this.context = context;
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
		public void onError(Throwable t) {
			this.delegate.onError(t);
		}

		@Override
		public void onComplete() {
			this.delegate.onComplete();
		}
	}
}
