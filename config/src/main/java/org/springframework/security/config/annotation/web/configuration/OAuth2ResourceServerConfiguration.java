/*
 * Copyright 2002-2019 the original author or authors.
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

import org.reactivestreams.Subscription;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Operators;
import reactor.util.context.Context;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ClassUtils;

/**
 * {@link Configuration} for OAuth 2.0 Resource Server support.
 *
 * <p>
 * This {@code Configuration} is conditionally imported by {@link OAuth2ImportSelector}
 * when the {@code spring-security-oauth2-resource-server} module is present on the classpath.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see OAuth2ImportSelector
 */
@Import(OAuth2ResourceServerConfiguration.OAuth2ClientWebFluxImportSelector.class)
final class OAuth2ResourceServerConfiguration {

	static class OAuth2ClientWebFluxImportSelector implements ImportSelector {

		@Override
		public String[] selectImports(AnnotationMetadata importingClassMetadata) {
			boolean webfluxPresent = ClassUtils.isPresent(
					"org.springframework.web.reactive.function.client.WebClient", getClass().getClassLoader());

			return webfluxPresent ?
					new String[] { "org.springframework.security.config.annotation.web.configuration.OAuth2ResourceServerConfiguration.OAuth2ResourceServerWebFluxSecurityConfiguration" } :
					new String[] {};
		}
	}

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ResourceServerWebFluxSecurityConfiguration {
		@Bean
		BearerRequestContextSubscriberRegistrar bearerRequestContextSubscriberRegistrar() {
			return new BearerRequestContextSubscriberRegistrar();
		}

		/**
		 * Registers a {@link CoreSubscriber} that provides the current {@link Authentication}
		 * to the correct {@link Context}.
		 *
		 * This is published as a {@code @Bean} automatically, so long as `spring-security-oauth2-resource-server`
		 * and `spring-webflux` are on the classpath.
		 */
		static class BearerRequestContextSubscriberRegistrar
				implements InitializingBean, DisposableBean {

			private static final String REQUEST_CONTEXT_OPERATOR_KEY = BearerRequestContextSubscriber.class.getName();

			@Override
			public void afterPropertiesSet() throws Exception {
				Hooks.onLastOperator(REQUEST_CONTEXT_OPERATOR_KEY,
						Operators.liftPublisher((s, sub) -> createRequestContextSubscriber(sub)));
			}

			@Override
			public void destroy() throws Exception {
				Hooks.resetOnLastOperator(REQUEST_CONTEXT_OPERATOR_KEY);
			}

			private <T> CoreSubscriber<T> createRequestContextSubscriber(CoreSubscriber<T> delegate) {
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				return new BearerRequestContextSubscriber<>(delegate, authentication);
			}

			static class BearerRequestContextSubscriber<T> implements CoreSubscriber<T> {
				private CoreSubscriber<T> delegate;
				private final Context context;

				private BearerRequestContextSubscriber(CoreSubscriber<T> delegate,
						Authentication authentication) {

					this.delegate = delegate;
					Context parentContext = this.delegate.currentContext();
					Context context;
					if (authentication == null || parentContext.hasKey(Authentication.class)) {
						context = parentContext;
					} else {
						context = parentContext.put(Authentication.class, authentication);
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
	}
}
