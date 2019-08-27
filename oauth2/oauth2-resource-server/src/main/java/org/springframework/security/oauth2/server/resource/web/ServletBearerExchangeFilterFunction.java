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

package org.springframework.security.oauth2.server.resource.web;

import java.util.Map;
import java.util.function.Consumer;

import org.reactivestreams.Subscription;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Operators;
import reactor.util.context.Context;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * An {@link ExchangeFilterFunction} that adds the
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>
 * from an existing {@link AbstractOAuth2Token} tied to the current {@link Authentication}.
 *
 * Suitable for Servlet applications, applying it to a typical {@link org.springframework.web.reactive.function.client.WebClient}
 * configuration:
 *
 * <pre>
 *  @Bean
 *  WebClient webClient() {
 *      ServletBearerExchangeFilterFunction bearer = new ServletBearerExchangeFilterFunction();
 *      return WebClient.builder()
 *              .apply(bearer.oauth2Configuration())
 *              .build();
 *  }
 * </pre>
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class ServletBearerExchangeFilterFunction
		implements ExchangeFilterFunction, InitializingBean, DisposableBean {

	private static final String AUTHENTICATION_ATTR_NAME = Authentication.class.getName();

	private static final String REQUEST_CONTEXT_OPERATOR_KEY = RequestContextSubscriber.class.getName();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		Hooks.onLastOperator(REQUEST_CONTEXT_OPERATOR_KEY,
				Operators.liftPublisher((s, sub) -> createRequestContextSubscriber(sub)));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void destroy() throws Exception {
		Hooks.resetOnLastOperator(REQUEST_CONTEXT_OPERATOR_KEY);
	}

	/**
	 * Configures the builder with {@link #defaultRequest()} and adds this as a {@link ExchangeFilterFunction}
	 * @return the {@link Consumer} to configure the builder
	 */
	public Consumer<WebClient.Builder> oauth2Configuration() {
		return builder -> builder.defaultRequest(defaultRequest()).filter(this);
	}

	/**
	 * Provides defaults for the {@link Authentication} using
	 * {@link SecurityContextHolder}. It also can default the {@link AbstractOAuth2Token} using the
	 * {@link #authentication(Authentication)}.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public Consumer<WebClient.RequestHeadersSpec<?>> defaultRequest() {
		return spec -> spec.attributes(attrs -> {
			populateDefaultAuthentication(attrs);
		});
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link Authentication} used to
	 * look up and save the {@link AbstractOAuth2Token}. The value is defaulted in
	 * {@link ServletBearerExchangeFilterFunction#defaultRequest()}
	 *
	 * @param authentication the {@link Authentication} to use.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> authentication(Authentication authentication) {
		return attributes -> attributes.put(AUTHENTICATION_ATTR_NAME, authentication);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return mergeRequestAttributesIfNecessary(request)
				.filter(req -> req.attribute(AUTHENTICATION_ATTR_NAME).isPresent())
				.map(req -> getOAuth2Token(req.attributes()))
				.map(token -> bearer(request, token))
				.flatMap(next::exchange)
				.switchIfEmpty(Mono.defer(() -> next.exchange(request)));
	}

	private Mono<ClientRequest> mergeRequestAttributesIfNecessary(ClientRequest request) {
		if (request.attribute(AUTHENTICATION_ATTR_NAME).isPresent()) {
			return Mono.just(request);
		}

		return mergeRequestAttributesFromContext(request);
	}

	private Mono<ClientRequest> mergeRequestAttributesFromContext(ClientRequest request) {
		ClientRequest.Builder builder = ClientRequest.from(request);
		return Mono.subscriberContext()
				.map(ctx -> builder.attributes(attrs -> populateRequestAttributes(attrs, ctx)))
				.map(ClientRequest.Builder::build);
	}

	private void populateRequestAttributes(Map<String, Object> attrs, Context ctx) {
		RequestContextDataHolder holder = RequestContextSubscriber.getRequestContext(ctx);
		if (holder == null) {
			return;
		}
		if (holder.getAuthentication() != null) {
			attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, holder.getAuthentication());
		}
	}

	private AbstractOAuth2Token getOAuth2Token(Map<String, Object> attrs) {
		Authentication authentication = (Authentication) attrs.get(AUTHENTICATION_ATTR_NAME);
		if (authentication.getCredentials() instanceof AbstractOAuth2Token) {
			return (AbstractOAuth2Token) authentication.getCredentials();
		}
		return null;
	}

	private ClientRequest bearer(ClientRequest request, AbstractOAuth2Token token) {
		return ClientRequest.from(request)
				.headers(headers -> headers.setBearerAuth(token.getTokenValue()))
				.build();
	}

	private <T> CoreSubscriber<T> createRequestContextSubscriber(CoreSubscriber<T> delegate) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return new RequestContextSubscriber<>(delegate, authentication);
	}

	private void populateDefaultAuthentication(Map<String, Object> attrs) {
		if (attrs.containsKey(AUTHENTICATION_ATTR_NAME)) {
			return;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, authentication);
	}

	private static class RequestContextDataHolder {
		private final Authentication authentication;

		RequestContextDataHolder(Authentication authentication) {
			this.authentication = authentication;
		}

		public Authentication getAuthentication() {
			return this.authentication;
		}
	}

	private static class RequestContextSubscriber<T> implements CoreSubscriber<T> {
		private static final String REQUEST_CONTEXT_DATA_HOLDER_ATTR_NAME =
				RequestContextSubscriber.class.getName().concat(".REQUEST_CONTEXT_DATA_HOLDER");

		private CoreSubscriber<T> delegate;
		private final Context context;

		private RequestContextSubscriber(CoreSubscriber<T> delegate,
				Authentication authentication) {

			this.delegate = delegate;
			Context parentContext = this.delegate.currentContext();
			Context context;
			if (authentication == null || parentContext.hasKey(REQUEST_CONTEXT_DATA_HOLDER_ATTR_NAME)) {
				context = parentContext;
			} else {
				context = parentContext.put(REQUEST_CONTEXT_DATA_HOLDER_ATTR_NAME,
						new RequestContextDataHolder(authentication));
			}

			this.context = context;
		}

		@Nullable
		static RequestContextDataHolder getRequestContext(Context ctx) {
			return ctx.getOrDefault(REQUEST_CONTEXT_DATA_HOLDER_ATTR_NAME, null);
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
