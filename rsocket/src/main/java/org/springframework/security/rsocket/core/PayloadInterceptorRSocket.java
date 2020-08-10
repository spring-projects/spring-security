/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.core;

import io.rsocket.Payload;
import io.rsocket.RSocket;
import io.rsocket.util.RSocketProxy;
import org.reactivestreams.Publisher;
import org.springframework.security.rsocket.api.PayloadExchangeType;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.util.MimeType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.List;

/**
 * Combines the {@link PayloadInterceptor} with an {@link RSocketProxy}
 *
 * @author Rob Winch
 * @since 5.2
 */
class PayloadInterceptorRSocket extends RSocketProxy {

	private final List<PayloadInterceptor> interceptors;

	private final MimeType metadataMimeType;

	private final MimeType dataMimeType;

	private final Context context;

	PayloadInterceptorRSocket(RSocket delegate, List<PayloadInterceptor> interceptors, MimeType metadataMimeType,
			MimeType dataMimeType) {
		this(delegate, interceptors, metadataMimeType, dataMimeType, Context.empty());
	}

	PayloadInterceptorRSocket(RSocket delegate, List<PayloadInterceptor> interceptors, MimeType metadataMimeType,
			MimeType dataMimeType, Context context) {
		super(delegate);
		this.metadataMimeType = metadataMimeType;
		this.dataMimeType = dataMimeType;
		if (delegate == null) {
			throw new IllegalArgumentException("delegate cannot be null");
		}
		if (interceptors == null) {
			throw new IllegalArgumentException("interceptors cannot be null");
		}
		if (interceptors.isEmpty()) {
			throw new IllegalArgumentException("interceptors cannot be empty");
		}
		this.interceptors = interceptors;
		this.context = context;
	}

	@Override
	public Mono<Void> fireAndForget(Payload payload) {
		return intercept(PayloadExchangeType.FIRE_AND_FORGET, payload)
				.flatMap(context -> this.source.fireAndForget(payload).subscriberContext(context));
	}

	@Override
	public Mono<Payload> requestResponse(Payload payload) {
		return intercept(PayloadExchangeType.REQUEST_RESPONSE, payload)
				.flatMap(context -> this.source.requestResponse(payload).subscriberContext(context));
	}

	@Override
	public Flux<Payload> requestStream(Payload payload) {
		return intercept(PayloadExchangeType.REQUEST_STREAM, payload)
				.flatMapMany(context -> this.source.requestStream(payload).subscriberContext(context));
	}

	@Override
	public Flux<Payload> requestChannel(Publisher<Payload> payloads) {
		return Flux.from(payloads).switchOnFirst((signal, innerFlux) -> {
			Payload firstPayload = signal.get();
			return intercept(PayloadExchangeType.REQUEST_CHANNEL, firstPayload).flatMapMany(
					context -> innerFlux.skip(1).flatMap(p -> intercept(PayloadExchangeType.PAYLOAD, p).thenReturn(p))
							.transform(securedPayloads -> Flux.concat(Flux.just(firstPayload), securedPayloads))
							.transform(securedPayloads -> this.source.requestChannel(securedPayloads))
							.subscriberContext(context));
		});
	}

	@Override
	public Mono<Void> metadataPush(Payload payload) {
		return intercept(PayloadExchangeType.METADATA_PUSH, payload)
				.flatMap(c -> this.source.metadataPush(payload).subscriberContext(c));
	}

	private Mono<Context> intercept(PayloadExchangeType type, Payload payload) {
		return Mono.defer(() -> {
			ContextPayloadInterceptorChain chain = new ContextPayloadInterceptorChain(this.interceptors);
			DefaultPayloadExchange exchange = new DefaultPayloadExchange(type, payload, this.metadataMimeType,
					this.dataMimeType);
			return chain.next(exchange).then(Mono.fromCallable(() -> chain.getContext()))
					.defaultIfEmpty(Context.empty()).subscriberContext(this.context);
		});
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[source=" + this.source + ",interceptors=" + this.interceptors + "]";
	}

}
