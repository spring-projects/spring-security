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

package org.springframework.security.rsocket.interceptor;

import io.rsocket.ConnectionSetupPayload;
import io.rsocket.Payload;
import io.rsocket.RSocket;
import io.rsocket.SocketAcceptor;
import io.rsocket.metadata.WellKnownMimeType;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.List;

/**
 * @author Rob Winch
 * @since 5.2
 */
class PayloadSocketAcceptor implements SocketAcceptor {
	private final SocketAcceptor delegate;

	private final List<PayloadInterceptor> interceptors;

	@Nullable
	private MimeType defaultDataMimeType;

	private MimeType defaultMetadataMimeType =
			MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	PayloadSocketAcceptor(SocketAcceptor delegate, List<PayloadInterceptor> interceptors) {
		Assert.notNull(delegate, "delegate cannot be null");
		if (interceptors == null) {
			throw new IllegalArgumentException("interceptors cannot be null");
		}
		if (interceptors.isEmpty()) {
			throw new IllegalArgumentException("interceptors cannot be empty");
		}
		this.delegate = delegate;
		this.interceptors = interceptors;
	}

	@Override
	public Mono<RSocket> accept(ConnectionSetupPayload setup, RSocket sendingSocket) {
		MimeType dataMimeType = parseMimeType(setup.dataMimeType(), this.defaultDataMimeType);
		Assert.notNull(dataMimeType, "No `dataMimeType` in ConnectionSetupPayload and no default value");

		MimeType metadataMimeType = parseMimeType(setup.metadataMimeType(), this.defaultMetadataMimeType);
		Assert.notNull(metadataMimeType, "No `metadataMimeType` in ConnectionSetupPayload and no default value");

		// FIXME do we want to make the sendingSocket available in the PayloadExchange
		return intercept(setup, dataMimeType, metadataMimeType)
			.flatMap(ctx -> this.delegate.accept(setup, sendingSocket)
				.map(acceptingSocket -> new PayloadInterceptorRSocket(acceptingSocket, this.interceptors, metadataMimeType, dataMimeType, ctx))
			);
	}

	private Mono<Context> intercept(Payload payload, MimeType dataMimeType, MimeType metadataMimeType) {
		return Mono.defer(() -> {
			ContextPayloadInterceptorChain chain = new ContextPayloadInterceptorChain(this.interceptors);
			DefaultPayloadExchange exchange = new DefaultPayloadExchange(PayloadExchangeType.SETUP, payload,
					metadataMimeType, dataMimeType);
			return chain.next(exchange)
					.then(Mono.fromCallable(() -> chain.getContext()))
					.defaultIfEmpty(Context.empty());
		});
	}

	private MimeType parseMimeType(String str, MimeType defaultMimeType) {
		return StringUtils.hasText(str) ? MimeTypeUtils.parseMimeType(str) : defaultMimeType;
	}

	public void setDefaultDataMimeType(@Nullable MimeType defaultDataMimeType) {
		this.defaultDataMimeType = defaultDataMimeType;
	}

	public void setDefaultMetadataMimeType(MimeType defaultMetadataMimeType) {
		Assert.notNull(defaultMetadataMimeType, "defaultMetadataMimeType cannot be null");
		this.defaultMetadataMimeType = defaultMetadataMimeType;
	}
}
