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

import io.rsocket.SocketAcceptor;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.plugins.SocketAcceptorInterceptor;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

import java.util.List;

/**
 * A {@link SocketAcceptorInterceptor} that applies the {@link PayloadInterceptor}s
 *
 * @author Rob Winch
 * @since 5.2
 */
public class PayloadSocketAcceptorInterceptor implements SocketAcceptorInterceptor {

	private final List<PayloadInterceptor> interceptors;

	@Nullable
	private MimeType defaultDataMimeType;

	private MimeType defaultMetadataMimeType =
		MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	public PayloadSocketAcceptorInterceptor(List<PayloadInterceptor> interceptors) {
		this.interceptors = interceptors;
	}

	@Override
	public SocketAcceptor apply(SocketAcceptor socketAcceptor) {
		PayloadSocketAcceptor acceptor = new PayloadSocketAcceptor(
				socketAcceptor, this.interceptors);
		acceptor.setDefaultDataMimeType(this.defaultDataMimeType);
		acceptor.setDefaultMetadataMimeType(this.defaultMetadataMimeType);
		return acceptor;
	}

	public void setDefaultDataMimeType(@Nullable MimeType defaultDataMimeType) {
		this.defaultDataMimeType = defaultDataMimeType;
	}

	public void setDefaultMetadataMimeType(MimeType defaultMetadataMimeType) {
		Assert.notNull(defaultMetadataMimeType, "defaultMetadataMimeType cannot be null");
		this.defaultMetadataMimeType = defaultMetadataMimeType;
	}
}
