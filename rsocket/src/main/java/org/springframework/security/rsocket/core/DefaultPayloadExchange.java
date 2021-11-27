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

import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadExchangeType;
import org.springframework.util.Assert;
import org.springframework.util.MimeType;

/**
 * Default implementation of {@link PayloadExchange}
 *
 * @author Rob Winch
 * @since 5.2
 */
public class DefaultPayloadExchange implements PayloadExchange {

	private final PayloadExchangeType type;

	private final Payload payload;

	private final MimeType metadataMimeType;

	private final MimeType dataMimeType;

	public DefaultPayloadExchange(PayloadExchangeType type, Payload payload, MimeType metadataMimeType,
			MimeType dataMimeType) {
		Assert.notNull(type, "type cannot be null");
		Assert.notNull(payload, "payload cannot be null");
		Assert.notNull(metadataMimeType, "metadataMimeType cannot be null");
		Assert.notNull(dataMimeType, "dataMimeType cannot be null");
		this.type = type;
		this.payload = payload;
		this.metadataMimeType = metadataMimeType;
		this.dataMimeType = dataMimeType;
	}

	@Override
	public PayloadExchangeType getType() {
		return this.type;
	}

	@Override
	public Payload getPayload() {
		return this.payload;
	}

	@Override
	public MimeType getMetadataMimeType() {
		return this.metadataMimeType;
	}

	@Override
	public MimeType getDataMimeType() {
		return this.dataMimeType;
	}

}
