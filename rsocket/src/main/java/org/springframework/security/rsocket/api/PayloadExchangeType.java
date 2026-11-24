/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.rsocket.api;

/**
 * The {@link PayloadExchange} type.
 *
 * @author Rob Winch
 * @since 5.2
 */
public enum PayloadExchangeType {

	/**
	 * The <a href="https://rsocket.io/about/protocol#setup-frame-0x01">Setup</a>. Can be
	 * used to determine if a Payload is part of the connection
	 */
	SETUP(false),

	/**
	 * A <a href=
	 * "https://rsocket.io/about/protocol#request_fnf-fire-n-forget-frame-0x05">Fire and
	 * Forget</a> exchange.
	 */
	FIRE_AND_FORGET(true),

	/**
	 * A <a href="https://rsocket.io/about/protocol#request_response-frame-0x04">Request
	 * Response</a> exchange.
	 */
	REQUEST_RESPONSE(true),

	/**
	 * A <a href="https://rsocket.io/about/protocol#request_stream-frame-0x06">Request
	 * Stream</a> exchange. This is only represents the request portion. The
	 * {@link #PAYLOAD} type represents the data that submitted.
	 */
	REQUEST_STREAM(true),

	/**
	 * A <a href="https://rsocket.io/about/protocol#request_channel-frame-0x07">Request
	 * Channel</a> exchange.
	 */
	REQUEST_CHANNEL(true),

	/**
	 * A <a href="https://rsocket.io/about/protocol#payload-frame-0x0a">Payload</a>
	 * exchange.
	 */
	PAYLOAD(false),

	/**
	 * A <a href="https://rsocket.io/about/protocol#metadata_push-frame-0x0c">Metadata
	 * Push</a> exchange.
	 */
	METADATA_PUSH(true);

	private final boolean isRequest;

	PayloadExchangeType(boolean isRequest) {
		this.isRequest = isRequest;
	}

	/**
	 * Determines if this exchange is a type of request (i.e. the initial frame).
	 * @return true if it is a request, else false
	 */
	public boolean isRequest() {
		return this.isRequest;
	}

}
