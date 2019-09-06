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

package org.springframework.security.rsocket.api;

/**
 * The {@link PayloadExchange} type
 *
 * @author Rob Winch
 * @since 5.2
 */
public enum PayloadExchangeType {
	/**
	 * The <a href="https://rsocket.io/docs/Protocol#setup-frame-0x01">Setup</a>. Can
	 * be used to determine if a Payload is part of the connection
	 */
	SETUP(false),

	/**
	 * A <a href="https://rsocket.io/docs/Protocol#frame-fnf">Fire and Forget</a> exchange.
	 */
	FIRE_AND_FORGET(true),

	/**
	 * A <a href="https://rsocket.io/docs/Protocol#frame-request-response">Request
	 * Response</a> exchange.
	 */
	REQUEST_RESPONSE(true),

	/**
	 * A <a href="https://rsocket.io/docs/Protocol#request-stream-frame">Request Stream</a>
	 * exchange. This is only represents the request portion. The {@link #PAYLOAD} type
	 * represents the data that submitted.
	 */
	REQUEST_STREAM(true),

	/**
	 * A <a href="https://rsocket.io/docs/Protocol#request-channel-frame">Request
	 * Channel</a> exchange.
	 */
	REQUEST_CHANNEL(true),

	/**
	 * A <a href="https://rsocket.io/docs/Protocol#payload-frame">Payload</a> exchange.
	 */
	PAYLOAD(false),

	/**
	 * A <a href="https://rsocket.io/docs/Protocol#frame-metadata-push">Metadata Push</a>
	 * exchange.
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
