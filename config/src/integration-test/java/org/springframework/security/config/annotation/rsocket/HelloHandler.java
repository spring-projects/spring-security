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

package org.springframework.security.config.annotation.rsocket;

import io.rsocket.ConnectionSetupPayload;
import io.rsocket.Payload;
import io.rsocket.RSocket;
import io.rsocket.SocketAcceptor;
import io.rsocket.util.ByteBufPayload;
import reactor.core.publisher.Mono;

public class HelloHandler implements SocketAcceptor {

	@Override
	public Mono<RSocket> accept(ConnectionSetupPayload setup, RSocket sendingSocket) {
		return Mono.just(new RSocket() {
			@Override
			public Mono<Payload> requestResponse(Payload payload) {
				String data = payload.getDataUtf8();
				payload.release();
				System.out.println("Got " + data);
				return Mono.just(ByteBufPayload.create("Hello " + data));
			}
		});
	}

}
