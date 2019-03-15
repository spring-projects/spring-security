/*
 * Copyright 2002-2017 the original author or authors.
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

package sample;

import java.security.Principal;
import java.util.Collections;

import reactor.core.publisher.Mono;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Component
public class HelloUserController {

	public Mono<ServerResponse> hello(ServerRequest serverRequest) {
		return serverRequest.principal()
			.map(Principal::getName)
			.flatMap(username ->
				ServerResponse.ok()
					.contentType(MediaType.APPLICATION_JSON)
					.syncBody(Collections.singletonMap("message", "Hello " + username + "!"))
			);
	}
}
