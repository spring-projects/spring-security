/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Component
public class UserController {
	private final SecurityContextRepository repo = new WebSessionSecurityContextRepository();

	private final UserRepository users;

	public UserController(UserRepository users) {
		this.users = users;
	}

	public Mono<ServerResponse> principal(ServerRequest serverRequest) {
		return serverRequest.principal().cast(Authentication.class).flatMap(p ->
			ServerResponse.ok()
				.contentType(MediaType.APPLICATION_JSON)
				.syncBody(p.getPrincipal()));
	}

	public Mono<ServerResponse> users(ServerRequest serverRequest) {
		return ServerResponse.ok()
			.contentType(MediaType.APPLICATION_JSON)
			.body(this.users.findAll(), User.class);
	}

	public Mono<ServerResponse> admin(ServerRequest serverRequest) {
		return serverRequest.principal().cast(Authentication.class).flatMap(p ->
			ServerResponse.ok()
				.contentType(MediaType.APPLICATION_JSON)
				.syncBody( Collections.singletonMap("isadmin", "true")));
	}
}
