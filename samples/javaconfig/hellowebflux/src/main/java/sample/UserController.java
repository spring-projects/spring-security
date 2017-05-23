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

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RestController
public class UserController {

	@GetMapping("/me")
	public Mono<Map<String,String>> me(@AuthenticationPrincipal UserDetails user) {
		return me(Mono.just(user));
	}

	@GetMapping("/mono/me")
	public Mono<Map<String,String>> me(@AuthenticationPrincipal Mono<UserDetails> user) {
		return user.flatMap( u -> Mono.just(Collections.singletonMap("username", u.getUsername())));
	}

	@GetMapping("/mono/session")
	public Mono<Map<String,Object>> Session(Mono<WebSession> session) {
		return session.flatMap( s -> Mono.just(s.getAttributes()));
	}

	@GetMapping("/principal")
	public Mono<Map<String,String>> principal(Principal principal) {
		return principal(Mono.just(principal));
	}

	@GetMapping("/mono/principal")
	public Mono<Map<String,String>> principal(Mono<Principal> principal) {
		return principal.flatMap( p -> Mono.just(Collections.singletonMap("username", p.getName())));
	}

	@GetMapping("/admin")
	public Map<String,String> admin() {
		return Collections.singletonMap("isadmin", "true");
	}
}
