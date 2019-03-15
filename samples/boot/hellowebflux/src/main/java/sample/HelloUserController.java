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
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RestController
public class HelloUserController {

	@GetMapping("/")
	public Mono<Map<String, String>> hello(Mono<Principal> principal) {
		return principal
			.map(Principal::getName)
			.map(this::helloMessage);
	}

	private Map<String, String> helloMessage(String username) {
		return Collections.singletonMap("message", "Hello " + username + "!");
	}
}
