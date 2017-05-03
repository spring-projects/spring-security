/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package sample;

import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Service
public class MapUserRepository implements UserRepository {
	private final Map<String,User> users = new HashMap<>();

	public MapUserRepository() {
		save(new User("rob", "rob", "Rob", "Winch")).block();
		save(new User("admin", "admin", "Admin", "User")).block();
	}

	@Override
	public Flux<User> findAll() {
		return Flux.fromIterable(users.values());
	}

	@Override
	public Mono<User> findByUsername(String username) {
		User result = users.get(username);

		return result == null ? Mono.empty() : Mono.just(result);
	}

	public Mono<User> save(User user) {
		users.put(user.getUsername(), user);
		return Mono.just(user);
	}
}
