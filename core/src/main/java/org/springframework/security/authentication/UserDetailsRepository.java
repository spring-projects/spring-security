package org.springframework.security.authentication;

import org.springframework.security.core.userdetails.UserDetails;

import reactor.core.publisher.Mono;

public interface UserDetailsRepository {

	Mono<UserDetails> findByUsername(String username);
}
