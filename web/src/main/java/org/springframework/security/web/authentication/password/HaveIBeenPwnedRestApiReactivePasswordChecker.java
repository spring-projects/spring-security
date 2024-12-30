/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.password;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.ReactiveCompromisedPasswordChecker;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/**
 * Checks if the provided password was leaked by relying on
 * <a href="https://www.haveibeenpwned.com/API/v3#PwnedPasswords">Have I Been Pwned REST
 * API</a>. This implementation uses the Search by Range in order to protect the value of
 * the source password being searched for.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public class HaveIBeenPwnedRestApiReactivePasswordChecker implements ReactiveCompromisedPasswordChecker {

	private static final String API_URL = "https://api.pwnedpasswords.com/range/";

	private static final int PREFIX_LENGTH = 5;

	private final Log logger = LogFactory.getLog(getClass());

	private WebClient webClient = WebClient.builder().baseUrl(API_URL).build();

	private final MessageDigest sha1Digest;

	public HaveIBeenPwnedRestApiReactivePasswordChecker() {
		this.sha1Digest = getSha1Digest();
	}

	@Override
	public Mono<CompromisedPasswordDecision> check(String password) {
		return getHash(password).map((hash) -> new String(Hex.encode(hash)))
			.flatMap(this::findLeakedPassword)
			.map(CompromisedPasswordDecision::new);
	}

	private Mono<Boolean> findLeakedPassword(String encodedPassword) {
		String prefix = encodedPassword.substring(0, PREFIX_LENGTH).toUpperCase(Locale.ROOT);
		String suffix = encodedPassword.substring(PREFIX_LENGTH).toUpperCase(Locale.ROOT);
		return getLeakedPasswordsForPrefix(prefix).any((leakedPw) -> leakedPw.startsWith(suffix));
	}

	private Flux<String> getLeakedPasswordsForPrefix(String prefix) {
		return this.webClient.get().uri(prefix).retrieve().bodyToMono(String.class).flatMapMany((body) -> {
			if (StringUtils.hasText(body)) {
				return Flux.fromStream(body.lines());
			}
			return Flux.empty();
		})
			.doOnError((ex) -> this.logger.error("Request for leaked passwords failed", ex))
			.onErrorResume(WebClientResponseException.class, (ex) -> Flux.empty());
	}

	/**
	 * Sets the {@link WebClient} to use when making requests to Have I Been Pwned REST
	 * API. By default, a {@link WebClient} with a base URL of {@link #API_URL} is used.
	 * @param webClient the {@link WebClient} to use
	 */
	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
	}

	private Mono<byte[]> getHash(String password) {
		return Mono.fromSupplier(() -> this.sha1Digest.digest(password.getBytes(StandardCharsets.UTF_8)))
			.subscribeOn(Schedulers.boundedElastic())
			.publishOn(Schedulers.parallel());
	}

	private static MessageDigest getSha1Digest() {
		try {
			return MessageDigest.getInstance("SHA-1");
		}
		catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex.getMessage());
		}
	}

}
