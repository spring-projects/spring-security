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
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Checks if the provided password was leaked by relying on
 * <a href="https://www.haveibeenpwned.com/API/v3#PwnedPasswords">Have I Been Pwned REST
 * API</a>. This implementation uses the Search by Range in order to protect the value of
 * the source password being searched for.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class HaveIBeenPwnedRestApiPasswordChecker implements CompromisedPasswordChecker {

	private static final String API_URL = "https://api.pwnedpasswords.com/range/";

	private static final int PREFIX_LENGTH = 5;

	private final Log logger = LogFactory.getLog(getClass());

	private final MessageDigest sha1Digest;

	private RestClient restClient = RestClient.builder().baseUrl(API_URL).build();

	public HaveIBeenPwnedRestApiPasswordChecker() {
		this.sha1Digest = getSha1Digest();
	}

	@Override
	@NonNull
	public CompromisedPasswordDecision check(String password) {
		byte[] hash = this.sha1Digest.digest(password.getBytes(StandardCharsets.UTF_8));
		String encoded = new String(Hex.encode(hash)).toUpperCase(Locale.ROOT);
		String prefix = encoded.substring(0, PREFIX_LENGTH);
		String suffix = encoded.substring(PREFIX_LENGTH);

		List<String> passwords = getLeakedPasswordsForPrefix(prefix);
		boolean isLeaked = findLeakedPassword(passwords, suffix);
		return new CompromisedPasswordDecision(isLeaked);
	}

	/**
	 * Sets the {@link RestClient} to use when making requests to Have I Been Pwned REST
	 * API. By default, a {@link RestClient} with a base URL of {@link #API_URL} is used.
	 * @param restClient the {@link RestClient} to use
	 */
	public void setRestClient(RestClient restClient) {
		Assert.notNull(restClient, "restClient cannot be null");
		this.restClient = restClient;
	}

	private boolean findLeakedPassword(List<String> passwords, String suffix) {
		for (String pw : passwords) {
			if (pw.startsWith(suffix)) {
				return true;
			}
		}
		return false;
	}

	private List<String> getLeakedPasswordsForPrefix(String prefix) {
		try {
			String response = this.restClient.get().uri(prefix).retrieve().body(String.class);
			if (!StringUtils.hasText(response)) {
				return Collections.emptyList();
			}
			return response.lines().toList();
		}
		catch (RestClientException ex) {
			this.logger.error("Request for leaked passwords failed", ex);
			return Collections.emptyList();
		}
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
