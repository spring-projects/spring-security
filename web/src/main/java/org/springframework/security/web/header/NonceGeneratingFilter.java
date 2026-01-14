/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.header;

import java.io.IOException;
import java.util.Base64;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A filter which generates a nonce string and sets it as a request attribute.
 *
 * <p>
 * {@link org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter}
 * can use the attribute to write a nonce-based Content Security Policy header, and a view
 * technology can render the nonce in generated HTML to allow intended inline
 * {@code <script>} or {@code <style>} blocks.
 *
 * <p>
 * This filter may be used to generate a nonce attribute for other purposes.
 *
 * @author Ziqin Wang
 * @since 7.1
 */
public final class NonceGeneratingFilter extends OncePerRequestFilter {

	private final String attributeName;

	private final StringKeyGenerator nonceGenerator;

	/**
	 * Creates a new instance.
	 * @param attributeName the name of the request attribute to generate
	 * @param nonceGenerator a {@link StringKeyGenerator} for generating nonce
	 * @throws IllegalArgumentException if {@code attributeName} is null or empty string,
	 * or {@code nonceGenerator} is null
	 */
	public NonceGeneratingFilter(String attributeName, StringKeyGenerator nonceGenerator) {
		Assert.hasLength(attributeName, "AttributeName must not be null or empty");
		Assert.notNull(nonceGenerator, "NonceGenerator must not be null");
		this.attributeName = attributeName;
		this.nonceGenerator = nonceGenerator;
	}

	/**
	 * Creates a new instance.
	 * <p>
	 * For each request, the created filter will generate a secure random nonce value with
	 * 128-bit entropy and encode it as a Base64 string without padding.
	 * @param attributeName the name of the request attribute to generate
	 * @throws IllegalArgumentException if {@code attributeName} is null or empty string
	 */
	public NonceGeneratingFilter(String attributeName) {
		this(attributeName, new Base64StringKeyGenerator(Base64.getEncoder().withoutPadding(), 16));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String nonce = this.nonceGenerator.generateKey();
		request.setAttribute(this.attributeName, nonce);
		filterChain.doFilter(request, response);
	}

}
