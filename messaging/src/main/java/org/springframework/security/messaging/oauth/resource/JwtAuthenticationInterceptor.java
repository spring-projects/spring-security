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

package org.springframework.security.messaging.oauth.resource;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.util.Assert;

/**
 * Given a bearer token in a message header, authenticates it and places the resulting
 * {@link Authentication} in a second header, leaving the rest of the message untouched.
 * <p>
 * This is typically placed before
 * {@link org.springframework.security.messaging.context.SecurityContextChannelInterceptor},
 * which installs the {@link Authentication} in the
 * {@link org.springframework.security.core.context.SecurityContextHolder}, and
 * {@link org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor},
 * which authorizes the message and permits or impedes its progress. Setting the
 * authentication header to {@link SimpMessageHeaderAccessor#USER_HEADER} lines it up with
 * the default used by {@code SecurityContextChannelInterceptor}.
 * <p>
 * If the token cannot be authenticated, the {@link AuthenticationException} raised by the
 * {@link AuthenticationManager} is propagated and the message is not sent.
 *
 * @author Josh Long
 * @since 7.2
 */
public class JwtAuthenticationInterceptor implements ChannelInterceptor {

	private final String tokenHeaderName;

	private final AuthenticationManager authenticationManager;

	private final String authenticationHeaderName;

	/**
	 * Creates an instance.
	 * @param tokenHeaderName the header to read the bearer token from
	 * @param authenticationHeaderName the header to write the {@link Authentication} to
	 * @param authenticationManager the {@link AuthenticationManager} used to authenticate
	 * the token
	 */
	public JwtAuthenticationInterceptor(String tokenHeaderName, String authenticationHeaderName,
			AuthenticationManager authenticationManager) {
		Assert.hasText(tokenHeaderName, "tokenHeaderName cannot be empty");
		Assert.hasText(authenticationHeaderName, "authenticationHeaderName cannot be empty");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.tokenHeaderName = tokenHeaderName;
		this.authenticationHeaderName = authenticationHeaderName;
		this.authenticationManager = authenticationManager;
	}

	/**
	 * Creates an instance backed by a single {@link AuthenticationProvider}, typically a
	 * {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider}.
	 * @param tokenHeaderName the header to read the bearer token from
	 * @param authenticationHeaderName the header to write the {@link Authentication} to
	 * @param authenticationProvider the {@link AuthenticationProvider} used to
	 * authenticate the token
	 */
	public JwtAuthenticationInterceptor(String tokenHeaderName, String authenticationHeaderName,
			AuthenticationProvider authenticationProvider) {
		this(tokenHeaderName, authenticationHeaderName, (authentication) -> {
			Authentication result = authenticationProvider.authenticate(authentication);
			if (result == null) {
				throw new BadCredentialsException("null authentication response provided!");
			}
			return result;
		});
	}

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		Assert.state(message.getHeaders().containsKey(this.tokenHeaderName),
				() -> "there is no header called '" + this.tokenHeaderName + "'");
		String token = (String) message.getHeaders().get(this.tokenHeaderName);
		Assert.hasText(token, () -> "the header '" + this.tokenHeaderName + "' must contain a non-empty token");
		Authentication authentication = this.authenticationManager
			.authenticate(new BearerTokenAuthenticationToken(token));
		return MessageBuilder.fromMessage(message).setHeader(this.authenticationHeaderName, authentication).build();
	}

}
