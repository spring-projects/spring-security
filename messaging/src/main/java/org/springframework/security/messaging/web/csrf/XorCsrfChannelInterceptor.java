/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.messaging.web.csrf;

import java.security.MessageDigest;
import java.util.Map;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpMessageTypeMatcher;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

/**
 * {@link ChannelInterceptor} that validates a CSRF token masked by the
 * {@link org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler} in
 * the header of any {@link SimpMessageType#CONNECT} message.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public final class XorCsrfChannelInterceptor implements ChannelInterceptor {

	private final MessageMatcher<Object> matcher = new SimpMessageTypeMatcher(SimpMessageType.CONNECT);

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		if (!this.matcher.matches(message)) {
			return message;
		}
		Map<String, Object> sessionAttributes = SimpMessageHeaderAccessor.getSessionAttributes(message.getHeaders());
		CsrfToken expectedToken = (sessionAttributes != null)
				? (CsrfToken) sessionAttributes.get(CsrfToken.class.getName()) : null;
		if (expectedToken == null) {
			throw new MissingCsrfTokenException(null);
		}
		String actualToken = SimpMessageHeaderAccessor.wrap(message)
			.getFirstNativeHeader(expectedToken.getHeaderName());
		String actualTokenValue = XorCsrfTokenUtils.getTokenValue(actualToken, expectedToken.getToken());
		boolean csrfCheckPassed = equalsConstantTime(expectedToken.getToken(), actualTokenValue);
		if (!csrfCheckPassed) {
			throw new InvalidCsrfTokenException(expectedToken, actualToken);
		}
		return message;
	}

	/**
	 * Constant time comparison to prevent against timing attacks.
	 * @param expected
	 * @param actual
	 * @return
	 */
	private static boolean equalsConstantTime(String expected, String actual) {
		if (expected == actual) {
			return true;
		}
		if (expected == null || actual == null) {
			return false;
		}
		// Encode after ensure that the string is not null
		byte[] expectedBytes = Utf8.encode(expected);
		byte[] actualBytes = Utf8.encode(actual);
		return MessageDigest.isEqual(expectedBytes, actualBytes);
	}

}
