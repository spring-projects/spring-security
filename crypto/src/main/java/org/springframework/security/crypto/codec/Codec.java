/*
 * Copyright 2011-2017 the original author or authors.
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
package org.springframework.security.crypto.codec;

/**
 * A {@code Codec} is responsible for translating byte array into {@link String} and a {@link String} back into byte array in a compatible manner.
 * <p>
 * Compatible manner means:
 * <dl>
 *     <dt>given {@code codec} as a {@link Codec} implementation and {@code array} as a byte array</dt>
 *     <dd>{@code java.util.Arrays.equals( codec.decode( codec.encode( array ) ), array ) == true}</dd>
 *     <dt>given {@code codec} as a {@link Codec} implementation and {@code string} as a String</dt>
 *     <dd>{@code string.equals( codec.encode( codec.decode( string ) ) ) == true}</dd>
 * </dl>
 *
 * @author Guillaume Wallet
 * @since 4.2.2
 * @see Codecs
 */
public interface Codec {
	/**
	 * Produces a {@link String} from a byte array.
	 *
	 * @param source source byte array.
	 * @return String representation of the byte array.
	 */
	String encode(byte[] source);

	/**
	 * Produces a byte array from a {@link String} representation.
	 *
	 * @param source the string representation.
	 * @return Returns the byte array represented in the {@link String}.
	 */
	byte[] decode(String source);
}
