/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.util.function.Supplier;

/**
 * A {@link JwtDecoder} that lazily initializes another {@link JwtDecoder}
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class SupplierJwtDecoder implements JwtDecoder {

	private final Supplier<JwtDecoder> jwtDecoderSupplier;

	private volatile JwtDecoder delegate;

	public SupplierJwtDecoder(Supplier<JwtDecoder> jwtDecoderSupplier) {
		this.jwtDecoderSupplier = jwtDecoderSupplier;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Jwt decode(String token) throws JwtException {
		if (this.delegate == null) {
			synchronized (this.jwtDecoderSupplier) {
				if (this.delegate == null) {
					try {
						this.delegate = this.jwtDecoderSupplier.get();
					}
					catch (Exception ex) {
						throw wrapException(ex);
					}
				}
			}
		}
		return this.delegate.decode(token);
	}

	private JwtDecoderInitializationException wrapException(Exception ex) {
		return new JwtDecoderInitializationException("Failed to lazily resolve the supplied JwtDecoder instance", ex);
	}

}
