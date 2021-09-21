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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link SupplierJwtDecoder}
 *
 * @author Josh Cummings
 */
public class SupplierJwtDecoderTests {

	@Test
	public void decodeWhenUninitializedThenSupplierInitializes() {
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		SupplierJwtDecoder supplierJwtDecoder = new SupplierJwtDecoder(() -> jwtDecoder);
		supplierJwtDecoder.decode("token");
		verify(jwtDecoder).decode("token");
	}

	@Test
	public void decodeWhenInitializationFailsThenInitializationException() {
		Supplier<JwtDecoder> broken = mock(Supplier.class);
		given(broken.get()).willThrow(RuntimeException.class);
		JwtDecoder jwtDecoder = new SupplierJwtDecoder(broken);
		assertThatExceptionOfType(JwtDecoderInitializationException.class).isThrownBy(() -> jwtDecoder.decode("token"));
		verify(broken).get();
	}

	@Test
	public void decodeWhenInitializedThenCaches() {
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		Supplier<JwtDecoder> supplier = mock(Supplier.class);
		given(supplier.get()).willReturn(jwtDecoder);
		JwtDecoder supplierJwtDecoder = new SupplierJwtDecoder(supplier);
		supplierJwtDecoder.decode("token");
		supplierJwtDecoder.decode("token");
		verify(supplier, times(1)).get();
		verify(jwtDecoder, times(2)).decode("token");
	}

	@Test
	public void decodeWhenInitializationInitiallyFailsThenRecoverable() {
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		Supplier<JwtDecoder> broken = mock(Supplier.class);
		given(broken.get()).willThrow(RuntimeException.class);
		JwtDecoder supplierJwtDecoder = new SupplierJwtDecoder(broken);
		assertThatExceptionOfType(JwtDecoderInitializationException.class)
				.isThrownBy(() -> supplierJwtDecoder.decode("token"));
		reset(broken);
		given(broken.get()).willReturn(jwtDecoder);
		supplierJwtDecoder.decode("token");
		verify(jwtDecoder).decode("token");
	}

}
