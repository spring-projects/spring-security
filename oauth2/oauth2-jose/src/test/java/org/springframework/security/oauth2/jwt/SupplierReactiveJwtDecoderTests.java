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
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link SupplierReactiveJwtDecoder}
 */
public class SupplierReactiveJwtDecoderTests {

	@Test
	public void decodeWhenUninitializedThenSupplierInitializes() {
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode("token")).willReturn(Mono.empty());
		SupplierReactiveJwtDecoder supplierReactiveJwtDecoder = new SupplierReactiveJwtDecoder(() -> jwtDecoder);
		supplierReactiveJwtDecoder.decode("token").block();
		verify(jwtDecoder).decode("token");
	}

	@Test
	public void decodeWhenInitializationFailsThenInitializationException() {
		Supplier<ReactiveJwtDecoder> broken = mock(Supplier.class);
		given(broken.get()).willThrow(RuntimeException.class);
		ReactiveJwtDecoder jwtDecoder = new SupplierReactiveJwtDecoder(broken);
		assertThatExceptionOfType(JwtDecoderInitializationException.class)
				.isThrownBy(() -> jwtDecoder.decode("token").block());
		verify(broken).get();
	}

	@Test
	public void decodeWhenInitializedThenCaches() {
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		Supplier<ReactiveJwtDecoder> supplier = mock(Supplier.class);
		given(supplier.get()).willReturn(jwtDecoder);
		given(jwtDecoder.decode("token")).willReturn(Mono.empty());
		ReactiveJwtDecoder supplierReactiveJwtDecoder = new SupplierReactiveJwtDecoder(supplier);
		supplierReactiveJwtDecoder.decode("token").block();
		supplierReactiveJwtDecoder.decode("token").block();
		verify(supplier, times(1)).get();
		verify(jwtDecoder, times(2)).decode("token");
	}

	@Test
	public void decodeWhenInitializationInitiallyFailsThenRecoverable() {
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		Supplier<ReactiveJwtDecoder> broken = mock(Supplier.class);
		given(broken.get()).willThrow(RuntimeException.class);
		given(jwtDecoder.decode("token")).willReturn(Mono.empty());
		ReactiveJwtDecoder supplierReactiveJwtDecoder = new SupplierReactiveJwtDecoder(broken);
		assertThatExceptionOfType(JwtDecoderInitializationException.class)
				.isThrownBy(() -> supplierReactiveJwtDecoder.decode("token").block());
		reset(broken);
		given(broken.get()).willReturn(jwtDecoder);
		supplierReactiveJwtDecoder.decode("token").block();
		verify(jwtDecoder).decode("token");
	}

}
