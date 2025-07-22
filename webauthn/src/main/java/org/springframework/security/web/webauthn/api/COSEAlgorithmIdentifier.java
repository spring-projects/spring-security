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

package org.springframework.security.web.webauthn.api;

/**
 * <a href=
 * "https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">COSEAlgorithmIdentifier</a> is
 * used to identify a cryptographic algorithm.
 *
 * @author Rob Winch
 * @since 6.4
 * @see PublicKeyCredentialParameters#getAlg()
 */
public final class COSEAlgorithmIdentifier {

	public static final COSEAlgorithmIdentifier EdDSA = new COSEAlgorithmIdentifier(-8);

	public static final COSEAlgorithmIdentifier ES256 = new COSEAlgorithmIdentifier(-7);

	public static final COSEAlgorithmIdentifier ES384 = new COSEAlgorithmIdentifier(-35);

	public static final COSEAlgorithmIdentifier ES512 = new COSEAlgorithmIdentifier(-36);

	public static final COSEAlgorithmIdentifier RS256 = new COSEAlgorithmIdentifier(-257);

	public static final COSEAlgorithmIdentifier RS384 = new COSEAlgorithmIdentifier(-258);

	public static final COSEAlgorithmIdentifier RS512 = new COSEAlgorithmIdentifier(-259);

	public static final COSEAlgorithmIdentifier RS1 = new COSEAlgorithmIdentifier(-65535);

	private final long value;

	private COSEAlgorithmIdentifier(long value) {
		this.value = value;
	}

	public long getValue() {
		return this.value;
	}

	@Override
	public String toString() {
		return String.valueOf(this.value);
	}

	public static COSEAlgorithmIdentifier[] values() {
		return new COSEAlgorithmIdentifier[] { EdDSA, ES256, ES384, ES512, RS256, RS384, RS512, RS1 };
	}

}
