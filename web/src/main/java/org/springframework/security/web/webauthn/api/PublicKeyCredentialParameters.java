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
 * The <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters">PublicKeyCredentialParameters</a>
 * is used to supply additional parameters when creating a new credential.
 *
 * @author Rob Winch
 * @author Justin Cranford
 * @since 6.4
 * @see PublicKeyCredentialCreationOptions#getPubKeyCredParams()
 */
public final class PublicKeyCredentialParameters {

	public static final PublicKeyCredentialParameters EdDSA = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.EdDSA);

	public static final PublicKeyCredentialParameters ES256 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.ES256);

	public static final PublicKeyCredentialParameters ES384 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.ES384);

	public static final PublicKeyCredentialParameters ES512 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.ES512);

	public static final PublicKeyCredentialParameters RS256 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.RS256);

	public static final PublicKeyCredentialParameters RS384 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.RS384);

	public static final PublicKeyCredentialParameters RS512 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.RS512);

	public static final PublicKeyCredentialParameters RS1 = new PublicKeyCredentialParameters(
			COSEAlgorithmIdentifier.RS1);

	/**
	 * This member specifies the type of credential to be created. The value SHOULD be a
	 * member of PublicKeyCredentialType but client platforms MUST ignore unknown values,
	 * ignoring any PublicKeyCredentialParameters with an unknown type.
	 */
	private final PublicKeyCredentialType type;

	/**
	 * This member specifies the cryptographic signature algorithm with which the newly
	 * generated credential will be used, and thus also the type of asymmetric key pair to
	 * be generated, e.g., RSA or Elliptic Curve.
	 */
	private final COSEAlgorithmIdentifier alg;

	private PublicKeyCredentialParameters(COSEAlgorithmIdentifier alg) {
		this(PublicKeyCredentialType.PUBLIC_KEY, alg);
	}

	private PublicKeyCredentialParameters(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
		this.type = type;
		this.alg = alg;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialparameters-type">type</a>
	 * property member specifies the type of credential to be created.
	 * @return the type
	 */
	public PublicKeyCredentialType getType() {
		return this.type;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialparameters-alg">alg</a>
	 * member specifies the cryptographic signature algorithm with which the newly
	 * generated credential will be used, and thus also the type of asymmetric key pair to
	 * be generated, e.g., RSA or Elliptic Curve.
	 * @return the algorithm
	 */
	public COSEAlgorithmIdentifier getAlg() {
		return this.alg;
	}

	public static PublicKeyCredentialParameters valueOf(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
		if (PublicKeyCredentialParameters.EdDSA.getType().equals(type) && PublicKeyCredentialParameters.EdDSA.getAlg().equals(alg)) {
			return EdDSA;
		} else if (PublicKeyCredentialParameters.ES256.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return ES256;
		} else if (PublicKeyCredentialParameters.ES384.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return ES384;
		} else if (PublicKeyCredentialParameters.ES512.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return ES512;
		} else if (PublicKeyCredentialParameters.RS256.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return RS256;
		} else if (PublicKeyCredentialParameters.RS384.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return RS384;
		} else if (PublicKeyCredentialParameters.RS512.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return RS512;
		} else if (PublicKeyCredentialParameters.RS1.getType().equals(type) && PublicKeyCredentialParameters.ES256.getAlg().equals(alg)) {
			return RS1;
		}
		return new PublicKeyCredentialParameters(type, alg);
	}

}
