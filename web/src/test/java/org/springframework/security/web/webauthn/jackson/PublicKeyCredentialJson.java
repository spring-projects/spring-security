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

package org.springframework.security.web.webauthn.jackson;

/**
 * JSON for {@code PublicKeyCredential<AuthenticatorAttestationResponse>}
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class PublicKeyCredentialJson {

	public static final String PUBLIC_KEY_JSON = """
				{
				   "id": "AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM",
				   "rawId": "AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM",
				   "response": {
					 "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk",
					 "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
					 "transports": [
					   "hybrid",
					   "internal"
					 ]
				   },
				   "type": "public-key",
				   "clientExtensionResults": {
					 "credProps": {
					   "rk": false
					 }
				   },
				   "authenticatorAttachment": "cross-platform"
				 }
			""";

	private PublicKeyCredentialJson() {
	}

}
