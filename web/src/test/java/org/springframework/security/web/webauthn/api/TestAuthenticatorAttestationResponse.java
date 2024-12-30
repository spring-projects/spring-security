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

public final class TestAuthenticatorAttestationResponse {

	public static AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder createAuthenticatorAttestationResponse() {
		return AuthenticatorAttestationResponse.builder()
			.attestationObject(Bytes.fromBase64(
					"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAALraVWanqkAfvZZFYZpVEg0AEDWRLOHq0Wxw4cOkCemynKqlAQIDJiABIVgg4Hkrn2kbGmpZTdoDZUNrppo93OqgQV7ONzVvo5GLCFciWCCrf6yIQggq2BfZntawxRsBBbWG_FWkYAoU8yPipS-5hg-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"))
			.clientDataJSON(Bytes.fromBase64(
					"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicTdsQ2RkM1NWUXhkQy12OHBuUkFHRW4xQjJNLXQ3WkVDV1B3Q0FtaFd2YyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
			.transports(AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL);
	}

	private TestAuthenticatorAttestationResponse() {
	}

}
