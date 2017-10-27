/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

/**
 * The &quot;Claims&quot; defined by the <i>OpenID Connect Core 1.0</i> specification
 * that can be returned in the <i>ID Token</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see IdToken
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 */

public interface IdTokenClaim {

	String ISS = "iss";

	String SUB = "sub";

	String AUD = "aud";

	String EXP = "exp";

	String IAT = "iat";

	String AUTH_TIME = "auth_time";

	String NONCE = "nonce";

	String ACR = "acr";

	String AMR = "amr";

	String AZP = "azp";

	String AT_HASH = "at_hash";

	String C_HASH = "c_hash";

}
