/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.jose.jws;

import org.springframework.security.oauth2.jose.JwaAlgorithm;

/**
 * Super interface for cryptographic algorithms defined by the JSON Web Algorithms (JWA)
 * specification and used by JSON Web Signature (JWS) to digitally sign or create a MAC of
 * the contents of the JWS Protected Header and JWS Payload.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see JwaAlgorithm
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518">JSON Web Algorithms
 * (JWA)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc7518#section-3">Cryptographic Algorithms for Digital
 * Signatures and MACs</a>
 */
public interface JwsAlgorithm extends JwaAlgorithm {

}
