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

import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * The <i>scope</i> values defined by the <i>OpenID Connect Core 1.0</i> specification
 * that can be used to request {@link StandardClaimNames Claims}.
 * <p>
 * The scope(s) associated to an {@link OAuth2AccessToken} determine what claims (resources)
 * will be available when they are used to access <i>OAuth 2.0 Protected Endpoints</i>,
 * such as the <i>UserInfo Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see StandardClaimNames
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">Requesting Claims using Scope Values</a>
 */
public interface OidcScopes {

	String OPENID = "openid";

	String PROFILE = "profile";

	String EMAIL = "email";

	String ADDRESS = "address";

	String PHONE = "phone";

}
