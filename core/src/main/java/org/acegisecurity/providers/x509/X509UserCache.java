/* Copyright 2004, 2005 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.x509;

import org.acegisecurity.UserDetails;

import java.security.cert.X509Certificate;

/**
 * Provides a cache of {@link UserDetails} objects for the
 * {@link X509AuthenticationProvider}.
 * <p>
 * Similar in function to the {@link org.acegisecurity.providers.dao.UserCache}
 * used by the Dao provider, but the cache is keyed with the user's certificate
 * rather than the user name.  
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface X509UserCache {

    UserDetails getUserFromCache(X509Certificate userCertificate);

    void putUserInCache(X509Certificate key, UserDetails user);

    void removeUserFromCache(X509Certificate key);
}
