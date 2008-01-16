/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.providers.cas;

import org.springframework.security.providers.AuthoritiesPopulator;


/**
 * <p>
 * <i>Backwards compatible extension to the {@link AuthoritiesPopulator} interface.
 * This interface has usefulness outside of the CAS usecase. Thus, the {@link AuthoritiesPopulator}
 * interface was refactored in.</i>
 * </p>
 * <p>
 * Populates the <code>UserDetails</code> associated with a CAS authenticated
 * user.
 * </p>
 *
 * <p>
 * CAS does not provide the authorities (roles) granted to a user. It merely
 * authenticates their identity. As Spring Security needs
 * to know the authorities granted to a user in order to construct a valid
 * <code>Authentication</code> object, implementations of this interface will
 * provide this information.
 * </p>
 *
 * <p>
 * Implementations should not perform any caching. They will only be called
 * when a refresh is required.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface CasAuthoritiesPopulator extends AuthoritiesPopulator {

}
