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

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;


/**
 * See: {@link ConcurrentSessionControllerImpl}
 *
 * @author Ray Krueger
 * @see ConcurrentSessionControllerImpl
 */
public interface ConcurrentSessionController {
    //~ Methods ================================================================

    void afterAuthentication(Authentication initialAuth, Authentication result)
            throws AuthenticationException;

    void beforeAuthentication(Authentication initialAuth)
            throws AuthenticationException;
}
