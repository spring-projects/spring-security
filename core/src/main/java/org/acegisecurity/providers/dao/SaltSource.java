/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao;

/**
 * Provides alternative sources of the salt to use for encoding passwords.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface SaltSource {
    //~ Methods ================================================================

    /**
     * Returns the salt to use for the indicated user.
     *
     * @param user from the <code>AuthenticationDao</code>
     *
     * @return the salt to use for this <code>USer</code>
     */
    public Object getSalt(User user);
}
