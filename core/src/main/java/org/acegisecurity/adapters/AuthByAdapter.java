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

package org.acegisecurity.adapters;

import org.acegisecurity.Authentication;


/**
 * Indicates a specialized, immutable, server-side only {@link Authentication}
 * class.
 *
 * <P>
 * Automatically considered valid by the {@link AuthByAdapterProvider},
 * provided the hash code presented by the implementation objects matches that
 * expected by the <code>AuthByAdapterProvider</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AuthByAdapter extends Authentication {
    //~ Methods ========================================================================================================

    /**
     * Returns the hash code of the key that was passed to the constructor of the <code>AuthByAdapter</code>
     * implementation. The implementation should convert the value to a hash code at construction time, rather than
     * storing the key itself.
     *
     * @return the hash code of the key used when the object was created.
     */
    int getKeyHash();
}
