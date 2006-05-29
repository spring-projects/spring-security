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

package org.acegisecurity.annotation.test;

import java.util.Collection;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision: 1496 $
  *
 * @param <E> DOCUMENT ME!
 */
public class ServiceImpl<E extends Entity> implements Service<E> {
    //~ Methods ========================================================================================================

    public int countElements(Collection<E> ids) {
        return 0;
    }

    public void makeLowerCase(E input) {
        input.makeLowercase();
    }

    public void makeUpperCase(E input) {
        input.makeUppercase();
    }

    public void publicMakeLowerCase(E input) {
        input.makeUppercase();
    }
}
