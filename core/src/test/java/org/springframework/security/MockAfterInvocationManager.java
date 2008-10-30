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

package org.springframework.security;

import java.util.Iterator;
import java.util.List;


/**
 * If there is a configuration attribute of "AFTER_INVOCATION_MOCK", modifies the return value to null.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockAfterInvocationManager implements AfterInvocationManager {
    //~ Methods ========================================================================================================

    public Object decide(Authentication authentication, Object object, List<ConfigAttribute> config,
        Object returnedObject) throws AccessDeniedException {
        Iterator iter = config.iterator();

        while (iter.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) iter.next();

            if (this.supports(attr)) {
                return null;
            }
        }

        // this "after invocation" hasn't got a config attribute asking
        // for this mock to modify the returned object
        return returnedObject;
    }

    public boolean supports(ConfigAttribute attribute) {
        if (attribute.getAttribute().equals("AFTER_INVOCATION_MOCK")) {
            return true;
        } else {
            return false;
        }
    }

    public boolean supports(Class clazz) {
        return true;
    }
}
