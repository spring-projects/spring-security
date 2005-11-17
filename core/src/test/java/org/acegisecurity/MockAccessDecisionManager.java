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

package org.acegisecurity;

import java.util.Iterator;


/**
 * Grants access if the user holds any of the authorities listed in the
 * configuration attributes starting with "MOCK_".
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockAccessDecisionManager implements AccessDecisionManager {
    //~ Methods ================================================================

    public void decide(Authentication authentication, Object object,
        ConfigAttributeDefinition config) throws AccessDeniedException {
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) iter.next();

            if (this.supports(attr)) {
                for (int i = 0; i < authentication.getAuthorities().length;
                    i++) {
                    if (attr.getAttribute().equals(authentication
                            .getAuthorities()[i].getAuthority())) {
                        return;
                    }
                }
            }
        }

        throw new AccessDeniedException("Didn't hold required authority");
    }

    public boolean supports(ConfigAttribute attribute) {
        if (attribute.getAttribute().startsWith("MOCK_")) {
            return true;
        } else {
            return false;
        }
    }

    public boolean supports(Class clazz) {
        return true;
    }
}
