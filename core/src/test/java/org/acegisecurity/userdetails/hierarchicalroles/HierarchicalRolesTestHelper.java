/*
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

package org.acegisecurity.userdetails.hierarchicalroles;

import java.util.ArrayList;
import java.util.List;

import org.acegisecurity.GrantedAuthority;
import org.apache.commons.collections.CollectionUtils;

/**
 * Test helper class for the hierarchical roles tests.
 * 
 * @author Michael Mayr
 */
public abstract class HierarchicalRolesTestHelper {

    public static boolean containTheSameGrantedAuthorities(GrantedAuthority[] authorities1, GrantedAuthority[] authorities2) {
        if (authorities1 == null && authorities2 == null) {
            return true;
        } else if (authorities1 == null || authorities2 == null) {
            return false;
        }
        List authoritiesList1 = new ArrayList();
        CollectionUtils.addAll(authoritiesList1, authorities1);
        List authoritiesList2 = new ArrayList();
        CollectionUtils.addAll(authoritiesList2, authorities2);
        return CollectionUtils.isEqualCollection(authoritiesList1, authoritiesList2);
    }
    
}