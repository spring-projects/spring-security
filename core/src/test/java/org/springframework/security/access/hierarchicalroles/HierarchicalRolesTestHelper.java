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

package org.springframework.security.access.hierarchicalroles;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.apache.commons.collections.CollectionUtils;

/**
 * Test helper class for the hierarchical roles tests.
 *
 * @author Michael Mayr
 */
public abstract class HierarchicalRolesTestHelper {

    public static boolean containTheSameGrantedAuthorities(List<GrantedAuthority> authorities1, List<GrantedAuthority> authorities2) {
        if (authorities1 == null && authorities2 == null) {
            return true;
        }

        if (authorities1 == null || authorities2 == null) {
            return false;
        }
        return CollectionUtils.isEqualCollection(authorities1, authorities2);
    }

}
