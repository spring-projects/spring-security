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

import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

/**
 * This class wraps Acegi's UserDetailsService in a way that its loadUserByUsername() 
 * method returns wrapped UserDetails that return all hierachically reachable authorities 
 * instead of only the directly assigned authorities.
 * 
 * @author Michael Mayr
 */
public class UserDetailsServiceWrapper implements UserDetailsService {
    
    private UserDetailsService userDetailsService = null;
    
    private RoleHierarchy roleHierarchy = null;

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }
    
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        // wrapped UserDetailsService might throw UsernameNotFoundException or DataAccessException which will then bubble up
        return new UserDetailsWrapper(userDetails, roleHierarchy);
    }
    
    public UserDetailsService getWrappedUserDetailsService() {
        return userDetailsService;
    }

}