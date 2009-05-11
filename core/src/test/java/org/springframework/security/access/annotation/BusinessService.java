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

package org.springframework.security.access.annotation;

import java.util.List;

import javax.annotation.security.RolesAllowed;
import javax.annotation.security.PermitAll;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * @version $Id$
 */
@Secured({"ROLE_USER"})
@PermitAll
public interface BusinessService {
    //~ Methods ========================================================================================================

    @Secured({"ROLE_ADMIN"})
    @RolesAllowed({"ROLE_ADMIN"})
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public void someAdminMethod();

    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    @RolesAllowed({"ROLE_USER", "ROLE_ADMIN"})
    public void someUserAndAdminMethod();

    @Secured({"ROLE_USER"})
    @RolesAllowed({"ROLE_USER"})
    public void someUserMethod1();

    @Secured({"ROLE_USER"})
    @RolesAllowed({"ROLE_USER"})
    public void someUserMethod2();

    public int someOther(String s);

    public int someOther(int input);

    public List<?> methodReturningAList(List<?> someList);

    public Object[] methodReturningAnArray(Object[] someArray);

    public List<?> methodReturningAList(String userName, String extraParam);

}
