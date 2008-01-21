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

package org.springframework.security.providers.dao.salt;

import org.springframework.security.AuthenticationServiceException;

import org.springframework.security.providers.dao.SaltSource;

import org.springframework.security.userdetails.UserDetails;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.BeanUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.Assert;

import java.lang.reflect.Method;
import java.beans.PropertyDescriptor;


/**
 * Obtains a salt from a specified property of the {@link org.springframework.security.userdetails.User} object.
 * <p>
 * This allows you to subclass <code>User</code> and provide an additional bean getter for a salt. You should use a
 * synthetic value that does not change, such as a database primary key.  Do not use <code>username</code> if it is
 * likely to change.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ReflectionSaltSource implements SaltSource, InitializingBean {
    //~ Instance fields ================================================================================================

    private String userPropertyToUse;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.hasText(userPropertyToUse, "A userPropertyToUse must be set");
    }

    /**
     * Performs reflection on the passed <code>User</code> to obtain the salt.
     * <p>
     * The property identified by <code>userPropertyToUse</code> must be available from the passed <code>User</code>
     * object. If it is not available, an {@link AuthenticationServiceException} will be thrown.
     *
     * @param user which contains the method identified by <code>userPropertyToUse</code>
     *
     * @return the result of invoking <tt>user.userPropertyToUse()</tt>, or if the method doesn't exist,
     * <tt>user.getUserPropertyToUse()</tt>.
     *
     * @throws AuthenticationServiceException if reflection fails
     */
    public Object getSalt(UserDetails user) {
        Method saltMethod = findSaltMethod(user);

        try {
            return saltMethod.invoke(user, new Object[] {});
        } catch (Exception exception) {
            throw new AuthenticationServiceException(exception.getMessage(), exception);
        }
    }

    private Method findSaltMethod(UserDetails user) {
        Method saltMethod = ReflectionUtils.findMethod(user.getClass(), userPropertyToUse, new Class[0]);

        if (saltMethod == null) {
            PropertyDescriptor pd = BeanUtils.getPropertyDescriptor(user.getClass(), userPropertyToUse);

            if (pd != null) {
                saltMethod = pd.getReadMethod();
            }

            if (saltMethod == null) {
                throw new AuthenticationServiceException("Unable to find salt method on user Object. Does the class '" +
                    user.getClass().getName() + "' have a method or getter named '" + userPropertyToUse + "' ?");
            }
        }

        return saltMethod;
    }

    protected String getUserPropertyToUse() {
        return userPropertyToUse;
    }

    /**
     * The method name to call to obtain the salt. Can be either a method name or a bean property name. If your
     * <code>UserDetails</code> contains a <code>UserDetails.getSalt()</code> method, you should set this property to
     * "getSalt" or "salt".
     *
     * @param userPropertyToUse the name of the <b>getter</b> to call to obtain the salt from the
     *        <code>UserDetails</code>
     */
    public void setUserPropertyToUse(String userPropertyToUse) {
        this.userPropertyToUse = userPropertyToUse;
    }

    public String toString() {
        return "ReflectionSaltSource[ userPropertyToUse='" + userPropertyToUse + "'; ]";
    }
}
