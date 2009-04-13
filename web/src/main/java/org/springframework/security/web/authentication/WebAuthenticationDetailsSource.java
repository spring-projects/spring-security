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

package org.springframework.security.web.authentication;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import javax.servlet.http.HttpServletRequest;


/**
 * Implementation of {@link AuthenticationDetailsSource} which builds the details object from
 * an <tt>HttpServletRequest</tt> object.
 * <p>
 * By default will create an instance of <code>WebAuthenticationDetails</code>. Any object that accepts a
 * <code>HttpServletRequest</code> as its sole constructor can be used instead of this default.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebAuthenticationDetailsSource implements AuthenticationDetailsSource {
    //~ Instance fields ================================================================================================

    private Class<?> clazz = WebAuthenticationDetails.class;

    //~ Methods ========================================================================================================

    /**
     * @param context the <tt>HttpServletRequest</tt> object.
     */
    public Object buildDetails(Object context) {
        Assert.isInstanceOf(HttpServletRequest.class, context);
        try {
            Constructor<?> constructor = clazz.getConstructor(HttpServletRequest.class);

            return constructor.newInstance(context);
        } catch (NoSuchMethodException ex) {
            ReflectionUtils.handleReflectionException(ex);
        } catch (InvocationTargetException ex) {
            ReflectionUtils.handleReflectionException(ex);
        } catch (InstantiationException ex) {
            ReflectionUtils.handleReflectionException(ex);
        } catch (IllegalAccessException ex) {
            ReflectionUtils.handleReflectionException(ex);
        }

        return null;
    }

    public void setClazz(Class<?> clazz) {
        Assert.notNull(clazz, "Class required");
        this.clazz = clazz;
    }
}
