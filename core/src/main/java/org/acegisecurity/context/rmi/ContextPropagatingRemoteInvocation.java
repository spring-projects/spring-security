/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context.rmi;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.SecurityContext;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.remoting.support.RemoteInvocation;

import java.lang.reflect.InvocationTargetException;


/**
 * The actual <code>RemoteInvocation</code> that is passed from the client to
 * the server, which contains the contents of {@link SecurityContext}, being
 * an {@link Authentication} object.
 * 
 * <p>
 * When constructed on the client via {@link
 * net.sf.acegisecurity.context.rmi.ContextPropagatingRemoteInvocationFactory},
 * the contents of the <code>SecurityContext</code> are stored inside the
 * object. The object is then passed to the server that is processing the
 * remote invocation. Upon the server invoking the remote invocation, it will
 * retrieve the passed contents of the <code>SecurityContext</code> and set
 * them to the server-side <code>SecurityContext</code> whilst the target
 * object is invoked. When the target invocation has been completed, the
 * server-side <code>SecurityContext</code> will be reset to
 * <code>null</code>.
 * </p>
 *
 * @author James Monaghan
 * @author Ben Alex
 * @version $Id$
 */
public class ContextPropagatingRemoteInvocation extends RemoteInvocation {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ContextPropagatingRemoteInvocation.class);

    //~ Instance fields ========================================================

    private Authentication authentication;

    //~ Constructors ===========================================================

    /**
     * Constructs the object, storing the value of the client-side
     * <code>ContextHolder</code> inside the object.
     *
     * @param methodInvocation the method to invoke
     */
    public ContextPropagatingRemoteInvocation(MethodInvocation methodInvocation) {
        super(methodInvocation);
        authentication = SecurityContext.getAuthentication();

        if (logger.isDebugEnabled()) {
            logger.debug("RemoteInvocation now has authentication: "
                + authentication);
        }
    }

    //~ Methods ================================================================

    /**
     * Invoked on the server-side as described in the class JavaDocs.
     *
     * @param targetObject the target object to apply the invocation to
     *
     * @return the invocation result
     *
     * @throws NoSuchMethodException if the method name could not be resolved
     * @throws IllegalAccessException if the method could not be accessed
     * @throws InvocationTargetException if the method invocation resulted in
     *         an exception
     */
    public Object invoke(Object targetObject)
        throws NoSuchMethodException, IllegalAccessException, 
            InvocationTargetException {
        SecurityContext.setAuthentication(authentication);

        if (logger.isDebugEnabled()) {
            logger.debug("Set SecurityContext to contain: " + authentication);
        }

        Object result = super.invoke(targetObject);

        SecurityContext.setAuthentication(null);

        if (logger.isDebugEnabled()) {
            logger.debug("Set SecurityContext to null");
        }

        return result;
    }
}
