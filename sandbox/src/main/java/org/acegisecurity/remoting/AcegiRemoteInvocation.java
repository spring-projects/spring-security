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

package net.sf.acegisecurity.remoting;

import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.remoting.support.RemoteInvocation;

import java.lang.reflect.InvocationTargetException;


/**
 * DOCUMENT ME!
 *
 * @author James Monaghan
 * @version $Id$
 */
public class AcegiRemoteInvocation extends RemoteInvocation {
    //~ Instance fields ========================================================

    private Context context;

    //~ Constructors ===========================================================

    public AcegiRemoteInvocation(MethodInvocation methodInvocation) {
        super(methodInvocation);
        context = ContextHolder.getContext();
    }

    //~ Methods ================================================================

    public Object invoke(Object targetObject)
        throws NoSuchMethodException, IllegalAccessException, 
            InvocationTargetException {
        ContextHolder.setContext(context);

        Object result = super.invoke(targetObject);
        ContextHolder.setContext(null);

        return result;
    }
}
