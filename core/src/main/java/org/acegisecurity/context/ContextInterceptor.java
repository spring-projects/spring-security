/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Ensures the {@link ContextHolder} contains a valid {@link Context}.
 * 
 * <p>
 * This interceptor works by calling {@link Context#validate()} before
 * proceeding with method invocations. It is configured in the bean context
 * with a <code>ProxyFactoryBean</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see Context#validate()
 */
public class ContextInterceptor implements MethodInterceptor {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ContextInterceptor.class);

    //~ Methods ================================================================

    public Object invoke(MethodInvocation mi) throws Throwable {
        if (ContextHolder.getContext() == null) {
            throw new ContextHolderEmptyException("ContextHolder does not contain a Context",
                                                  null);
        }

        ContextHolder.getContext().validate();

        Object ret = mi.proceed();

        return ret;
    }
}
