/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.aopalliance.intercept.MethodInvocation;

import java.util.Iterator;


/**
 * Implemented by classes that store {@link ConfigAttributeDefinition}s and can
 * identify the appropriate <code>ConfigAttributeDefinition</code> that
 * applies for the current method call.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface MethodDefinitionSource {
    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @param invocation the method being called
     *
     * @return the <code>ConfigAttributeDefinition</code> that applies to the
     *         passed method call
     */
    public ConfigAttributeDefinition getAttributes(MethodInvocation invocation);

    /**
     * If available, all of the <code>ConfigAttributeDefinition</code>s defined
     * by the implementing class.
     *
     * @return an iterator over all the <code>ConfigAttributeDefinition</code>s
     *         or <code>null</code> if unsupported
     */
    public Iterator getConfigAttributeDefinitions();
}
