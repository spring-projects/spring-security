/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Basic concrete implementation of a {@link Context}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextImpl implements Context {
    //~ Methods ================================================================

    public void validate() throws ContextInvalidException {
        // Nothing to validate.
    }
}
