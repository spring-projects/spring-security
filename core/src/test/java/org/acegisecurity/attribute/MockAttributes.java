/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.attribute;

import org.springframework.metadata.Attributes;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import java.util.Collection;


/**
 * DOCUMENT ME!
 *
 * @author CameronBraid
 */
public class MockAttributes implements Attributes {
    //~ Methods ================================================================

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.Class, java.lang.Class)
     */
    public Collection getAttributes(Class arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.Class)
     */
    public Collection getAttributes(Class arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Field, java.lang.Class)
     */
    public Collection getAttributes(Field arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Field)
     */
    public Collection getAttributes(Field arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Method, java.lang.Class)
     */
    public Collection getAttributes(Method arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Method)
     */
    public Collection getAttributes(Method arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
