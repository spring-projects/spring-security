/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Associates a given {@link Context} with the current execution thread.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextHolder {
    //~ Static fields/initializers =============================================

    private static ThreadLocal contextHolder = new ThreadLocal();

    //~ Methods ================================================================

    public static void setContext(Context context) {
        contextHolder.set(context);
    }

    public static Context getContext() {
        return (Context) contextHolder.get();
    }
}
