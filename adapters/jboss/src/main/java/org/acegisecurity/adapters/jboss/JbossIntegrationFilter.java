/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters.jboss;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.adapters.AbstractIntegrationFilter;

import java.security.Principal;

import java.util.Iterator;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import javax.security.auth.Subject;

import javax.servlet.ServletRequest;


/**
 * Populates a {@link net.sf.acegisecurity.context.SecureContext} from JBoss'
 * <code>java:comp/env/security/subject</code>.
 * 
 * <p>
 * See {@link AbstractIntegrationFilter} for further information.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JbossIntegrationFilter extends AbstractIntegrationFilter {
    //~ Methods ================================================================

    public Object extractFromContainer(ServletRequest request) {
        Subject subject = null;

        try {
            InitialContext ic = new InitialContext();
            subject = (Subject) ic.lookup("java:comp/env/security/subject");
        } catch (NamingException ne) {
            if (super.logger.isDebugEnabled()) {
                super.logger.warn("Lookup on Subject failed "
                                  + ne.getLocalizedMessage());
            }
        }

        if ((subject != null) && (subject.getPrincipals() != null)) {
            Iterator principals = subject.getPrincipals().iterator();

            while (principals.hasNext()) {
                Principal p = (Principal) principals.next();

                if (super.logger.isDebugEnabled()) {
                    super.logger.debug("Found Principal in container ("
                                       + p.getClass().getName() + ") : "
                                       + p.getName());
                }

                if (p instanceof Authentication) {
                    return p;
                }
            }
        }

        return null;
    }
}
