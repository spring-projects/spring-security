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

package net.sf.acegisecurity.adapters.jboss;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ui.AbstractIntegrationFilter;

import java.security.Principal;

import java.util.Iterator;

import javax.naming.Context;
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

    /**
     * Not supported for this type of well-known location.
     *
     * @param request DOCUMENT ME!
     * @param authentication DOCUMENT ME!
     */
    public void commitToContainer(ServletRequest request,
        Authentication authentication) {}

    public Object extractFromContainer(ServletRequest request) {
        Subject subject = null;

        try {
            Context lc = this.getLookupContext();

            if (lc == null) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Could not obtain a Context to perform lookup");
                }

                return null;
            }

            Object result = lc.lookup("java:comp/env/security/subject");

            if (result instanceof Subject) {
                subject = (Subject) result;
            }
        } catch (NamingException ne) {
            if (logger.isWarnEnabled()) {
                logger.warn("Lookup on Subject failed "
                    + ne.getLocalizedMessage());
            }
        }

        if ((subject != null) && (subject.getPrincipals() != null)) {
            Iterator principals = subject.getPrincipals().iterator();

            while (principals.hasNext()) {
                Principal p = (Principal) principals.next();

                if (p instanceof Authentication) {
                    return p;
                }
            }
        }

        return null;
    }

    /**
     * Provided so that unit tests can override.
     *
     * @return a <code>Context</code> that can be used for lookup
     *
     * @throws NamingException DOCUMENT ME!
     */
    protected Context getLookupContext() throws NamingException {
        return new InitialContext();
    }
}
