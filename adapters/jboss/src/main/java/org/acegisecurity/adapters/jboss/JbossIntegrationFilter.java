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
                        + p.getClass().getName() + ") : " + p.getName());
                }

                if (p instanceof Authentication) {
                    return p;
                }
            }
        }

        return null;
    }
}
