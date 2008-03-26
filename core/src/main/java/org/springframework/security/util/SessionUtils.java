package org.springframework.security.util;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.concurrent.SessionRegistry;
import org.springframework.security.concurrent.SessionRegistryUtils;
import org.springframework.security.context.SecurityContextHolder;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public final class SessionUtils {
    private final static Log logger = LogFactory.getLog(SessionUtils.class);
    
    SessionUtils() {}

    public static void startNewSessionIfRequired(HttpServletRequest request, boolean migrateAttributes, 
            SessionRegistry sessionRegistry) {
        
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }
        
        String originalSessionId = session.getId();

        if (logger.isDebugEnabled()) {
            logger.debug("Invalidating session with Id '" + originalSessionId +"' " + (migrateAttributes ? "and" : "without") +  " migrating attributes.");
        }        

        HashMap attributesToMigrate = null;
        
        if (migrateAttributes) {
            attributesToMigrate = new HashMap();

            Enumeration enumer = session.getAttributeNames();

            while (enumer.hasMoreElements()) {
                String key = (String) enumer.nextElement();
                attributesToMigrate.put(key, session.getAttribute(key));
            }
        }
        
        session.invalidate();
        session = request.getSession(true); // we now have a new session

        if (logger.isDebugEnabled()) {
            logger.debug("Started new session: " + session.getId());
        }
        
        if (attributesToMigrate != null) {
            Iterator iter = attributesToMigrate.entrySet().iterator();

            while (iter.hasNext()) {
                Map.Entry entry = (Map.Entry) iter.next();
                session.setAttribute((String) entry.getKey(), entry.getValue());
            }
        }
        
        if (sessionRegistry != null) {
            sessionRegistry.removeSessionInformation(originalSessionId);
            Object principal = SessionRegistryUtils.obtainPrincipalFromAuthentication(
                    SecurityContextHolder.getContext().getAuthentication());
            
            sessionRegistry.registerNewSession(session.getId(), principal);
        } 
    }
}
