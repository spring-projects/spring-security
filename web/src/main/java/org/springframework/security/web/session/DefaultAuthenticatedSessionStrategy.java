package org.springframework.security.web.session;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * The default implementation of {@link AuthenticatedSessionStrategy}.
 * <p>
 * Creates a new session for the newly authenticated user if they already have a session (as a defence against
 * session-fixation protection attacks), and copies their
 * session attributes across to the new session (can be disabled by setting <tt>migrateSessionAttributes</tt> to
 * <tt>false</tt>).
 * <p>
 * This approach will only be effective if your servlet container always assigns a new session Id when a session is
 * invalidated and a new session created by calling {@link HttpServletRequest#getSession()}.
 * <p>
 * If concurrent session control is in use, then a <tt>SessionRegistry</tt> must be injected.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultAuthenticatedSessionStrategy implements AuthenticatedSessionStrategy {
    protected final Log logger = LogFactory.getLog(this.getClass());

    /**
     * Indicates that the session attributes of an existing session
     * should be migrated to the new session. Defaults to <code>true</code>.
     */
    private boolean migrateSessionAttributes = true;

    /**
     * In the case where the attributes will not be migrated, this field allows a list of named attributes
     * which should <em>not</em> be discarded.
     */
    private List<String> retainedAttributes = Arrays.asList(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);

    /**
     * If set to <tt>true</tt>, a session will always be created, even if one didn't exist at the start of the request.
     * Defaults to <tt>false</tt>.
     */
    private boolean alwaysCreateSession;

    /**
     * Called when a user is newly authenticated.
     * <p>
     * If a session already exists, a new session will be created, the session attributes copied to it (if
     * <tt>migrateSessionAttributes</tt> is set) and the sessionRegistry updated with the new session information.
     * <p>
     * If there is no session, no action is taken unless the <tt>alwaysCreateSession</tt> property is set, in which
     * case a session will be created if one doesn't already exist.
     */
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        boolean hadSessionAlready = request.getSession(false) != null;

        if (!hadSessionAlready && !alwaysCreateSession) {
            // Session fixation isn't a problem if there's no session

            return;
        }

        // Create new session if necessary
        HttpSession session = request.getSession();

        if (hadSessionAlready) {
            // We need to migrate to a new session
            String originalSessionId = session.getId();

            if (logger.isDebugEnabled()) {
                logger.debug("Invalidating session with Id '" + originalSessionId +"' " + (migrateSessionAttributes ?
                        "and" : "without") +  " migrating attributes.");
            }

            HashMap<String, Object> attributesToMigrate = createMigratedAttributeMap(session);

            session.invalidate();
            session = request.getSession(true); // we now have a new session

            if (logger.isDebugEnabled()) {
                logger.debug("Started new session: " + session.getId());
            }

            if (originalSessionId.equals(session.getId())) {
                logger.warn("Your servlet container did not change the session ID when a new session was created. You will" +
                        " not be adequately protected against session-fixation attacks");
            }

            // Copy attributes to new session
            if (attributesToMigrate != null) {
                for (Map.Entry<String, Object> entry : attributesToMigrate.entrySet()) {
                    session.setAttribute(entry.getKey(), entry.getValue());
                }
            }
        }
    }

    /**
     * Called when the session has been changed and the old attributes have been migrated to the new session.
     * Only called if a session existed to start with. Allows subclasses to plug in additional behaviour.
     *
     * @param originalSessionId the original session identifier
     * @param newSession the newly created session
     * @param auth the token for the newly authenticated principal
     */
    protected void onSessionChange(String originalSessionId, HttpSession newSession, Authentication auth) {
    }

    @SuppressWarnings("unchecked")
    private HashMap<String, Object> createMigratedAttributeMap(HttpSession session) {
        HashMap<String, Object> attributesToMigrate = null;

        if (migrateSessionAttributes) {
            attributesToMigrate = new HashMap<String, Object>();

            Enumeration enumer = session.getAttributeNames();

            while (enumer.hasMoreElements()) {
                String key = (String) enumer.nextElement();
                attributesToMigrate.put(key, session.getAttribute(key));
            }
        } else {
            // Only retain the attributes which have been specified in the retainAttributes list
            if (!retainedAttributes.isEmpty()) {
                attributesToMigrate = new HashMap<String, Object>();
                for (String name : retainedAttributes) {
                    Object value = session.getAttribute(name);

                    if (value != null) {
                        attributesToMigrate.put(name, value);
                    }
                }
            }
        }
        return attributesToMigrate;
    }

    public void setMigrateSessionAttributes(boolean migrateSessionAttributes) {
        this.migrateSessionAttributes = migrateSessionAttributes;
    }

    public void setRetainedAttributes(List<String> retainedAttributes) {
        this.retainedAttributes = retainedAttributes;
    }

    public void setAlwaysCreateSession(boolean alwaysCreateSession) {
        this.alwaysCreateSession = alwaysCreateSession;
    }
}
