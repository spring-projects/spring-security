package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.providers.jaas.event.JaasAuthenticationFailedEvent;
import net.sf.acegisecurity.providers.jaas.event.JaasAuthenticationSuccessEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

/**
 * @author Ray Krueger
 * @version $Id$
 */
public class JaasEventCheck implements ApplicationListener {

    JaasAuthenticationFailedEvent failedEvent;
    JaasAuthenticationSuccessEvent successEvent;

    public void onApplicationEvent(ApplicationEvent event) {

        if (event instanceof JaasAuthenticationFailedEvent)
            failedEvent = (JaasAuthenticationFailedEvent) event;

        if (event instanceof JaasAuthenticationSuccessEvent)
            successEvent = (JaasAuthenticationSuccessEvent) event;
    }
}
