package org.springframework.security.config.authentication;

import org.junit.Test;
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.authentication.concurrent.SessionRegistryImpl;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;

    private final String SESSION_CONTROLLER =
        "<b:bean id='sc' class='" + ConcurrentSessionControllerImpl.class.getName() + "'>" +
        "  <b:property name='sessionRegistry'>" +
        "      <b:bean class='" + SessionRegistryImpl.class.getName() + "'/>" +
        "  </b:property>" +
        "</b:bean>";

    @Test(expected=XmlBeanDefinitionStoreException.class)
    public void sessionControllerRefAttributeIsRejectedFor30Context() throws Exception {
        setContext(
          "<authentication-manager session-controller-ref='sc'>" +
          "    <authentication-provider>" +
          "        <user-service>" +
          "            <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
          "        </user-service>" +
          "    </authentication-provider>" +
          "</authentication-manager>" + SESSION_CONTROLLER, "3.0");
        appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);
    }

    private void setContext(String context, String version) {
        appContext = new InMemoryXmlApplicationContext(context, version, null);
    }
}
