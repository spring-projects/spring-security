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

package net.sf.acegisecurity.integrationtests.web;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebLink;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

import junit.framework.TestCase;

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.PropertiesBeanDefinitionReader;

import org.springframework.remoting.RemoteAccessException;

import sample.contact.ContactManager;

import java.net.URL;

import java.util.Properties;


/**
 * Tests the Contacts sample application from a HTTP user's perspective.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractContactsTests extends TestCase {
    //~ Methods ================================================================

    /**
     * Returns the base URL where the Contacts application can be found, such
     * as <code>http://localhost:8080/contacts</code>. There should be no
     * ending slash.
     *
     * @return DOCUMENT ME!
     */
    public abstract String getBaseUrl();

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractContactsTests.class);
    }

    public void testHelloPageAccessible() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse response = conversation.getResponse(request);
        assertEquals("Contacts Security Demo", response.getTitle());
        assertEquals(2, response.getLinks().length); // debug and manage links
        assertTrue(response.getText().lastIndexOf("sample.contact.Contact@") != -1);
    }

    public void testHessianFailsWithIncorrectCredentials() {
        String PREFIX = "beans.";
        DefaultListableBeanFactory lbf = new DefaultListableBeanFactory();
        Properties p = new Properties();
        p.setProperty(PREFIX + "hessianProxy.class",
            "org.springframework.remoting.caucho.HessianProxyFactoryBean");
        p.setProperty(PREFIX + "hessianProxy.serviceInterface",
            "sample.contact.ContactManager");
        p.setProperty(PREFIX + "hessianProxy.serviceUrl",
            getBaseUrl() + "/caucho/ContactManager-hessian");
        p.setProperty(PREFIX + "hessianProxy.username", "marissa");
        p.setProperty(PREFIX + "hessianProxy.password", "WRONG_PASSWORD");

        (new PropertiesBeanDefinitionReader(lbf)).registerBeanDefinitions(p,
            PREFIX);

        ContactManager contactManager = (ContactManager) lbf.getBean(
                "hessianProxy");

        try {
            contactManager.getRandomContact();
            fail("Should have thrown RemoteAccessException");
        } catch (RemoteAccessException exception) {
            assertTrue(true);
        }
    }

    public void testHessianOperational() {
        String PREFIX = "beans.";
        DefaultListableBeanFactory lbf = new DefaultListableBeanFactory();
        Properties p = new Properties();
        p.setProperty(PREFIX + "hessianProxy.class",
            "org.springframework.remoting.caucho.HessianProxyFactoryBean");
        p.setProperty(PREFIX + "hessianProxy.serviceInterface",
            "sample.contact.ContactManager");
        p.setProperty(PREFIX + "hessianProxy.serviceUrl",
            getBaseUrl() + "/caucho/ContactManager-hessian");
        p.setProperty(PREFIX + "hessianProxy.username", "marissa");
        p.setProperty(PREFIX + "hessianProxy.password", "koala");

        (new PropertiesBeanDefinitionReader(lbf)).registerBeanDefinitions(p,
            PREFIX);

        ContactManager contactManager = (ContactManager) lbf.getBean(
                "hessianProxy");
        assertTrue(contactManager.getRandomContact() != null);
    }

    public void testLoginNameCaseSensitive() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse helloPage = conversation.getResponse(request);
        WebLink debugLink = helloPage.getLinkWith("Debug");
        WebResponse loginPage = debugLink.click();
        assertEquals(1, loginPage.getForms()[0].getSubmitButtons().length);

        WebForm loginForm = loginPage.getForms()[0];
        loginPage = null;

        loginForm.setParameter("j_username", "mArIsSA");
        loginForm.setParameter("j_password", "koala");

        WebResponse loginOutcome = conversation.getResponse(loginForm
                .getRequest("submit"));

        assertTrue(loginOutcome.getText().lastIndexOf("SUCCESS!") != -1);
    }

    public void testLoginPasswordCaseSensitive() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse helloPage = conversation.getResponse(request);
        WebLink debugLink = helloPage.getLinkWith("Debug");
        WebResponse loginPage = debugLink.click();
        assertEquals(1, loginPage.getForms()[0].getSubmitButtons().length);

        WebForm loginForm = loginPage.getForms()[0];
        loginPage = null;

        loginForm.setParameter("j_username", "dianne");
        loginForm.setParameter("j_password", "EmU");

        WebResponse loginOutcome = conversation.getResponse(loginForm
                .getRequest("submit"));

        assertEquals("Login", loginOutcome.getTitle());
    }

    public void testLoginSuccess() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse helloPage = conversation.getResponse(request);
        WebLink debugLink = helloPage.getLinkWith("Debug");
        WebResponse loginPage = debugLink.click();
        assertEquals(1, loginPage.getForms()[0].getSubmitButtons().length);

        WebForm loginForm = loginPage.getForms()[0];
        loginPage = null;

        loginForm.setParameter("j_username", "marissa");
        loginForm.setParameter("j_password", "koala");

        WebResponse loginOutcome = conversation.getResponse(loginForm
                .getRequest("submit"));

        assertTrue(loginOutcome.getText().lastIndexOf("SUCCESS!") != -1);
    }

    public void testLoginUnknownUsername() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse helloPage = conversation.getResponse(request);
        WebLink debugLink = helloPage.getLinkWith("Debug");
        WebResponse loginPage = debugLink.click();
        assertEquals(1, loginPage.getForms()[0].getSubmitButtons().length);

        WebForm loginForm = loginPage.getForms()[0];
        loginPage = null;

        loginForm.setParameter("j_username", "angella");
        loginForm.setParameter("j_password", "echidna");

        WebResponse loginOutcome = conversation.getResponse(loginForm
                .getRequest("submit"));

        assertEquals("Login", loginOutcome.getTitle());
    }

    public void testSessionAsMarissa() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse helloPage = conversation.getResponse(request);
        WebLink manageLink = helloPage.getLinkWith("Manage");
        WebResponse loginPage = manageLink.click();
        manageLink = null;
        assertEquals(1, loginPage.getForms()[0].getSubmitButtons().length);

        WebForm loginForm = loginPage.getForms()[0];
        loginPage = null;

        loginForm.setParameter("j_username", "marissa");
        loginForm.setParameter("j_password", "koala");

        WebResponse loginOutcome = conversation.getResponse(loginForm
                .getRequest("submit"));

        assertEquals("Your Contacts", loginOutcome.getTitle());
        assertTrue(loginOutcome.getText().lastIndexOf("marissa's Contacts") != -1);
        assertEquals(4, loginOutcome.getTables()[0].getRowCount()); // 3 contacts + header
        assertEquals(5, loginOutcome.getLinks().length); // 3 contacts + add + logoff

        WebLink addLink = loginOutcome.getLinkWith("Add");
        loginOutcome = null;

        WebResponse addPage = addLink.click();
        WebForm addForm = addPage.getForms()[0];
        addPage = null;

        addForm.setParameter("name", "");
        addForm.setParameter("email", "");

        WebResponse addOutcomeFail = conversation.getResponse(addForm
                .getRequest("execute"));

        assertEquals(new URL(getBaseUrl() + "/secure/add.htm"),
            addOutcomeFail.getURL());
        assertTrue(addOutcomeFail.getText().lastIndexOf("Please fix all errors!") != -1);
        addOutcomeFail = null;

        addForm.setParameter("name", "somebody");
        addForm.setParameter("email", "them@somewhere.com");

        WebResponse addOutcomeSuccess = conversation.getResponse(addForm
                .getRequest("execute"));

        assertEquals("Your Contacts", addOutcomeSuccess.getTitle());
        assertTrue(addOutcomeSuccess.getText().lastIndexOf("marissa's Contacts") != -1);
        assertEquals(5, addOutcomeSuccess.getTables()[0].getRowCount()); // 4 contacts + header
        assertEquals(6, addOutcomeSuccess.getLinks().length); // 4 contacts + add + logoff

        WebLink logout = addOutcomeSuccess.getLinkWith("Logoff");
        addOutcomeSuccess = null;

        WebResponse loggedOut = logout.click();
        assertEquals("Contacts Security Demo", loggedOut.getTitle());

        WebLink debugLink = loggedOut.getLinkWith("Debug");
        loggedOut = null;

        WebResponse loginAgainPage = debugLink.click();
        assertEquals("Login", loginAgainPage.getTitle());
    }

    public void testSessionAsScott() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(getBaseUrl());

        WebResponse helloPage = conversation.getResponse(request);
        WebLink manageLink = helloPage.getLinkWith("Manage");
        WebResponse loginPage = manageLink.click();
        manageLink = null;
        assertEquals(1, loginPage.getForms()[0].getSubmitButtons().length);

        WebForm loginForm = loginPage.getForms()[0];
        loginPage = null;

        loginForm.setParameter("j_username", "scott");
        loginForm.setParameter("j_password", "wombat");

        WebResponse loginOutcome = conversation.getResponse(loginForm
                .getRequest("submit"));

        assertEquals("Your Contacts", loginOutcome.getTitle());
        assertTrue(loginOutcome.getText().lastIndexOf("scott's Contacts") != -1);
        assertEquals(3, loginOutcome.getTables()[0].getRowCount()); // 2 contacts + header
        assertEquals(2, loginOutcome.getLinks().length); // add + logoff only

        WebLink addLink = loginOutcome.getLinkWith("Add");
        loginOutcome = null;

        WebResponse addPage = addLink.click();
        WebForm addForm = addPage.getForms()[0];
        addPage = null;

        addForm.setParameter("name", "somebody");
        addForm.setParameter("email", "them@somewhere.com");

        WebResponse addOutcomeSuccess = conversation.getResponse(addForm
                .getRequest("execute"));

        assertEquals("Your Contacts", addOutcomeSuccess.getTitle());
        assertTrue(addOutcomeSuccess.getText().lastIndexOf("scott's Contacts") != -1);
        assertEquals(4, addOutcomeSuccess.getTables()[0].getRowCount()); // 3 contacts + header
        assertEquals(2, addOutcomeSuccess.getLinks().length); // add + logoff only

        WebLink logout = addOutcomeSuccess.getLinkWith("Logoff");
        addOutcomeSuccess = null;

        WebResponse loggedOut = logout.click();
        assertEquals("Contacts Security Demo", loggedOut.getTitle());

        WebLink debugLink = loggedOut.getLinkWith("Debug");
        loggedOut = null;

        WebResponse loginAgainPage = debugLink.click();
        assertEquals("Login", loginAgainPage.getTitle());
    }
}
