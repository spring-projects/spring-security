/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.integrationtests.web;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebLink;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

import junit.framework.TestCase;

import java.net.URL;


/**
 * Tests the Contacts sample application and container integration from a HTTP
 * user's perspective.
 * 
 * <P>
 * NB: Assumes a default container configuration concerning the usernames and
 * passwords in <code>acegisecurity.xml</code>. Also assumes default
 * configuration in terms of password and username case sensitivity.
 * Importantly, the Contacts application is expected to be started "clean", in
 * that all default contacts data is present, without any additional data.
 * This means it is necessary to restart the Contacts application between
 * successive test runs.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContactsWarTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ContactsWarTests.class);
    }

    public void testHelloPageAccessible() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

        WebResponse response = conversation.getResponse(request);
        assertEquals("Contacts Security Demo", response.getTitle());
        assertEquals(2, response.getLinks().length); // debug and manage links
        assertTrue(response.getText().lastIndexOf("sample.contact.Contact@") != -1);
    }

    public void testLoginNameCaseSensitive() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

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

        assertTrue(loginOutcome.getText().lastIndexOf("SUCCESS! Your container adapter appears to be properly configured!") != -1);
    }

    public void testLoginPasswordCaseSensitive() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

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
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

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

        assertTrue(loginOutcome.getText().lastIndexOf("SUCCESS! Your container adapter appears to be properly configured!") != -1);
    }

    public void testLoginUnknownUsername() throws Exception {
        WebConversation conversation = new WebConversation();
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

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
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

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

        assertEquals(new URL("http://localhost:8080/contacts/secure/add.htm"),
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
        WebRequest request = new GetMethodWebRequest(
                "http://localhost:8080/contacts");

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
