<%@ include file="/WEB-INF/jsp/include.jsp" %>

<html>
<head><title>Contacts Security Demo</title></head>
<body>
<h1>Contacts Security Demo</h1>
<p>This is a very simple application to demonstrate the Acegi Security System for Spring.
The application manages contacts, partitioned based on the user that owns them.
Users may only manage their own contacts, and only users with ROLE_SUPERVISOR
are allowed to delete their contacts. It also demonstrates how to configure
server-side secure objects so they can only be accessed via a public facade.

<P>If you deployed the contacts-container-adapter.war file, the application
automatically extracts the principal from the web container (which should be 
configured with a suitable Acegi Security System for Spring adapter). If
you're using the standard contacts.war file, the application is entirely
self-contained and you don't need to do anything special with your web
container. If you're using the contacts-cas.war file, please review the
setup in samples/contacts/etc/cas/applicationContext.xml for your CAS server
and if necessary rebuild using the Contacts application's build.xml.

<P>This application also demonstrates a public method, which is used to select
the random contact that is shown below:
<P>
<code>
<c:out value="${contact}"/>
</code>
<p>
<p><A HREF="<c:url value="secure/index.htm"/>">Manage</a>
<A HREF="<c:url value="secure/debug.jsp"/>">Debug</a>
</body>
</html>
