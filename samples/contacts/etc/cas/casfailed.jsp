<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core' %>
<%@ page import="net.sf.acegisecurity.ui.AbstractProcessingFilter" %>
<%@ page import="net.sf.acegisecurity.AuthenticationException" %>
<%-- This page will be copied into WAR's root directory if using CAS --%>

<html>
  <head>
    <title>Login to CAS failed!</title>
  </head>

  <body>
    <h1>Login to CAS failed!</h1>

      <font color="red">
        Your CAS credentials were rejected.<BR><BR>
        Reason: <%= ((AuthenticationException) session.getAttribute(AbstractProcessingFilter.ACEGI_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>
      </font>

  </body>
</html>
