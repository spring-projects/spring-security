<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core' %>

<%@ page import="org.acegisecurity.context.SecurityContextHolder" %>
<%@ page import="org.acegisecurity.Authentication" %>
<%@ page import="org.acegisecurity.ui.AbstractProcessingFilter" %>
<%@ page import="org.acegisecurity.ui.webapp.AuthenticationProcessingFilter" %>
<%@ page import="org.acegisecurity.AuthenticationException" %>

<html>
  <head>
    <title>Exit User</title>
  </head>

  <body>
    <h1>Exit User</h1>

    <c:if test="${not empty param.login_error}">
      <font color="red">
        Your 'Exit User' attempt was not successful, try again.<BR><BR>
        Reason: <%= ((AuthenticationException) session.getAttribute(AbstractProcessingFilter.ACEGI_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>
      </font>
    </c:if>

    <form action="<c:url value='j_acegi_exit_user'/>" method="POST">
      <table>
        <tr><td>Current User:</td><td>

         <%
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth != null) { %>

			<%= auth.getPrincipal().toString() %>

		<% } %>



         </td></tr>
        <tr><td colspan='2'><input name="exit" type="submit" value="Exit"></td></tr>
      </table>

    </form>

  </body>
</html>
