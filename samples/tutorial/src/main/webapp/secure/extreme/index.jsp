<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<html>
  <head>
      <meta http-equiv="content-type" content="text/html; charset=UTF-8">
      <link rel="stylesheet" href="<c:url value='/static/css/tutorial.css'/>" type="text/css" />
      <title>Secure Page</title>
  </head>
<body>
<div id="content">
<h1>VERY Secure Page</h1>
This is a protected page. You can only see me if you are a supervisor.

<authz:authorize access="hasRole('ROLE_SUPERVISOR')">
   You have "ROLE_SUPERVISOR" (this text is surrounded by &lt;authz:authorize&gt; tags).
</authz:authorize>

<p><a href="../../">Home</a></p>
<p><a href="../../j_spring_security_logout">Logout</a></p>
</div>
</body>
</html>
