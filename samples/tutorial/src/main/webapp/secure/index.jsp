<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
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

<h1>Secure Page</h1>
<p>
This is a protected page. You can get to me if you've been remembered,
or if you've authenticated this session.
</p>
<p>
<sec:authorize access="hasRole('ROLE_SUPERVISOR')">
    You are a supervisor! You can therefore see the <a href="extreme/index.jsp">extremely secure page</a>.<br/><br/>
</sec:authorize>
</p>
<h3>Properties obtained using &lt;sec:authentication /&gt; tag</h3>
<table border="1">
<tr><th>Tag</th><th>Value</th></tr>
<tr>
<td>&lt;sec:authentication property='name' /&gt;</td><td><sec:authentication property="name"/></td>
</tr>
<tr>
<td>&lt;sec:authentication property='principal.username' /&gt;</td><td><sec:authentication property="principal.username"/></td>
</tr>
<tr>
<td>&lt;sec:authentication property='principal.enabled' /&gt;</td><td><sec:authentication property="principal.enabled"/></td>
</tr>
<tr>
<td>&lt;sec:authentication property='principal.accountNonLocked' /&gt;</td><td><sec:authentication property="principal.accountNonLocked"/></td>
</tr>
</table>


<p><a href="../">Home</a></p>
<p><a href="../j_spring_security_logout">Logout</a></p>
</div>
</body>
</html>
