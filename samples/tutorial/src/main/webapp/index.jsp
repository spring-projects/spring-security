<%@ page session="false" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<html>
  <head>
      <meta http-equiv="content-type" content="text/html; charset=UTF-8">
      <link rel="stylesheet" href="<c:url value='/static/css/tutorial.css'/>" type="text/css" />
      <title>Home Page</title>
  </head>
<body>
<div id="content">
<h1>Home Page</h1>
<p>
Anyone can view this page.
</p>
<p>
While anyone can also view the <a href="listAccounts.html">list accounts</a> page, you must be authorized to post to an Account from the list accounts page.
</p>
<p>
Your principal object is....: <%= request.getUserPrincipal() %>
</p>
<sec:authorize url='/secure/index.jsp'>
<p>
You can currently access "/secure" URLs.
</p>
</sec:authorize>
<sec:authorize url='/secure/extreme/index.jsp'>
<p>
You can currently access "/secure/extreme" URLs.
</p>
</sec:authorize>

<p>
<a href="secure/index.jsp">Secure page</a></p>
<p><a href="secure/extreme/index.jsp">Extremely secure page</a></p>
</div>
</body>
</html>
