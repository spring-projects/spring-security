<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@taglib prefix="c" uri="https://java.sun.com/jsp/jstl/core" %>

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

<sec:authorize access="hasAuthority('supervisor')">
You have authority "supervisor" (this text is surrounded by &lt;sec:authorize&gt; tags).
</sec:authorize>

<p><a href="../../">Home</a></p>

<form action="../../logout" method="post">
	<sec:csrfInput />
	<input type="submit" value="Logout"/>
</form>
</div>
</body>
</html>
