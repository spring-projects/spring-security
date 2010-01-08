<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<html>
<body>
<h1>Secure Page</h1>
<p>
This is a protected page. You can get to me if you've been remembered,
or if you've authenticated this session.
</p>

<sec:authorize ifAllGranted="ROLE_SUPERVISOR">
	You are a supervisor! You can therefore see the <a href="extreme/index.jsp">extremely secure page</a>.<br/><br/>
</sec:authorize>

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

Saved Request: <%= session.getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY") %>


<p><a href="../">Home</a>
<p><a href="../j_spring_security_logout">Logout</a>
</body>
</html>