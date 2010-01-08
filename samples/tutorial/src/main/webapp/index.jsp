<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<html>
<body>
<h1>Home Page</h1>
<p>
Anyone can view this page.
</p>
<p>
If you're logged in, you can <a href="listAccounts.html">list accounts</a>.
</p>
<p>
Your principal object is....: <%= request.getUserPrincipal() %>
</p>
<p>
<sec:authorize url='/secure/index.jsp'>You can currently access "/secure" URLs.</sec:authorize>
</p>
<p>
<sec:authorize url='/secure/extreme/index.jsp'>You can currently access "/secure/extreme" URLs.</sec:authorize>
</p>

<p>
<a href="secure/index.jsp">Secure page</a></p>
<p><a href="secure/extreme/index.jsp">Extremely secure page</a></p>
</body>
</html>
