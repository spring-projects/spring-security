<html>
<body>
<h1>Home Page</h1>
Anyone can view this page.<br><br>

If you're logged in, you can <a href="listAccounts.html">list accounts</a>.<br><br>


Your principal object is....: <%= request.getUserPrincipal() %><br><br>

<p><a href="secure/index.jsp">Secure page</a>
<p><a href="secure/extreme/index.jsp">Extremely secure page</a>
</body>
</html>