<html>
  <head>
    <title>Spring Security Login</title>
  </head>

  <body onload="document.f.username.focus();">
    <h1>Spring Security Login (Freemarker)</h1>

    <form name="f" action="login" method="POST">
      <table>
        <tr><td>User:</td><td><input type='text' name='username' value=''/></td></tr>
        <tr><td>Password:</td><td><input type='password' name='password' value=''/></td></tr>
        <tr><td><input type="checkbox" name="remember-me"/></td><td>Don't ask for my password for two weeks</td></tr>

        <tr><td colspan='2'><input name="submit" type="submit"></td></tr>
        <tr><td colspan='2'><input name="reset" type="reset"></td></tr>
      </table>

    </form>

  </body>
</html>
