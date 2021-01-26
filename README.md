@ -0,0 +1,2 @@
# horse-jwt
Middleware to generate jwt token and verify signature on HORSE servers

Sample Horse server validate basic authentication:

```delphi
uses Horse, Horse.BasicAuthentication, System.SysUtils;

begin
  THorse.Use(HorseBasicAuthentication(
    function(const AUsername, APassword: string): Boolean
    begin
      Result := AUsername.Equals('user') and APassword.Equals('password');
    end));

  THorse.Get('/ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('pong');
    end);

  THorse.Listen(9000);
end.
```
