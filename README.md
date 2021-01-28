@ -0,0 +1,2 @@
# horse-jwt
Middleware to generate jwt token and verify signature on HORSE servers

Sample Horse server validate basic authentication:

```delphi
uses Horse, Horse.JWT, System.SysUtils;

begin
  THorse
    .Use(JWT.Login)
    .Get('/public', ...)
    .Get('/private', CallbackPrivate, JWT.Guard);
    
  THorse.Listen(80);
end.
```


