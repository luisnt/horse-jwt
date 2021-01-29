
# horse-jwt
Middleware to generate jwt token and verify signature on HORSE servers

Sample Horse server validate basic authentication:

```delphi
uses System.SysUtils

  , Horse
  , Horse.JWT 
;

begin
  THorse
    .Get('/', procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc) begin
      Res.Send('Página pública Home');
    end)
    .Get('/sobre', procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc) begin
      Res.Send('Página pública Sobre');
    end)
    .Post('/login', JWT.Login(ProcAuth))
    .Get('/privada', CallbackPrivada, JWT.Guard); // Middleware JWT.Guard Valída o Token
    
  THorse.Listen(80);
end.
```

```delphi
function FuncAuth(const aUserName: string; const aPassword: string): string;
var
  LToken: string;
begin 
   if samestr(aUserName, 'root') and samestr(aPassword, 'toor') then
   begin
      JWT.Header.Algorithm(TJwtAlgorithm.HS256);
      JWT.Payload
           .jti(1)                           { jti - Jwt ID          - Jwt ID ( ID ) }
           .iss('Luis Nt')                   { iss - Issuer          - Emissor ( Emissor ) }
           .sub('Chave de acesso')           { sub - Subject         - Assunto }
           .aud('192.168.0.77')              { aud - Audience        - Audiência ( Remote IP ) }
           .iat('2021-01-31 15:55:21.123')   { iat - Issued At       - Emitido em ( Quando o Token foi Emitido / Automático ) }
           .nbf('2021-01-31 18:01:01.001')   { nbf - Not Before      - Validade Iniciada ( Inicia Em ) }
           .exp('2021-01-31 22:01:01.001')   { exp - Expiration Time - Validade Terminada ( Expirar Em ) }
           .add('chave personalizada', 10.5) { Chave personalizada com o valor decimal 10,5 }
      ;
      LToken := JWT.Signature.Sign; 
      Result := LToken;
   end; 
end)
```

```delphi
function FuncCheckToken(const aToken: string; const aPassword: string): string;
begin 
   Result := 
    JWT
      .Token(aValue)
      .Password(aPassword) { Opcional pois lé da variável de ambiente JWT_PRIVATE_PASSWORD se não encontrada usará a constante DEFAULT_PASSWORD contida na classe }
      .Signature.Verify;
end)
```
