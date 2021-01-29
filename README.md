
# horse-jwt
Middleware to generate jwt token and verify signature on HORSE servers

Sample Horse server validate basic authentication:

```delphi
uses System.SysUtils

  , Horse
  , Horse.JWT 
;

begin
  THorse.Get('/', procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc) begin
      Res.Send('Página pública Home');
  end);
  
  THorse.Get('/sobre', procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc) begin
      Res.Send('Página pública Sobre');
  end);
  
  THorse.Post('/login', procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc) begin
      Res.Send(FuncAuth);
  end);
  
  THorse.Get('/privada', procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc) begin
         Res.Send('Área restrita protegida por verificação de Json WEB Token Assinado.');
  end), JWT.Guard ); { Middleware JWT.Guard Validará o Token se válido continua. se não bloqueia o acesso a rota }
    
  THorse.Listen(80);
end.
```

Função de autenticação

```delphi
function FuncAuth(const aUserName: string; const aPassword: string): string;
var
  LToken: string;
begin 
   if samestr(aUserName, 'root') and samestr(aPassword, 'toor') then
   begin
      { 
         Definir a senha atraves do método JWT.Password('secret'); é opcional 
         Carrega por padrão a ambiente JWT_PRIVATE_PASSWORD e se não existir 
         usará a constante DEFAULT_PASSWORD='your-256-bit-secret' contida na 
         unit Core.JWT.Utils.pas 
      }
      JWT.Password('secret'); { OPCIONAL }
      
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
      exit(LToken);
   end; 
   Result := 'Acesso Negado';
end)
```

Método de guarda das rotas
```delphi
function JWT.Guard(const aToken: string; const aPassword: string): string; { Função de Checagem do Token }
begin 
    { 
       Definir a senha atraves do método JWT.Password('secret'); é opcional 
       Carrega por padrão a ambiente JWT_PRIVATE_PASSWORD e se não existir 
       usará a constante DEFAULT_PASSWORD='your-256-bit-secret' contida na 
       unit Core.JWT.Utils.pas 
    }
    JWT.Password('secret'); { OPCIONAL }
      
    Result := JWT.Token(aValue).Signature.Verify;
end)
```
