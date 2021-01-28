unit Horse.JWT;

interface

uses
  System.SysUtils, System.NetEncoding, System.Classes
    , Horse
    , Horse.Commons
    ;

type
  JWT = class
    class procedure Login(Req: THorseRequest; Res: THorseResponse; Next: TProc);
    class procedure Guard(Req: THorseRequest; Res: THorseResponse; Next: TProc);
  end;

const
  BASEC_AUTH    = 'basic';
  BEARER        = 'bearer';
  AUTHORIZATION = 'authorization';

implementation

uses
  Web.HTTPApp
    , Horse.JWT.Facade
    ;

{ TJWT }

class procedure JWT.Login(Req: THorseRequest; Res: THorseResponse; Next: TProc);
begin
  if THorseHackRequest(Req).GetWebRequest.Method = 'POST' then
  begin
    Res.Send('').Status(THTTPStatus.NoContent);
    raise EHorseCallbackInterrupted.Create();
  end
  else
    Next();
end;

class procedure JWT.Guard(Req: THorseRequest; Res: THorseResponse; Next: TProc);
var
  LToken: string;
begin
  LToken := Req.Headers[AUTHORIZATION];
  if LToken.Trim.IsEmpty and not Req.Query.TryGetValue(AUTHORIZATION, LToken) then
  begin
    Res.Send('Authorization not found').Status(THTTPStatus.Unauthorized).RawWebResponse
    {$IF DEFINED(FPC)}
      .WWWAuthenticate := Format('Basic realm=%s', [RealmMessage]);
    {$ELSE}
      .Realm := 'Enter credentials';
    {$ENDIF}
    raise EHorseCallbackInterrupted.Create;
  end;

  if not LToken.ToLower.StartsWith(BEARER) then
  begin
    Res.Send('Invalid authorization type').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  LToken := LToken.Replace(BEARER, '', [rfIgnoreCase]).Trim;

  CoreJWT.JWT.
  if not  Token(LToken).Signature.Verify then
  begin
    Res.Send('Access deny.').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  Next();
end;

end.
