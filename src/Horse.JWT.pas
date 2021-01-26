unit Horse.JWT;
{$IF DEFINED(FPC)}
{$MODE DELPHI}{$H+}
{$ENDIF}

interface

uses
  {$IF DEFINED(FPC)}SysUtils, base64, Classes, {$ELSE} System.SysUtils, System.NetEncoding, System.Classes {$ENDIF}
    , Horse
    , Horse.Commons
    ;

type
  JWT = class
    class procedure Login(Req: THorseRequest; Res: THorseResponse; Next: {$IF DEFINED(FPC)} TNextProc {$ELSE} TProc {$ENDIF} );
    class procedure Guard(Req: THorseRequest; Res: THorseResponse; Next: {$IF DEFINED(FPC)} TNextProc {$ELSE} TProc {$ENDIF} );
  end;

const
  BASEC_AUTH    = 'basic';
  BEARER        = 'bearer';
  AUTHORIZATION = 'authorization';

implementation

uses
  Web.HTTPApp
    , Core.JWT
    ;

{ JWT }

class procedure JWT.Login(Req: THorseRequest; Res: THorseResponse; Next: TProc);
var
  LWebResponse: {$IF DEFINED(FPC)}TResponse{$ELSE} TWebResponse {$ENDIF};
begin
  LWebResponse := THorseHackResponse(Res).GetWebResponse;
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
  LWebResponse: {$IF DEFINED(FPC)}TResponse{$ELSE} TWebResponse {$ENDIF};
  LToken      : string;
begin
  LWebResponse := THorseHackResponse(Res).GetWebResponse;

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

  Horse.JWT.Core.JWT.Verify(LToken, );
  Horse.JWT.Core.JWT.
end;

end.
