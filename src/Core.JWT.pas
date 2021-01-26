unit Core.JWT;

interface

uses
  Core.JWT.Enums,
  Core.JWT.Interfaces;

type
  TJWT = class(TInterfacedObject, iJWT, iJWTOne, iJWTTwo)
    class function New: iJWT;
    constructor Create;
    destructor Destroy; override;
  strict private
    FAlgorithm    : Core.JWT.Enums.TJwtAlgorithm;
    FPassword     : string;
    FToken        : string;
    FPayload      : string;
    FExpireInHours: integer;
    FID           : string;
    FRemoteIP     : string;
    FVerified     : boolean;

  private

  public { iJWT }
    function Password(aValue: string): iJWTOne;

  public { iJWTOne }
    function Verify(aToken: string): boolean;
    function Algorithm(aValue: TJwtAlgorithm): iJWTTwo;

  public { iJWTTwo }
    function ID(aID: int64): iJWTTwo;
    function RemoteIP(aValue: String): iJWTTwo;
    function ExpireIn(aHours: integer): iJWTTwo;
    function Payload(aPairs: string): iJWTTwo; overload;
    function Payload(aPairs: TPairs): iJWTTwo; overload;
    function Token: string;
  end;

function JWT: iJWT;

implementation

uses
  System.JSON
    , System.SysUtils
    , System.DateUtils
    , System.TypInfo

    , JOSE.Types.Bytes
    , JOSE.Core.JWA
    , JOSE.Core.JWK
    , JOSE.Core.JWS
    , JOSE.Core.JWT
    ;

function JWT: iJWT;
begin
  Result := TJWT.New;
end;

{ TJWT }

class function TJWT.New: iJWT;
begin
  Result := Self.Create;
end;

constructor TJWT.Create;
begin
  FPassword     := 'your-256-bit-secret';
  FJwtAlgorithm := TJwtAlgorithm.HS256;
end;

destructor TJWT.Destroy;
begin

  inherited;
end;

function TJWT.Token(aJwtID: int64; aEmissor: String; aIPClient: String; aPassword: String = 'your-256-bit-secret'): String;
  function GenerateToken(const aHeader: String; const aPayload: String; const aPassword: string; aJoseAlgorithmID: TJoseAlgorithmID = TJoseAlgorithmID.HS256): String;
  var
    FJWT   : JOSE.Core.JWT.TJWT;
    LKey   : JOSE.Core.JWK.TJWK;
    LSigner: JOSE.Core.JWS.TJWS;
  begin
    FJWT := JOSE.Core.JWT.TJWT.Create(JOSE.Core.JWT.TJWTClaims);
    FJWT.Header.JSON.Free;
    FJWT.Claims.JSON.Free;

    FJWT.Header.JSON := System.JSON.TJSONObject(TJSONObject.ParseJSONValue(aHeader));
    FJWT.Claims.JSON := System.JSON.TJSONObject(TJSONObject.ParseJSONValue(aPayload));

    LKey    := JOSE.Core.JWK.TJWK.Create(aPassword);
    LSigner := JOSE.Core.JWS.TJWS.Create(FJWT);

    LSigner.SkipKeyValidation := true;
    LSigner.Sign(LKey, aJoseAlgorithmID);

    Result := LSigner.Header.AsString + '.' + LSigner.Payload.AsString + '.' + LSigner.Signature.AsString;
    LKey.Free;
    LSigner.Free;
    FJWT.Free;
  end;

var
  LHeader : String;
  LPayload: String;
begin
  Result   := '';
  LHeader  := String(Format('{"alg":"%s","typ":"JWT"}', [aJwtAlgorithm.AsString]));
  LPayload := String(Format('{ "jti": "%d", "iss": "%s", "aud":"%s", "iat":"%s", "exp": "%s" }', [ { }
    aJwtID,                                                                                        { }
    aEmissor,                                                                                      { }
    aIPClient,
    FormatDateTime('yyyymmddHHmmsszzz', now),            { }
    FormatDateTime('yyyymmddHHmmsszzz', IncHour(now, 2)) { }
    ]));

  Result := GenerateToken(LHeader.ClearLineBreak, LPayload.ClearLineBreak, aPassword);
end;

function TJWT.Verify(aToken: String; aPassword: String = 'your-256-bit-secret'): boolean;
var
  LKey         : TJWK;
  LToken       : TJWT;
  LSigner      : TJWS;
  LCompactToken: String;
begin
  Result        := False;
  LCompactToken := aToken.ClearLineBreak;
  LKey          := TJWK.Create(aPassword);
  LToken        := TJWT.Create;
  try
    LSigner                   := TJWS.Create(LToken);
    LSigner.SkipKeyValidation := true;
    try
      LSigner.SetKey(LKey);
      LSigner.CompactToken := LCompactToken;
      LSigner.VerifySignature;
    finally
      LSigner.Free;
    end;

    if LToken.Verified then
      Result := true;
  finally
    LKey.Free;
    LToken.Free;
  end;
end;

end.
