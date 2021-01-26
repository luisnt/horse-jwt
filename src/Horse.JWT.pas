unit Horse.JWT;

interface

type
  TJwtAlgorithm = (HS256, HS384, HS512);

function Token(aJwtID: int64; aEmissor: String; aIPClient: String; aPassword: String = 'your-256-bit-secret';
  aJwtAlgorithm: TJwtAlgorithm = TJwtAlgorithm.HS256): String;
function Verify(aToken: String; aPassword: String = 'your-256-bit-secret'): boolean;

implementation

uses
  System.JSON
    , System.SysUtils
    , System.DateUtils
    , System.TypInfo

    , JOSE.Types.Bytes
    , JOSE.Core.JWK
    , JOSE.Core.JWS
    , JOSE.Core.JWT
    , JOSE.Core.JWA
    ;

type
  TJwtAlgorithmHelper = record Helper for TJwtAlgorithm
  public
    function AsJoseAlgorithmID: TJoseAlgorithmID;
    function AsString: String;
  end;

  TJwtAlgorithmStringHelper = record Helper for
    String
      public
    function AsJwtAlgorithm: TJwtAlgorithm;
    function AsJoseAlgorithmID: TJoseAlgorithmID;
    function ClearLineBreak: String;
  end;

function Token(aJwtID: int64; aEmissor: String; aIPClient: String; aPassword: String = 'your-256-bit-secret'; aJwtAlgorithm: TJwtAlgorithm = TJwtAlgorithm.HS256): String;
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

function Verify(aToken: String; aPassword: String = 'your-256-bit-secret'): boolean;
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

function TJwtAlgorithmHelper.AsJoseAlgorithmID: TJoseAlgorithmID;
begin
  Result := Self.AsString.AsJoseAlgorithmID;
end;

function TJwtAlgorithmHelper.AsString: String;
begin
  Result := GetEnumName(TypeInfo(TJwtAlgorithm), integer(Self));
end;

{ TJwtAlgorithmStringHelper }

function TJwtAlgorithmStringHelper.AsJoseAlgorithmID: TJoseAlgorithmID;
begin
  Result := TJoseAlgorithmID(GetEnumValue(TypeInfo(TJoseAlgorithmID), Self));
end;

function TJwtAlgorithmStringHelper.AsJwtAlgorithm: TJwtAlgorithm;
begin
  Result := TJwtAlgorithm(GetEnumValue(TypeInfo(TJwtAlgorithm), String(Self)));
end;

function TJwtAlgorithmStringHelper.ClearLineBreak: String;
begin
  Self   := String(StringReplace(Self, sLineBreak, '', [rfReplaceAll]));
  Result := Self;
end;

end.
