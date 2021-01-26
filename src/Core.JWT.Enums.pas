unit Core.JWT.Enums;

interface

uses JOSE.Core.JWA;

type
  TJwtAlgorithm = (HS256, HS384, HS512);

type
  TPair = array [1 .. 2] of string;

type
  TPairs = array of TPair;

type
  TJwtAlgorithmHelper = record Helper
    for TJwtAlgorithm
  public
    function AsJoseAlgorithmID: TJoseAlgorithmID;
    function AsString: String;
  end;

  TJwtAlgorithmStringHelper = record Helper
    for
    String
      public
    function AsJwtAlgorithm: TJwtAlgorithm;

    function AsJoseAlgorithmID: TJoseAlgorithmID;
    function ClearLineBreak: String;
  end;

implementation

uses
  System.TypInfo, System.SysUtils

    ;

{ TJwtAlgorithmHelper }
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
