unit Core.JWT.Payload;

interface

uses
  System.Classes, System.JSON, System.SysUtils, System.DateUtils, System.NetEncoding

    , Core.JWT.Utils
    , Core.JWT.Payload.Interfaces
    ;

type
  TPayload = class(TInterfacedObject, iPayload)
    class function New: iPayload;
    constructor Create;
    destructor Destroy; override;
  strict private
    FData: TStrings;
  private

  public
    function Clear: iPayload;

    function Add(const aKey: string; const aValue: string; aFormat: string = '"%s":"%s"'): iPayload; overload;
    function Add(const aKey: string; const aValue: Int64; aFormat: string = '"%s":%s'): iPayload; overload;
    function Add(const aKey: string; const aValue: UInt64; aFormat: string = '"%s":%s'): iPayload; overload;
    function Add(const aKey: string; const aValue: boolean; aFormat: string = '"%s":%s'): iPayload; overload;
    function Add(const aKey: string; const aValue: TDateTime; aFormat: string = '"%s":"%s"'): iPayload; overload;
    function Add(const aKey: string; const aValue: Extended; aFormat: string = '"%s":%s'): iPayload; overload;

    function jti(const aID: UInt64): iPayload;                 { jti - Jwt ID          - Jwt ID ( ID ) }
    function iss(const aEmissor: String): iPayload;            { iss - Issuer          - Emissor ( Emissor ) }
    function sub(const aAssunto: String): iPayload;            { sub - Subject         - Assunto }
    function aud(const aRemoteIP: String): iPayload;           { aud - Audience        - Audi�ncia ( Remote IP ) }
    function iat(const aEmissionAt: TDateTime): iPayload;      { iat - Issued At       - Emitido em ( Quando o Token foi Emitido / Autom�tico ) }
    function nbf(const aValidityStarted: TDateTime): iPayload; { nbf - Not Before      - Validade Iniciada ( Inicia Em ) }
    function exp(const aValidityEnded: TDateTime): iPayload;   { exp - Expiration Time - Validade Terminada ( Expirar Em ) }

    function AsJson(const aAsBase64: boolean = false): string;
    function AsJsonObject: TJSONObject;

  end;

implementation

{ TPayload }

class function TPayload.New: iPayload;
begin
  Result := Self.Create;
end;

constructor TPayload.Create;
begin
  FData := TStringList.Create;
  FData.Clear;
end;

destructor TPayload.Destroy;
begin
  FData.Free;
  inherited;
end;

function TPayload.Clear: iPayload;
begin
  FData.Clear;
end;

function TPayload.Add(const aKey: string; const aValue: string; aFormat: string = '"%s":"%s"'): iPayload;
begin
  FData.Values[aKey] := Format(aFormat, [aKey, aValue]);
  Result             := Self;
end;

function TPayload.Add(const aKey: string; const aValue: Int64; aFormat: string = '"%s":%s'): iPayload;
begin
  FData.Values[aKey] := Format(aFormat, [aKey, aValue.ToString]);
  Result             := Self;
end;

function TPayload.Add(const aKey: string; const aValue: UInt64; aFormat: string): iPayload;
begin
  FData.Values[aKey] := Format(aFormat, [aKey, aValue.ToString]);
  Result             := Self;
end;

function TPayload.Add(const aKey: string; const aValue: boolean; aFormat: string = '"%s":%s'): iPayload;
begin
  FData.Values[aKey] := Format(aFormat, [aKey, LowerCase(BoolToStr(aValue, true))]);
  Result             := Self;
end;

function TPayload.Add(const aKey: string; const aValue: TDateTime; aFormat: string = '"%s":"%s"'): iPayload;
begin
  FData.Values[aKey] := Format(aFormat, [aKey, FormatDateTime('yyyy-mm-dd HH:mm:ss.zzz', aValue)]);
  Result             := Self;
end;

function TPayload.Add(const aKey: string; const aValue: Extended; aFormat: string): iPayload;
begin
  FData.Values[aKey] := Format(aFormat, [aKey, StringReplace(FormatFloat('0.00', aValue), ',', '.', [])]);
  Result             := Self;
end;

function TPayload.jti(const aID: UInt64): iPayload; { jti - Jwt ID                      - Jwt ID ( ID ) }
begin
  Result := Add('jti', aID);
end;

function TPayload.iss(const aEmissor: String): iPayload; { iss - Issuer                     - Emissor ( Emissor ) }
begin
  Result := Add('iss', aEmissor);
end;

function TPayload.sub(const aAssunto: String): iPayload; { sub - Subject                   - Assunto }
begin
  Result := Add('sub', aAssunto);
end;

function TPayload.aud(const aRemoteIP: String): iPayload; { aud - Audience                 - Audi�ncia ( Remote IP ) }
begin
  Result := Add('aud', aRemoteIP);
end;

function TPayload.iat(const aEmissionAt: TDateTime): iPayload; { iat - Issued At             - Emitido em }
begin
  Result := Add('iat', aEmissionAt);
end;

function TPayload.nbf(const aValidityStarted: TDateTime): iPayload; { nbf - Not Before           - N�o antes }
begin
  Result := Add('nbf', aValidityStarted);
end;

function TPayload.exp(const aValidityEnded: TDateTime): iPayload; { exp - Expiration Time - Prazo de Validade ( Expirar Em ) }
begin
  Result := Add('exp', aValidityEnded);
end;

function TPayload.AsJson(const aAsBase64: boolean = false): string;
var
  I   : integer;
  LSep: string;
begin
  LSep   := EmptyStr;
  Result := EmptyStr;

  for I := 0 to pred(FData.Count) do
  begin
    Result := Result + LSep + FData.ValueFromIndex[I];
    LSep   := ',';
  end;
  Result := '{' + Result + '}';

  if aAsBase64 then
    Result := Result.AsBase64url.ClearLineBreak;
end;

function TPayload.AsJsonObject: TJSONObject;
begin
  Result := AsJson(false).ClearLineBreak.AsJsonObject;
end;

end.
