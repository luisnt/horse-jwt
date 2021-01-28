unit Core.JWT.Header;

interface

uses
  System.JSON, System.Classes, System.SysUtils

    , Core.JWT.Utils
    , Core.JWT.Header.Interfaces

    ;

type
  THeader = class(TInterfacedObject, iHeader)
    class function New: iHeader;
    constructor Create;
    destructor Destroy; override;
  strict private
    FHeader: TJwtAlgorithm;
  private

  public
    function Algorithm(const aAlgorithm: TJwtAlgorithm): iHeader;
    function AsJson(const AsBase64: boolean = false): string;
    function AsJsonObject: TJSONObject;
    function AsAlgorithm: TSHA2Version;
  end;

implementation

{ THeader }

class function THeader.New: iHeader;
begin
  Result := Self.Create;
end;

constructor THeader.Create;
begin
  FHeader := TJwtAlgorithm.HS256;
end;

destructor THeader.Destroy;
begin
  inherited;
end;

function THeader.Algorithm(const aAlgorithm: TJwtAlgorithm): iHeader;
begin
  FHeader := aAlgorithm;
  Result  := Self;
end;

function THeader.AsJson(const AsBase64: boolean = false): string;
begin
  Result := Format('{"alg":"%s","typ":"JWT"}', [FHeader.AsString]);
  if AsBase64 then
    Result := Result.AsBase64url.ClearLineBreak;
end;

function THeader.AsJsonObject: TJSONObject;
begin
  Result := AsJson(false).ClearLineBreak.AsJsonObject;
end;

function THeader.AsAlgorithm: TSHA2Version;
begin
  Result := FHeader.AsAlgorithm;
end;

end.
