unit Core.JWT.Header.Interfaces;

interface

uses
  System.JSON

    , Core.JWT.Utils
    ;

Type
  iHeader = interface
    ['{A14B0231-CAB9-40BF-A0D1-91552D33FEA6}']

    function Algorithm(const aAlgorithm: TJwtAlgorithm): iHeader;
    function AsJson(const AsBase64: boolean = false): string;
    function AsJsonObject: TJSONObject;
    function AsAlgorithm: TSHA2Version;
  end;

implementation

end.
