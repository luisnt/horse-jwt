unit Core.JWT.Interfaces;

interface

uses
  Core.JWT.Enums;

Type
  iJWTOne   = interface;
  iJWTTwo   = interface;

  iJWT = interface
    ['{BA7A5BBF-6B4A-4E25-9C38-8EF66A241701}']
    function Password(aPassword: string): iJWTOne;
  end;

  iJWTOne = interface
    ['{5020F829-D970-4B17-B5EA-DC2E801BAD11}']
    function Verify(aToken: string): boolean;
    function Algorithm(aValue: TJwtAlgorithm): iJWTTwo;
  end;

  iJWTTwo = interface
    ['{B3442033-24EF-4C13-B3DE-26861F138A17}']
    function ID(aID: int64): iJWTTwo;
    function RemoteIP(aValue: String): iJWTTwo;
    function ExpireIn(aHours: integer): iJWTTwo;
    function Payload(aPairs: string): iJWTTwo; overload;
    function Payload(aPairs: TPairs): iJWTTwo; overload;
    function Token: string;
  end;

implementation

end.
