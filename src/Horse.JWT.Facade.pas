unit Horse.JWT.Facade;

interface

uses
  System.SysUtils, System.NetEncoding, System.Classes

    , Core.JWT.Interfaces

    ;

type
  CoreJWT = class
    class function JWT: iJWT;
  end;

implementation

uses Core.JWT;

{ TJWTFacade }

class function CoreJWT.JWT: iJWT;
begin
  Result := Core.JWT.JWT;
end;

end.
