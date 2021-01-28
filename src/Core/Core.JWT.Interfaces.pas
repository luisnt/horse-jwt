unit Core.JWT.Interfaces;

interface

uses
  Core.JWT.Header.Interfaces,
  Core.JWT.Payload.Interfaces,
  Core.JWT.Signature.Interfaces
    ;

Type
  iJWT = interface
    ['{BB0D5281-A6B9-47E5-920C-810F0074BC3D}']
    function Token(aValue: string): iJWT; overload;
    function Password(aValue: string; const aEncoded: boolean = false): iJWT; overload;

    function Password: string; overload;
    function PasswordEncoded: boolean;

    function Token: string; overload;

    function Header: iHeader;
    function Payload: iPayload;
    function Signature: iSignature;
  end;

implementation

end.
