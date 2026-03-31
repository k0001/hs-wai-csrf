{ mkDerivation, base, bytestring, case-insensitive, cookie, crypton
, http-types, lib, ram, time, wai, wai-extra
}:
mkDerivation {
  pname = "wai-csrf";
  version = "0.2";
  src = ./.;
  libraryHaskellDepends = [
    base bytestring case-insensitive cookie crypton http-types ram time
    wai
  ];
  testHaskellDepends = [
    base bytestring cookie http-types wai wai-extra
  ];
  homepage = "https://github.com/k0001/hs-wai-csrf";
  description = "Cross-site request forgery protection for WAI";
  license = lib.licenses.asl20;
}
