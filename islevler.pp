unit islevler;

{$mode ObjFPC}{$H+}

interface

uses Classes, SysUtils, IdGlobal;

const
  OnDegerDNSSunucuIPAdresi = '192.168.1.1';
  AyarDosyaAdi : string = 'dnsi.ini';

var
  DNSSunucusu: string = OnDegerDNSSunucuIPAdresi;

const
  DNS_PORTNO = 53;
  TANIM_KIMLIK = $ABCD;

procedure Ekle2Byte(var AHedef: TIdBytes; const ADeger: Word);
procedure Ekle4Byte(var AHedef: TIdBytes; const ADeger: DWord);
procedure AyarDosyasiniOku;
procedure AyarDosyasinaYaz;

implementation

uses IniFiles;

// indy yardımcı işlev - veriye word değer ekleme (veriler big-endian biçiminde)
procedure Ekle2Byte(var AHedef: TIdBytes; const ADeger: Word);
begin

  AppendByte(AHedef, Byte(ADeger shr 8));
  AppendByte(AHedef, Byte(ADeger and $FF));
end;

// indy yardımcı işlev - veriye dword değer ekleme (veriler big-endian biçiminde)
procedure Ekle4Byte(var AHedef: TIdBytes; const ADeger: DWord);
begin

  AppendByte(AHedef, Byte(ADeger shr 24));
  AppendByte(AHedef, Byte(ADeger shr 16));
  AppendByte(AHedef, Byte(ADeger shr 8));
  AppendByte(AHedef, Byte(ADeger and $FF));
end;

procedure AyarDosyasiniOku;
var
  INIDosyasi: TINIFile;
begin

  if not(FileExists(AyarDosyaAdi)) then
  begin

    INIDosyasi := TINIFile.Create(AyarDosyaAdi);

    // ayar dosyası daha önce oluşturulmamışsa öndeğer ayarları oluştur
    DNSSunucusu := OnDegerDNSSunucuIPAdresi;

    INIDosyasi.WriteString('Sunucu', 'IPAdresi', DNSSunucusu);

    INIDosyasi.Free;
  end
  else
  begin

    INIDosyasi := TINIFile.Create(AyarDosyaAdi);

    DNSSunucusu := INIDosyasi.ReadString('Sunucu', 'IPAdresi', OnDegerDNSSunucuIPAdresi);

    INIDosyasi.Free;
  end;
end;

procedure AyarDosyasinaYaz;
var
  INIDosyasi: TINIFile;
begin

  INIDosyasi := TINIFile.Create(AyarDosyaAdi);

  INIDosyasi.WriteString('Sunucu', 'IPAdresi', DNSSunucusu);

  INIDosyasi.UpdateFile;
  INIDosyasi.Free;
end;

end.
