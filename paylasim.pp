unit paylasim;

{$mode ObjFPC}{$H+}

interface

uses Classes, SysUtils;

var
  DNSSunucusu: string = '192.168.1.1';

const
  DNS_PORTNO = 53;
  TANIM_KIMLIK = 33455;

  // sorgu tipleri
  DNS_STIP_A      = 1;              // ipv4 adresi
  DNS_STIP_AAAA   = 28;             // ipv6 adresi

  // sorgu sınıfları
  DNS_SSINIF_IN   = 1;              // internet sınıfı
  DNS_SSINIF_CS   = 2;              // csnet sınıfı

type
  PDNSKayit = ^TDNSKayit;
  TDNSKayit = packed record
  	Tanimlayici,
    Bayrak,
    SorguSayisi,
    YanitSayisi,
    YetkiSayisi,
    DigerSayisi: Word;
    Veriler: Pointer;
  end;

type
  PMACAdres = ^TMACAdres;
  TMACAdres = array[0..5] of Byte;
  PIPAdres = ^TIPAdres;
  TIPAdres = array[0..3] of Byte;

var
  IPAdres0: TIPAdres = (0, 0, 0, 0);
  MACAdres0: TMACAdres = ($F4, $4D, $30, $4B, $15, $39);

function IP_KarakterKatari(AIPAdres: LongWord): string;

implementation

{
  IP adres değerini karakter katarına çevirir
}
function IP_KarakterKatari(AIPAdres: LongWord): string;
var
  Toplam, i: Byte;
  Deger: string[3];
  IPAdres: LongWord;
begin

  IPAdres := AIPAdres;

  Toplam := 0;
  Result := '';

  // convert ip address
  for i := 0 to 3 do
  begin

    Deger := IntToStr(IPAdres and $FF);
    Toplam := Toplam + Length(Deger);
    Result := Result + Deger;

    IPAdres := IPAdres shr 8;

    if(i < 3) then
    begin

      Result := Result + '.'
    end;
  end;

  SetLength(Result, Toplam + 3);  // + 3 = nokta sayısı
end;

end.
