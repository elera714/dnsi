{

  Program Adı: DNS İstemci
  Program Exe Adı: dnsi.exe
  Kodlayan: Fatih KILIÇ
  Mail: hs.fatih.kilic@gmail.com

  Tanım: program DNS adlarını sorgulayarak sorgu sonuçlarını görüntüler

  https://www.firewall.cx/networking/network-protocols/dns-protocol/protocols-dns.html

}
unit anasayfafrm;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls,
  Buttons, ComCtrls, IdComponent, IdGlobal, IdUDPClient;

type
  TfrmAnaSayfa = class(TForm)
    btnBilgi: TBitBtn;
    btnSorgu: TButton;
    edtDNSAdi: TEdit;
    idUDPIstemci: TIdUDPClient;
    lblDNSAdi: TLabel;
    mmSonuc: TMemo;
    pnlBilgi: TPanel;
    pnlSorgu: TPanel;
    sbDurum: TStatusBar;
    procedure btnBilgiClick(Sender: TObject);
    procedure btnSorguClick(Sender: TObject);
    procedure edtDNSAdiKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormShow(Sender: TObject);
  private
    procedure Sorgula(ADNSAdi: string);
  public
  end;

var
  frmAnaSayfa: TfrmAnaSayfa;

implementation

{$R *.lfm}
uses IdDNSCommon, Sockets, paylasim, LCLType, sunucudegistirfrm;

procedure TfrmAnaSayfa.btnSorguClick(Sender: TObject);
begin

  Sorgula(edtDNSAdi.Text);
end;

procedure TfrmAnaSayfa.btnBilgiClick(Sender: TObject);
begin

  if(frmSunucuDegistir.ShowModal = mrOK) then
  begin

    FormShow(Self);
  end;
end;

procedure TfrmAnaSayfa.edtDNSAdiKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin

  if(Key = VK_RETURN) then btnSorguClick(Self);
end;

procedure TfrmAnaSayfa.FormShow(Sender: TObject);
begin

  btnBilgi.Hint := Format('DNS Sunucusu: %s', [DNSSunucusu]);

  edtDNSAdi.SetFocus;
end;

{
  DNS sunucusuna sorgu gönderir
}
procedure TfrmAnaSayfa.Sorgula(ADNSAdi: string);
var
  DNSKayit: PDNSKayit;
  PB1, PBellek: PByte;
  PB2: PWord;
  C: Char;
  i, DNSAdresU, ToplamU, TTL, IP: LongWord;
  BellekU, U: Byte;
  DNSBellek, B: TIdBytes;
  Tanimlayici, YanitSayisi, Bayrak, SorguTipi,
  SorguSinifi, VeriU: Word;
  DNSAdi: string;
begin

  sbDurum.SimpleText := Format('%s adresi sorgulanıyor...', [ADNSAdi]);
  sbDurum.Repaint;

  mmSonuc.Lines.Add('');
  mmSonuc.Lines.Add('');
  mmSonuc.Lines.Add(Format('Sorgulanan DNS Adı: %s', [ADNSAdi]));
  mmSonuc.Lines.Add('---------------------------');

  SetLength(DNSBellek, 57 + Length(ADNSAdi) + 1);

  DNSKayit := PDNSKayit(@DNSBellek[0]);

  // 12 bytelık veri
	DNSKayit^.Tanimlayici := Swap(TANIM_KIMLIK);
  DNSKayit^.Bayrak := Swap($0100);        // standard sorgu, recursion
  DNSKayit^.SorguSayisi := Swap(1);       // 1 sorgu
  DNSKayit^.YanitSayisi := Swap(0);
  DNSKayit^.YetkiSayisi := Swap(0);
  DNSKayit^.DigerSayisi := Swap(0);

  PB1 := @DNSKayit^.Veriler;
  PBellek := PB1;     // 1 byte veri uzunluk adresi
  Inc(PB1);
  BellekU := 0;
  ToplamU := 0;

  DNSAdresU := Length(ADNSAdi);
  for i := 1 to DNSAdresU do
  begin

    C := ADNSAdi[i];

    if(C = '.') then
    begin

      PBellek^ := BellekU;
      PBellek := PB1;
      ToplamU += BellekU + 1;
      Inc(PB1);
      BellekU := 0;
    end
    else
    begin

      PChar(PB1)^ := C;
      Inc(PB1);
      Inc(BellekU);
    end;
  end;
  PBellek^ := BellekU;
  ToplamU += BellekU + 1;

  PB1^ := 0;        // sıfır sonlandırma
  Inc(ToplamU);

  Inc(PB1);
  PB2 := Pointer(PB1);
  PB2^ := Swap(DNS_STIP_A);
  Inc(PB2);
  PB2^ := Swap(DNS_SSINIF_IN);

  idUDPIstemci.SendBuffer(DNSSunucusu, DNS_PORTNO, DNSBellek);

  SetLength(B, 1024);

  i := idUDPIstemci.ReceiveBuffer(B, 2000);

  if(i > 0) then
  begin

    SetLength(B, i);

    DNSKayit := PDNSKayit(B);
    Tanimlayici := htons(DNSKayit^.Tanimlayici);
    YanitSayisi := htons(DNSKayit^.YanitSayisi);
    Bayrak := htons(DNSKayit^.Bayrak);

    if(YanitSayisi = 1) and (Tanimlayici = TANIM_KIMLIK) then
    begin

      mmSonuc.Lines.Add('Tanimlayici: ' + IntToHex(Tanimlayici));
      mmSonuc.Lines.Add('Bayrak: ' + IntToHex(htons(DNSKayit^.Bayrak)));     // $8180
      mmSonuc.Lines.Add('SorguSayisi: ' + IntToStr(htons(DNSKayit^.SorguSayisi)));
      mmSonuc.Lines.Add('YanitSayisi: ' + IntToStr(YanitSayisi));
      mmSonuc.Lines.Add('Bayrak: ' + IntToHex(Bayrak));

      DNSAdi := '';
      PB1 := @DNSKayit^.Veriler;
      while PB1^ <> 0 do
      begin

        U := PB1^;
        Inc(PB1);
        for i := 1 to U do
        begin

          DNSAdi +=  Char(PB1^);
          Inc(PB1);
        end;

        if(PB1^ <> 0) then DNSAdi += '.';
      end;

      Inc(PB1);
      SorguTipi := PWord(PB1)^;
      Inc(PB1, 2);
      SorguSinifi := PWord(PB1)^;

      mmSonuc.Lines.Add('DNSAdi: ' + DNSAdi);
      mmSonuc.Lines.Add('SorguTipi: $' + IntToHex(SorguTipi));
      mmSonuc.Lines.Add('SorguSinifi: $' + IntToHex(SorguSinifi));

      Inc(PB1, 2 + 2);    // jump $c0 and $0c data
      SorguTipi := PWord(PB1)^;
      Inc(PB1, 2);
      SorguSinifi := PWord(PB1)^;
      mmSonuc.Lines.Add('SorguTipi: $' + IntToHex(SorguTipi));
      mmSonuc.Lines.Add('SorguSinifi: $' + IntToHex(SorguSinifi));

      Inc(PB1, 2);
      TTL := htonl(PLongWord(PB1)^);
      mmSonuc.Lines.Add('TTL: ' + IntToStr(TTL));

      Inc(PB1, 4);
      VeriU := htons(PWord(PB1)^);
      mmSonuc.Lines.Add('VeriU: ' + IntToStr(VeriU));

      Inc(PB1, 2);
      IP := PLongWord(PB1)^;
      mmSonuc.Lines.Add('IP Adresi: ' + IP_KarakterKatari(IP));

    end
    else
    begin

      mmSonuc.Lines.Add('Hata: YanitSayisi: ' + IntToStr(YanitSayisi));
    end;
  end
  else
  begin

    mmSonuc.Lines.Add('Hata: DNS adı çözümlenemiyor!');
  end;

  SetLength(B, 0);
  SetLength(DNSBellek, 0);

  sbDurum.SimpleText := '';
  sbDurum.Repaint;
end;

end.
