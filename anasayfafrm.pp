{

  Program Adı: DNS İstemcisi
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
  Buttons, ComCtrls, IdComponent, IdGlobal, IdUDPClient, IdDNSResolver;

type
  TfrmAnaSayfa = class(TForm)
    btnBilgi: TBitBtn;
    btnSorgu: TButton;
    edtDNSAdi: TEdit;
    idDNSYanitlayici: TIdDNSResolver;
    idUDPIstemci: TIdUDPClient;
    lblDNSAdi: TLabel;
    mmSonuc: TMemo;
    pnlBilgi: TPanel;
    pnlSorgu: TPanel;
    sbDurum: TStatusBar;
    procedure btnBilgiClick(Sender: TObject);
    procedure btnSorguClick(Sender: TObject);
    procedure edtDNSAdiKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormShow(Sender: TObject);
  private
    procedure Sorgula(ADNSAdi: string);
  public
  end;

var
  frmAnaSayfa: TfrmAnaSayfa;

implementation

{$R *.lfm}
uses IdDNSCommon, Sockets, IdStack, islevler, LCLType, sunucudegistirfrm;

procedure TfrmAnaSayfa.FormShow(Sender: TObject);
begin

  AyarDosyasiniOku;

  edtDNSAdi.Text := SorgulananSonDNSAdi;
  btnBilgi.Hint := Format('DNS Sunucusu: %s', [DNSSunucusu]);

  edtDNSAdi.SetFocus;
end;

procedure TfrmAnaSayfa.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin

  // program çıkışında ayarları dosyaya kaydet
  AyarDosyasinaYaz;
end;

procedure TfrmAnaSayfa.btnSorguClick(Sender: TObject);
var
  DNSAdi: string;
begin

  DNSAdi := Trim(edtDNSAdi.Text);
  edtDNSAdi.Text := DNSAdi;

  if(Length(DNSAdi) = 0) then
  begin

    ShowMessage('Hata: Lütfen sorgulanacak DNS adını giriniz!');
    edtDNSAdi.SetFocus;
    Exit;
  end;

  Sorgula(DNSAdi);
end;

procedure TfrmAnaSayfa.btnBilgiClick(Sender: TObject);
begin

  if(frmSunucuDegistir.ShowModal = mrOK) then
  begin

    btnBilgi.Hint := Format('DNS Sunucusu: %s', [DNSSunucusu]);

    edtDNSAdi.SetFocus;
  end;
end;

procedure TfrmAnaSayfa.edtDNSAdiKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin

  if(Key = VK_RETURN) then btnSorguClick(Self);
end;

{
  DNS sunucusuna sorgu gönderir
}
procedure TfrmAnaSayfa.Sorgula(ADNSAdi: string);
var
  DNSBaslik: TDNSHeader;
  DNSSorgu, DNSYanit: TIdBytes;
  SorguTipi, SorguSinifi: Word;
  DNSAdi, s: string;
  i: Integer;
begin

  sbDurum.SimpleText := Format('%s adresi sorgulanıyor...', [ADNSAdi]);
  sbDurum.Repaint;

  mmSonuc.Lines.Add(Format('Sorgulanan DNS Adı: %s', [ADNSAdi]));
  mmSonuc.Lines.Add('Yanıt:---------------------');

  // 12 bytelık başlık verisi
  SetLength(DNSSorgu, 12);
  CopyTIdWord(GStack.NetworkToHost(Word(TANIM_KIMLIK)), DNSSorgu, 0);
  CopyTIdWord(GStack.NetworkToHost(Word($0100)), DNSSorgu, 2);         // standard sorgu, recursion
  CopyTIdWord(GStack.NetworkToHost(Word(1)), DNSSorgu, 4);
  CopyTIdWord(GStack.NetworkToHost(Word(0)), DNSSorgu, 6);
  CopyTIdWord(GStack.NetworkToHost(Word(0)), DNSSorgu, 8);
  CopyTIdWord(GStack.NetworkToHost(Word(0)), DNSSorgu, 10);

  // sorgulanması istenen DNS adı
  DNSAdi := ADNSAdi;
  while Length(DNSAdi) > 0 do begin
    s := Fetch(DNSAdi, '.');
    i := Length(s);
    AppendByte(DNSSorgu, i);
    AppendString(DNSSorgu, s, i);
  end;
  AppendByte(DNSSorgu, 0);       // 0 sonlandırama

  // tip ve sınıf kodu
  Ekle2Byte(DNSSorgu, TypeCode_A);
  Ekle2Byte(DNSSorgu, Class_IN);

  // hazırlanan sorgu verisini sunucuya gönder
  idUDPIstemci.SendBuffer(DNSSunucusu, DNS_PORTNO, DNSSorgu);

  SetLength(DNSYanit, 512);

  // sunucudan 2 saniye içerisinde yanıt bekle
  i := idUDPIstemci.ReceiveBuffer(DNSYanit, 2 * 1000);
  if(i > 0) then
  begin

    DNSBaslik := TDNSHeader.Create;

    if(DNSBaslik.ParseQuery(DNSYanit) = 0) then
    begin

      idDNSYanitlayici.ParseAnswers(DNSBaslik, DNSYanit);

      // DNS sunucusu tarafından geri döndürülen yanıt sayısı
      if(DNSBaslik.ANCount > 0) then
      begin

        // alınan mesaj bir yanıt mesajı ve
        // alınan sorgu kimliği gönderilen sorgu kimliği ile aynı ise
        if(DNSBaslik.BitCode = $8180) and (DNSBaslik.ID = TANIM_KIMLIK) then
        begin

          SorgulananSonDNSAdi := ADNSAdi;

          for i := 0 to idDNSYanitlayici.QueryResult.Count - 1 do
          begin

            // sıralı yanıt mesajı yalnızca 1den fazla yanıt olması durumunda görüntülenecek
            if(idDNSYanitlayici.QueryResult.Count > 1) then
              mmSonuc.Lines.Add(Format('%d. Yanıt', [i + 1]));

            // mesaj tip ve sınıf kontrolü
            SorguTipi := QueryRecordValues[Ord(idDNSYanitlayici.QueryResult.Items[i].RecType)];
            SorguSinifi := idDNSYanitlayici.QueryResult.Items[i].RecClass;
            if(SorguSinifi = Class_IN) then
            begin

              if(SorguTipi = TypeCode_A) then
              begin

                mmSonuc.Lines.Add(Format('DNS Adı: %s', [idDNSYanitlayici.QueryResult.Items[i].Name]));
                mmSonuc.Lines.Add(Format('IP Adresi: %s', [BytesToIPv4Str(idDNSYanitlayici.QueryResult.Items[i].RData)]));
                mmSonuc.Lines.Add(Format('TTL: %d saniye', [idDNSYanitlayici.QueryResult.Items[i].TTL]));
              end
              else if(SorguTipi = TypeCode_CName) then
              begin


                mmSonuc.Lines.Add(Format('DNS Adı: %s', [idDNSYanitlayici.QueryResult.Items[i].Name]));
                mmSonuc.Lines.Add(Format('CNAME: %s', [Byte2DNSAdi(idDNSYanitlayici.QueryResult.Items[i].RData,
                  idDNSYanitlayici.QueryResult.Items[i].RDataLength)]));
                mmSonuc.Lines.Add(Format('TTL: %d saniye', [idDNSYanitlayici.QueryResult.Items[i].TTL]));
              end
              else
              begin

                mmSonuc.Lines.Add('Hata: mesaj sorgu tipi çözümlenemiyor!');
                mmSonuc.Lines.Add(Format('Sorgu Tipi: %d', [SorguTipi, SorguSinifi]));
              end;
            end
            else
            begin

              mmSonuc.Lines.Add('Hata: sorgu sınıf kodu çözümlenemiyor!');
              mmSonuc.Lines.Add(Format('Sorgu Sınıfı: %d', [SorguSinifi]));
            end;

            mmSonuc.Lines.Add('---------------------------');
          end;
        end
        else
        begin

          mmSonuc.Lines.Add('Hata: yanıt mesajı veya tanım kimliği uyuşmuyor!');
          mmSonuc.Lines.Add(Format('Yanıt Mesajı: %d, Tanım Kimliği: %d', [DNSBaslik.BitCode, DNSBaslik.ID]));
          mmSonuc.Lines.Add('---------------------------');
        end;
      end
      else
      begin

        mmSonuc.Lines.Add('Hata: DNS adı çözümlenemiyor!');
        mmSonuc.Lines.Add('---------------------------');
      end;
    end
    else
    begin

      mmSonuc.Lines.Add('Hata: DNS adı çözümlenemiyor!');
      mmSonuc.Lines.Add('---------------------------');
    end;

    FreeAndNil(DNSBaslik);
  end
  else
  begin

    mmSonuc.Lines.Add('Hata: DNS adı çözümlenemiyor!');
    mmSonuc.Lines.Add('---------------------------');
  end;

  SetLength(DNSYanit, 0);
  SetLength(DNSSorgu, 0);

  sbDurum.SimpleText := '';
  sbDurum.Repaint;
end;

end.
