unit sunucudegistirfrm;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, Buttons,
  ExtCtrls;

type
  TfrmSunucuDegistir = class(TForm)
    btnDegistir: TBitBtn;
    edtDNSSunucusu: TEdit;
    lblDNSSunucusu: TLabel;
    procedure btnDegistirClick(Sender: TObject);
    procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormShow(Sender: TObject);
  end;

var
  frmSunucuDegistir: TfrmSunucuDegistir;

implementation

{$R *.lfm}
uses islevler, LCLType;

procedure TfrmSunucuDegistir.FormShow(Sender: TObject);
begin

  edtDNSSunucusu.Text := DNSSunucusu;
  edtDNSSunucusu.SetFocus;
end;

procedure TfrmSunucuDegistir.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin

  if(Key = VK_ESCAPE) then ModalResult := mrCancel;
end;

procedure TfrmSunucuDegistir.btnDegistirClick(Sender: TObject);
begin

  DNSSunucusu := Trim(edtDNSSunucusu.Text);
end;

end.
