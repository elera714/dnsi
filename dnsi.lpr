program dnsi;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  {$IFDEF HASAMIGA}
  athreads,
  {$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, anasayfafrm;

{$R *.res}

begin
  RequireDerivedFormResource:=True;
  Application.Title:='DNS İstamci';
  Application.Scaled:=True;
  Application.Initialize;
  Application.CreateForm(TfrmAnaSayfa, frmAnaSayfa);
  Application.Run;
end.

