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
  Forms, anchordockpkg, anasayfafrm, sunucudegistirfrm;

{$R *.res}

begin
  RequireDerivedFormResource:=True;
  Application.Title:='DNS İstamcisi';
  Application.Scaled:=True;
  Application.Initialize;
  Application.CreateForm(TfrmAnaSayfa, frmAnaSayfa);
  Application.CreateForm(TfrmSunucuDegistir, frmSunucuDegistir);
  Application.Run;
end.

