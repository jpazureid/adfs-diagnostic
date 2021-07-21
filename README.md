# adfs-diagnostic
Get diagnostic data of Active Directory Federation Service (AD FS)

本スクリプトでは以下の情報を採取します。

* ADFS/WAP 構成情報
* ADFS Admin イベント ログ
* application/system/security イベント ログ
* Certutil 出力結果
* ipconfig /all
* netsh http show ssl 出力結果
* Get-HotFix

対象 OS

* Windows Server 2012 R2 以降


実行手順は以下の通りです。

1. Clone or download より getadfslogscript.ps1 をダウンロードします。
2. PowerShell プロンプトを管理者として起動し、カレントディレクトリをスクリプトを配置したフォルダーに移動します。
 
    Windows PowerShell (x86) と表示されている PowerShell で本スクリプトを実行すると失敗します。 x86 という表記がない PowerShell にて実行ください。
3. 下記のように実行します。
    ```
    .\getadfslogscript.ps1
    ```
4. PowerShell 実行カレント フォルダー上に <実行日時>_hostname でフォルダーが作成され、その配下に各種ログが出力されます。

    ※ 構成によってはエラーが返ってくる場合もございますが、この場合は無視ください。

5. 実行完了後、 PowerShell 画面に表示された保存先フォルダーを ZIP 等で圧縮し、弊社までお寄せください

 スクリプトの実行が許可されていない場合 (Restricted) は、下記コマンドを利用してスクリプトを実行することが可能です。
```
Powershell.exe -ExecutionPolicy RemoteSigned -File .\getadfslogscript.ps1
```
