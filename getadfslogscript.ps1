############################################################
#AD FS/WAP 情報採取スクリプト
#LastUpdate:2020/02/17
#
###採取情報###
#ADFS/WAP 構成情報
#ADFS Admin イベント ログ
#WAP Admin イベント ログ <- 2020/1/1 追加
#application/system/security イベント ログ
#Certutil 出力結果
#ipconfig /all
#netsh http show ssl 出力結果
#Get-HotFix
##2020/2/17 追加
#WIASupportedUserAgents の一覧
#netstat -anot
#netsh http show urlacl
#tasklist /svc
#W2k19 で追加された AD FS コマンド
############################################################


######初期チェック。 OS バージョンと ProductType の確認処理

Function startup(){
    ###OS バージョンチェック
    #6.3 未満 = NG
    #6.4 未満 = W2k12R2
    #6.4 以上かつ BuildNumber が 17763 未満 = W2k16
    #それ以外 = W2k19 以上
    
    ##OS バージョン取得

    $oschk = ""
    $tmpOSVersion = Get-WmiObject Win32_OperatingSystem
    $tmpOSBuildNumber = $tmpOSVersion.BuildNumber
    $ProductType = (Get-WmiObject Win32_OperatingSystem).ProductType
    $tmpOSVersion = $tmpOSVersion.Version
    $tmpVersion = $tmpOSVersion.Replace( ".$tmpOSBuildNumber", "" )
    ##数値化

    $WinVer = [decimal]$tmpVersion

    ##判定処理
    # Windows Server 2012 R2/Windows 8.1 以降のいずれかでなければ false を返す。
    # 20200217 : Windows Server 2016/2019 の判定条件を追加

    if($WinVer -lt "6.3"){
        $oschk = "false"
    }elseif($WinVer -lt "6.4"){
        $oschk = "W2k12R2"
    }elseif($WinVer -eq "10.0" -and $tmpOSBuildNumber -lt "17763"){
        $oschk = "W2k16"
    }else{
        $oschk = "W2k19"
    }
    ##OS バージョン、 ProductType を返す。

    return $oschk,$ProductType
 }


######情報採取停止処理

Function GetLog ($oschk,$ProductType) {
    ###保存先フォルダー作成

    $str_path = (Convert-Path .)
    $FolderName = $str_path + "\" + $(Get-Date).ToString("yyyyMMdd") + "_" + $(Get-Date).ToString("HHmm") + "_" + $Env:COMPUTERNAME
    
    ##フォルダー作成
    #フォルダー作成に失敗した場合は Catch に移動し処理を停止する。

    try{
        $Item = New-Item -Path $FolderName -ItemType directory
        $FolderName = $Item.FullName
    }catch{
        $ErrorMessage = $_.Exception_Message
        $ErrorMessage
        Write-Host "There is an error : $error" -ForegroundColor Yellow
        exit
    }
   ##フォルダー パスの確認
   #フォルダーが確認できなかった失敗した場合は処理を停止する

    $PathChk = Test-Path $FolderName
    if($PathChk -eq "True"){
        Write-Host "Created folder "$FolderName
    }else{
        Write-Host "It is not a valided path."
        exit
    }


    ###ProductType が 1 (Client) 以外の場合役割の確認を行う。

    if($ProductType -ne "1"){
        ###AD FS の役割の有無のチェック

        $ADFSCheck = (Get-WindowsFeature -Name ADFS-Federation).InstallState

        if ($ADFSCheck -eq "Installed"){
            $ADFSCheck = "true"
        }else{
            $ADFSCheck = "false"
        }

        #WAP の役割の有無のチェック

        $WAPCheck = (Get-WindowsFeature -Name Web-Application-Proxy).InstallState

        if ($WAPCheck -eq "Installed"){
            $WAPCheck = "true"
        }else{
            $WAPCheck = "false"
        }
    }

    ###セキュリティ・アプリケーション・システム・ CAPI2 ログを evtx 形式で取得

    $tmpsystem = $FolderName + "\System.evtx"
    wevtutil epl system $tmpsystem
    $tmpapp = $FolderName + "\Application.evtx"
    wevtutil epl Application $tmpapp
    $tmpsec = $FolderName + "\security.evtx"
    wevtutil epl security $tmpsec
    $tmpcapi2 = $FolderName + "\capi2.evtx"
    wevtutil epl "Microsoft-Windows-CAPI2/Operational" $tmpcapi2

    ###ipconfig の結果を txt 形式で取得

    $tmpip = $FolderName + "\ipconfig.txt"
    ipconfig /all > $tmpip

    ##Hotfix 取得

    $hotfix = $FolderName + "\GetHotFix.txt"
    Get-HotFix | fl | Out-File  $hotfix
    
    $netstat_anot = $FolderName + "\netstat_anot.txt"
    netstat -anot > $netstat_anot
    
    $netsh_urlacl = $FolderName + "\netsh_urlacl.txt"
    netsh http show urlacl > $netsh_urlacl
    
    $tasklist_svc = $FolderName + "\tasklist_svc.txt"
    tasklist /svc > $tasklist_svc


    ### OS バージョンごとに AD FS Admin ログと各種 Get コマンドの結果を取得

    if ($oschk -eq "W2k12R2"){
    ## AD FS 3.0

        if($ADFSCheck -eq "true"){
            $adfslog = $FolderName + "\ADFSAdmin.evtx"
            wevtutil epl "AD FS/Admin" $adfslog

            $adfslog = $FolderName + "\ADFSDebug.evtx"
            wevtutil epl "AD FS Tracing/Debug" $adfslog

            $adfslog = $FolderName + "\Get-AdfsAdditionalAuthenticationRule.txt"
            Get-AdfsAdditionalAuthenticationRule | fl | Out-File $adfslog

            $adfslog = $FolderName + "\Get-AdfsAttributeStore.txt"
            Get-AdfsAttributeStore | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAuthenticationProvider.txt"
            Get-AdfsAuthenticationProvider | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAuthenticationProviderWebContent.txt"
            Get-AdfsAuthenticationProviderWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsCertificate.txt"
            Get-AdfsCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimDescription.txt"
            Get-AdfsClaimDescription | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimsProviderTrust.txt"
            Get-AdfsClaimsProviderTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClient.txt"
            Get-AdfsClient | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDeviceRegistration.txt"
            Get-AdfsDeviceRegistration | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDeviceRegistrationUpnSuffix.txt"
            Get-AdfsDeviceRegistrationUpnSuffix | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsEndpoint.txt"
            Get-AdfsEndpoint | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsGlobalAuthenticationPolicy.txt"
            Get-AdfsGlobalAuthenticationPolicy | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsGlobalWebContent.txt"
            Get-AdfsGlobalWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsNonClaimsAwareRelyingPartyTrust.txt"
            Get-AdfsNonClaimsAwareRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsProperties.txt"
            Get-AdfsProperties | fl | Out-File  $adfslog
            Write-Output "======== WIASupportedUserAgents ========" | Out-File  $adfslog -Append
            Get-AdfsProperties |select -ExpandProperty WIASupportedUserAgents | Out-File  $adfslog -Append

            Get-AdfsProperties |select -ExpandProperty WIASupportedUserAgents | Out-File  $adfslog -Append

            $adfslog = $FolderName + "\Get-AdfsRegistrationHosts.txt"
            Get-AdfsRegistrationHosts | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyTrust.txt"
            Get-AdfsRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyWebContent.txt"
            Get-AdfsRelyingPartyWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsSslCertificate.txt"
            Get-AdfsSslCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsSyncProperties.txt"
            Get-AdfsSyncProperties | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebApplicationProxyRelyingPartyTrust.txt"
            Get-AdfsWebApplicationProxyRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebConfig.txt"
            Get-AdfsWebConfig | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebTheme.txt"
            Get-AdfsWebTheme | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\netsh_ssl.txt"
            netsh http show ssl | Out-File $adfslog
        }
    ## WAP 3.0

        if($WAPCheck -eq "true"){
            $adfslog = $FolderName + "\ADFSAdmin.evtx"
            wevtutil epl "AD FS/Admin" $adfslog

            $adfslog = $FolderName + "\ADFSDebug.evtx"
            wevtutil epl "AD FS Tracing/Debug" $adfslog

            $adfslog = $FolderName + "\WAPAdmin.evtx"
            wevtutil epl "Microsoft-Windows-WebApplicationProxy/Admin" $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyApplication.txt"
            Get-WebApplicationProxyApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyAvailableADFSRelyingParty.txt"
            Get-WebApplicationProxyAvailableADFSRelyingParty | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyConfiguration.txt"
            Get-WebApplicationProxyConfiguration | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyHealth.txt"
            Get-WebApplicationProxyHealth | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxySslCertificate.txt"
            Get-WebApplicationProxySslCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\netsh_ssl.txt"
            netsh http show ssl > $adfslog

        }
    }
    if ($oschk -eq "W2k16"){
    ## AD FS 4.0

        if($ADFSCheck -eq "true"){
            $adfslog = $FolderName + "\ADFSAdmin.evtx"
            wevtutil epl "AD FS/Admin" $adfslog

            $adfslog = $FolderName + "\ADFSDebug.evtx"
            wevtutil epl "AD FS Tracing/Debug" $adfslog

            $adfslog = $FolderName + "\Get-AdfsAccessControlPolicy.txt"
            Get-AdfsAccessControlPolicy  | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAdditionalAuthenticationRule.txt"
            Get-AdfsAdditionalAuthenticationRule | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsApplicationGroup.txt"
            Get-AdfsApplicationGroup | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsApplicationPermission.txt"
            Get-AdfsApplicationPermission | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAttributeStore.txt"
            Get-AdfsAttributeStore | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAuthenticationProvider.txt"
            Get-AdfsAuthenticationProvider | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAuthenticationProviderWebContent.txt"
            Get-AdfsAuthenticationProviderWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAzureMfaConfigured.txt"
            Get-AdfsAzureMfaConfigured | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsCertificate.txt"
            Get-AdfsCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsCertificateAuthority.txt"
            Get-AdfsCertificateAuthority | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimDescription.txt"
            Get-AdfsClaimDescription | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimsProviderTrust.txt"
            Get-AdfsClaimsProviderTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimsProviderTrustsGroup.txt"
            Get-AdfsClaimsProviderTrustsGroup | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClient.txt"
            Get-AdfsClient | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDeviceRegistration.txt"
            Get-AdfsDeviceRegistration | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDeviceRegistrationUpnSuffix.txt"
            Get-AdfsDeviceRegistrationUpnSuffix | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsEndpoint.txt"
            Get-AdfsEndpoint | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsFarmInformation.txt"
            Get-AdfsFarmInformation | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsGlobalAuthenticationPolicy.txt"
            Get-AdfsGlobalAuthenticationPolicy | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsGlobalWebContent.txt"
            Get-AdfsGlobalWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsLocalClaimsProviderTrust.txt"
            Get-AdfsLocalClaimsProviderTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsNativeClientApplication.txt"
            Get-AdfsNativeClientApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsNonClaimsAwareRelyingPartyTrust.txt"
            Get-AdfsNonClaimsAwareRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsProperties.txt"
            Get-AdfsProperties | fl | Out-File  $adfslog
            Write-Output "======== WIASupportedUserAgents ==========" | Out-File  $adfslog -Append
            Get-AdfsProperties |select -ExpandProperty WIASupportedUserAgents | Out-File  $adfslog -Append

            $adfslog = $FolderName + "\Get-AdfsRegistrationHosts.txt"
            Get-AdfsRegistrationHosts | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyTrust.txt"
            Get-AdfsRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyTrustsGroup.txt"
            Get-AdfsRelyingPartyTrustsGroup | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyWebContent.txt"
            Get-AdfsRelyingPartyWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyWebTheme.txt"
            Get-AdfsRelyingPartyWebTheme | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsScopeDescription.txt"
            Get-AdfsScopeDescription | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsServerApplication.txt"
            Get-AdfsServerApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsSslCertificate.txt"
            Get-AdfsSslCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsSyncProperties.txt"
            Get-AdfsSyncProperties | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsTrustedFederationPartner.txt"
            Get-AdfsTrustedFederationPartner | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebApiApplication.txt"
            Get-AdfsWebApiApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebApplicationProxyRelyingPartyTrust.txt"
            Get-AdfsWebApplicationProxyRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebConfig.txt"
            Get-AdfsWebConfig | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebTheme.txt"
            Get-AdfsWebTheme | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\netsh_ssl.txt"
            netsh http show ssl > $adfslog
        }
    ## WAP 4.0

        if($WAPCheck -eq "true"){
            $adfslog = $FolderName + "\ADFSAdmin.evtx"
            wevtutil epl "AD FS/Admin" $adfslog

            $adfslog = $FolderName + "\ADFSDebug.evtx"
            wevtutil epl "AD FS Tracing/Debug" $adfslog

            $adfslog = $FolderName + "\WAPAdmin.evtx"
            wevtutil epl "Microsoft-Windows-WebApplicationProxy/Admin" $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyApplication.txt"
            Get-WebApplicationProxyApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyAvailableADFSRelyingParty.txt"
            Get-WebApplicationProxyAvailableADFSRelyingParty | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyConfiguration.txt"
            Get-WebApplicationProxyConfiguration | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyHealth.txt"
            Get-WebApplicationProxyHealth | fl | Out-File  $adfslog
            
            $adfslog = $FolderName + "\Get-WebApplicationProxySslCertificate.txt"
            Get-WebApplicationProxySslCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\netsh_ssl.txt"
            netsh http show ssl > $adfslog
        }
    }
    
    #20200217 追記/ Windows Server 2019 AD FS/WAP 用

    if ($oschk -eq "W2k19"){
    ## AD FS 5.0

        if($ADFSCheck -eq "true"){
            $adfslog = $FolderName + "\ADFSAdmin.evtx"
            wevtutil epl "AD FS/Admin" $adfslog

            $adfslog = $FolderName + "\ADFSDebug.evtx"
            wevtutil epl "AD FS Tracing/Debug" $adfslog

            $adfslog = $FolderName + "\Get-AdfsAccessControlPolicy.txt"
            Get-AdfsAccessControlPolicy  | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAdditionalAuthenticationRule.txt"
            Get-AdfsAdditionalAuthenticationRule | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsApplicationGroup.txt"
            Get-AdfsApplicationGroup | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsApplicationPermission.txt"
            Get-AdfsApplicationPermission | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAttributeStore.txt"
            Get-AdfsAttributeStore | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAuthenticationProvider.txt"
            Get-AdfsAuthenticationProvider | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAuthenticationProviderWebContent.txt"
            Get-AdfsAuthenticationProviderWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsAzureMfaConfigured.txt"
            Get-AdfsAzureMfaConfigured | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsCertificate.txt"
            Get-AdfsCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsCertificateAuthority.txt"
            Get-AdfsCertificateAuthority | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimDescription.txt"
            Get-AdfsClaimDescription | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimsProviderTrust.txt"
            Get-AdfsClaimsProviderTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClaimsProviderTrustsGroup.txt"
            Get-AdfsClaimsProviderTrustsGroup | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsClient.txt"
            Get-AdfsClient | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDeviceRegistration.txt"
            Get-AdfsDeviceRegistration | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDeviceRegistrationUpnSuffix.txt"
            Get-AdfsDeviceRegistrationUpnSuffix | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsEndpoint.txt"
            Get-AdfsEndpoint | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsFarmInformation.txt"
            Get-AdfsFarmInformation | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsGlobalAuthenticationPolicy.txt"
            Get-AdfsGlobalAuthenticationPolicy | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsGlobalWebContent.txt"
            Get-AdfsGlobalWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsLocalClaimsProviderTrust.txt"
            Get-AdfsLocalClaimsProviderTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsNativeClientApplication.txt"
            Get-AdfsNativeClientApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsNonClaimsAwareRelyingPartyTrust.txt"
            Get-AdfsNonClaimsAwareRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsProperties.txt"
            Get-AdfsProperties | fl | Out-File  $adfslog
            Write-Output "======== WIASupportedUserAgents ==========" | Out-File  $adfslog -Append
            Get-AdfsProperties |select -ExpandProperty WIASupportedUserAgents | Out-File  $adfslog -Append
            
            $adfslog = $FolderName + "\Get-AdfsRegistrationHosts.txt"
            Get-AdfsRegistrationHosts | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyTrust.txt"
            Get-AdfsRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyTrustsGroup.txt"
            Get-AdfsRelyingPartyTrustsGroup | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyWebContent.txt"
            Get-AdfsRelyingPartyWebContent | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsRelyingPartyWebTheme.txt"
            Get-AdfsRelyingPartyWebTheme | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsScopeDescription.txt"
            Get-AdfsScopeDescription | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsServerApplication.txt"
            Get-AdfsServerApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsSslCertificate.txt"
            Get-AdfsSslCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsSyncProperties.txt"
            Get-AdfsSyncProperties | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsTrustedFederationPartner.txt"
            Get-AdfsTrustedFederationPartner | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebApiApplication.txt"
            Get-AdfsWebApiApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebApplicationProxyRelyingPartyTrust.txt"
            Get-AdfsWebApplicationProxyRelyingPartyTrust | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebConfig.txt"
            Get-AdfsWebConfig | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsWebTheme.txt"
            Get-AdfsWebTheme | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDebugLogConsumersConfiguration_Email.txt"
            Get-AdfsDebugLogConsumersConfiguration -Consumer Email  | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDebugLogConsumersConfiguration_FileShare.txt"
            Get-AdfsDebugLogConsumersConfiguration -Consumer FileShare | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsDirectoryProperties.txt"
            Get-AdfsDirectoryProperties | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-AdfsThreatDetectionModule.txt"
            Get-AdfsThreatDetectionModule | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\netsh_ssl.txt"
            netsh http show ssl > $adfslog
        }
    ## WAP 5.0

        if($WAPCheck -eq "true"){
            $adfslog = $FolderName + "\ADFSAdmin.evtx"
            wevtutil epl "AD FS/Admin" $adfslog

            $adfslog = $FolderName + "\ADFSDebug.evtx"
            wevtutil epl "AD FS Tracing/Debug" $adfslog

            $adfslog = $FolderName + "\WAPAdmin.evtx"
            wevtutil epl "Microsoft-Windows-WebApplicationProxy/Admin" $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyApplication.txt"
            Get-WebApplicationProxyApplication | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyAvailableADFSRelyingParty.txt"
            Get-WebApplicationProxyAvailableADFSRelyingParty | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyConfiguration.txt"
            Get-WebApplicationProxyConfiguration | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\Get-WebApplicationProxyHealth.txt"
            Get-WebApplicationProxyHealth | fl | Out-File  $adfslog
            
            $adfslog = $FolderName + "\Get-WebApplicationProxySslCertificate.txt"
            Get-WebApplicationProxySslCertificate | fl | Out-File  $adfslog

            $adfslog = $FolderName + "\netsh_ssl.txt"
            netsh http show ssl > $adfslog
        }
    }

    ## 証明書情報取得

    $certlog = $FolderName + "\cert-root.txt"
    certutil -v -silent -store ROOT | Out-File $certlog
  
    $certlog = $FolderName + "\cert-user-root.txt"
    certutil -v -silent -store -user ROOT | Out-File $certlog
    
    $certlog = $FolderName + "\cert-ca.txt"
    certutil -v -silent -store CA | Out-File $certlog

    $certlog = $FolderName + "\cert-authroot.txt"
    certutil -v -silent -store AUTHROOT | Out-File $certlog

    $certlog = $FolderName + "\cert-ent-roott.txt"
    certutil -v -silent -store -enterprise ROOT | Out-File $certlog

    $certlog = $FolderName + "\cert-ent-ntauth.txt"
    certutil -v -silent -store -enterprise NTAUTH | Out-File $certlog

    $certlog = $FolderName + "\cert-gp-root.txt"
    certutil -v -silent -store -grouppolicy ROOT | Out-File $certlog

    $certlog = $FolderName + "\cert-machine-my.txt"
    certutil -v -silent -store MY | Out-File $certlog

    $certlog = $FolderName + "\cert-user-my.txt"
    certutil -v -silent -store -user MY | Out-File $certlog

    Write-Host "Complate: Export Folder : " $FolderName
}

#######################開始処理#############################

#####管理者権限チェック。管理者権限でない場合に処理を終了する。

if (-not(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
    Write-Host "Start PowerShell with adminisrator privilege."
    exit
}

#####Startup 処理、[0] に OS バージョン情報を、 [1] に ProductType の値を入れる。 1=Client 2=DC 3=Server

$chk = startup

#####OS チェック、6.3 未満のビルドの場合は処理を終了する

if($chk[0] -eq "false"){
    Write-Host "You have to run this script on Windows Server 2012 R2 or later version."
    exit
}else{
    #OS がバージョン通りであれば OSVersion と ProductType を提供してログ採取を開始する。

    GetLog $chk[0] $chk[1]
}
